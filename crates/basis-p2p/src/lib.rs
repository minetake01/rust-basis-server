//! P2P signalling broker.
//!
//! The server relays `BasisP2PSignalMessage` frames between authenticated peers and
//! tracks which pairs reported a direct link. NAT traversal itself belongs to the
//! transport (LiteNetLib NatPunchModule in C#); this crate owns the relay/session
//! state and the wire body, so the transport only has to move packets.

use basis_wire::{Reader, WireResult, Writer};
use std::collections::{HashMap, HashSet};

pub const P2P_CHANNEL: u8 = 54;
pub const SUB_REQUEST: u8 = 0;
pub const SUB_ACCEPT: u8 = 1;
pub const SUB_DECLINE: u8 = 2;
pub const SUB_CANCEL: u8 = 3;
pub const SUB_LINK_LOST: u8 = 4;
pub const SUB_SERVER_ARMED: u8 = 5;
pub const SUB_LINK_UP: u8 = 6;
pub const SUB_OFFLOADED: u8 = 7;

const MAX_TOKEN: usize = 64;
const MAX_SESSIONS_PER_PEER: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signal {
    pub other: u16,
    pub token: String,
    pub key: Option<[u8; 32]>,
}

pub fn parse(payload: &[u8]) -> WireResult<(u8, Signal)> {
    let mut reader = Reader::new(payload);
    let sub = reader.get_u8()?;
    let other = reader.get_u16()?;
    let token = reader.get_string()?;
    let has_key = reader.get_u8()?;
    let key = if has_key == 1 && reader.remaining() >= 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(reader.get_bytes(32)?);
        Some(key)
    } else {
        None
    };
    Ok((
        sub,
        Signal {
            other,
            token: token.chars().take(MAX_TOKEN).collect(),
            key,
        },
    ))
}

pub fn build(sub: u8, signal: &Signal) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.put_u8(sub);
    writer.put_u16(signal.other);
    writer.put_string(&signal.token);
    if let Some(key) = signal.key {
        writer.put_u8(1);
        writer.put_bytes(&key);
    } else {
        writer.put_u8(0);
    }
    writer.into_vec()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outbound {
    pub to: u16,
    pub sub: u8,
    pub other: u16,
    pub token: String,
    pub key: Option<[u8; 32]>,
}

impl Outbound {
    fn signal(&self) -> Signal {
        Signal {
            other: self.other,
            token: self.token.clone(),
            key: self.key,
        }
    }
}

#[derive(Default)]
pub struct Broker {
    sessions: HashMap<String, Session>,
    peer_sessions: HashMap<u16, HashSet<String>>,
    offloaded: HashSet<(u16, u16)>,
}

struct Session {
    initiator: u16,
    target: u16,
}

impl Broker {
    pub fn is_offloaded(&self, a: u16, b: u16) -> bool {
        self.offloaded.contains(&pair(a, b))
    }

    pub fn handle(&mut self, from: u16, payload: &[u8]) -> Vec<Outbound> {
        let Ok((sub, signal)) = parse(payload) else {
            return Vec::new();
        };
        if signal.token.is_empty() {
            return vec![cancel(from, &signal)];
        }
        match sub {
            SUB_REQUEST => self.request(from, signal),
            SUB_ACCEPT => self.accept(from, signal),
            SUB_DECLINE | SUB_CANCEL => self.close_and_forward(from, sub, signal),
            SUB_LINK_LOST => {
                if let Some(session) = self.sessions.get(&signal.token) {
                    let other = other_peer(session, from);
                    self.offloaded
                        .remove(&pair(session.initiator, session.target));
                    vec![forward(other, SUB_LINK_LOST, &signal)]
                } else {
                    Vec::new()
                }
            }
            SUB_LINK_UP => {
                let Some(session) = self.sessions.get(&signal.token) else {
                    return Vec::new();
                };
                let other = other_peer(session, from);
                let pair_key = pair(session.initiator, session.target);
                self.offloaded.insert(pair_key);
                vec![
                    forward(other, SUB_LINK_UP, &signal),
                    forward(session.initiator, SUB_OFFLOADED, &signal),
                    forward(session.target, SUB_OFFLOADED, &signal),
                ]
            }
            _ => Vec::new(),
        }
    }

    pub fn remove_peer(&mut self, peer: u16) -> Vec<Outbound> {
        let tokens: Vec<String> = self
            .peer_sessions
            .remove(&peer)
            .map(|set| set.into_iter().collect())
            .unwrap_or_default();
        let mut out = Vec::new();
        for token in tokens {
            if let Some(session) = self.sessions.remove(&token) {
                let other = if session.initiator == peer {
                    session.target
                } else {
                    session.initiator
                };
                if let Some(set) = self.peer_sessions.get_mut(&other) {
                    set.remove(&token);
                }
                out.push(Outbound {
                    to: other,
                    sub: SUB_CANCEL,
                    other: peer,
                    token,
                    key: None,
                });
                self.offloaded
                    .remove(&pair(session.initiator, session.target));
            }
        }
        out
    }

    fn request(&mut self, from: u16, signal: Signal) -> Vec<Outbound> {
        if signal.other == from {
            return vec![cancel(from, &signal)];
        }
        if self.sessions.contains_key(&signal.token)
            || self
                .peer_sessions
                .get(&from)
                .is_some_and(|set| set.len() >= MAX_SESSIONS_PER_PEER)
        {
            return vec![cancel(from, &signal)];
        }
        self.sessions.insert(
            signal.token.clone(),
            Session {
                initiator: from,
                target: signal.other,
            },
        );
        self.peer_sessions
            .entry(from)
            .or_default()
            .insert(signal.token.clone());
        self.peer_sessions
            .entry(signal.other)
            .or_default()
            .insert(signal.token.clone());
        vec![
            Outbound {
                to: signal.other,
                sub: SUB_REQUEST,
                other: from,
                token: signal.token.clone(),
                key: signal.key,
            },
            Outbound {
                to: from,
                sub: SUB_SERVER_ARMED,
                other: signal.other,
                token: signal.token,
                key: None,
            },
        ]
    }

    fn accept(&mut self, from: u16, signal: Signal) -> Vec<Outbound> {
        let Some(session) = self.sessions.get(&signal.token) else {
            return vec![cancel(from, &signal)];
        };
        if session.target != from {
            return vec![cancel(from, &signal)];
        }
        let initiator = session.initiator;
        vec![Outbound {
            to: initiator,
            sub: SUB_ACCEPT,
            other: from,
            token: signal.token,
            key: signal.key,
        }]
    }

    fn close_and_forward(&mut self, from: u16, sub: u8, signal: Signal) -> Vec<Outbound> {
        let Some(session) = self.sessions.remove(&signal.token) else {
            return Vec::new();
        };
        let other = other_peer(&session, from);
        self.offloaded
            .remove(&pair(session.initiator, session.target));
        for peer in [session.initiator, session.target] {
            if let Some(set) = self.peer_sessions.get_mut(&peer) {
                set.remove(&signal.token);
            }
        }
        vec![Outbound {
            to: other,
            sub,
            other: from,
            token: signal.token,
            key: signal.key,
        }]
    }
}

fn cancel(from: u16, signal: &Signal) -> Outbound {
    Outbound {
        to: from,
        sub: SUB_CANCEL,
        other: signal.other,
        token: signal.token.clone(),
        key: None,
    }
}

fn forward(to: u16, sub: u8, signal: &Signal) -> Outbound {
    Outbound {
        to,
        sub,
        other: signal.other,
        token: signal.token.clone(),
        key: signal.key,
    }
}

fn other_peer(session: &Session, from: u16) -> u16 {
    if session.initiator == from {
        session.target
    } else {
        session.initiator
    }
}

fn pair(a: u16, b: u16) -> (u16, u16) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

impl Outbound {
    pub fn to_payload(&self) -> Vec<u8> {
        build(self.sub, &self.signal())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_accept_linkup_offload_and_cancel_round_trip() {
        let mut broker = Broker::default();
        let request = build(
            SUB_REQUEST,
            &Signal {
                other: 2,
                token: "token-1".into(),
                key: Some([7u8; 32]),
            },
        );
        let actions = broker.handle(1, &request);
        assert!(actions.iter().any(|a| a.to == 2 && a.sub == SUB_REQUEST));
        assert!(actions
            .iter()
            .any(|a| a.to == 1 && a.sub == SUB_SERVER_ARMED));

        let accept = build(
            SUB_ACCEPT,
            &Signal {
                other: 1,
                token: "token-1".into(),
                key: Some([9u8; 32]),
            },
        );
        let actions = broker.handle(2, &accept);
        assert_eq!(actions.len(), 1);
        assert_eq!((actions[0].to, actions[0].sub), (1, SUB_ACCEPT));

        let link_up = build(
            SUB_LINK_UP,
            &Signal {
                other: 1,
                token: "token-1".into(),
                key: None,
            },
        );
        let actions = broker.handle(2, &link_up);
        assert!(actions.iter().any(|a| a.sub == SUB_OFFLOADED && a.to == 1));
        assert!(actions.iter().any(|a| a.sub == SUB_OFFLOADED && a.to == 2));
        assert!(broker.is_offloaded(1, 2));

        let actions = broker.remove_peer(1);
        assert_eq!(actions.len(), 1);
        assert_eq!((actions[0].to, actions[0].sub), (2, SUB_CANCEL));
        assert!(!broker.is_offloaded(1, 2));
    }

    #[test]
    fn signal_wire_body_is_length_prefixed() {
        let body = build(
            SUB_REQUEST,
            &Signal {
                other: 513,
                token: "abc".into(),
                key: Some([1u8; 32]),
            },
        );
        assert_eq!(body[0], SUB_REQUEST);
        assert_eq!(u16::from_le_bytes([body[1], body[2]]), 513);
        assert_eq!(u16::from_le_bytes([body[3], body[4]]), 4);
        assert_eq!(&body[5..8], b"abc");
        assert_eq!(body[8], 1);
        let (sub, signal) = parse(&body).unwrap();
        assert_eq!(sub, SUB_REQUEST);
        assert_eq!(signal.other, 513);
        assert_eq!(signal.token, "abc");
        assert_eq!(signal.key, Some([1u8; 32]));
    }
}
