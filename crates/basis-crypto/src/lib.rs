//! Protocol-56 DID login cryptography and the per-peer packet cipher.
//!
//! The C# implementation binds DID login to an X25519 connection key and seals all
//! client-to-server user data with the derived key. This crate implements exactly that
//! byte layout; it is deliberately independent of the transport so it can be tested
//! without a socket.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub const PUBLIC_KEY_SIZE: usize = 32;
pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const COUNTER_SIZE: usize = 8;
pub const PACKET_OVERHEAD: usize = TAG_SIZE + COUNTER_SIZE;
pub const MIN_NONCE_SIZE: usize = 32;
pub const LEGACY_NONCE_SIZE: usize = 256;

const INFO_CLIENT_TO_SERVER: &[u8] = b"basis-server-link-v1-c2s";
const LOGIN_TAG: &[u8] = b"basis-did-login-v2";

pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let mut private_key = [0u8; 32];
    let mut public_key = [0u8; 32];
    private_key.copy_from_slice(secret.as_bytes());
    public_key.copy_from_slice(public.as_bytes());
    (private_key, public_key)
}

pub fn public_key(private_key: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*private_key)).to_bytes()
}

pub fn agree(private_key: &[u8; 32], peer_public: &[u8; 32]) -> Option<[u8; 32]> {
    let shared = StaticSecret::from(*private_key).diffie_hellman(&PublicKey::from(*peer_public));
    let bytes = shared.to_bytes();
    if bytes.iter().all(|b| *b == 0) {
        None
    } else {
        Some(bytes)
    }
}

fn derive_client_to_server(
    my_private: &[u8; 32],
    peer_public: &[u8; 32],
    client_public: &[u8; 32],
    server_public: &[u8; 32],
) -> Option<[u8; 32]> {
    let shared = agree(my_private, peer_public)?;
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(client_public);
    salt[32..].copy_from_slice(server_public);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &shared);
    let mut key = [0u8; 32];
    hkdf.expand(INFO_CLIENT_TO_SERVER, &mut key).ok()?;
    Some(key)
}

pub fn derive_client_key(
    client_private: &[u8; 32],
    client_public: &[u8; 32],
    server_public: &[u8; 32],
) -> Option<[u8; 32]> {
    derive_client_to_server(client_private, server_public, client_public, server_public)
}

pub fn derive_server_key(
    server_private: &[u8; 32],
    client_public: &[u8; 32],
    server_public: &[u8; 32],
) -> Option<[u8; 32]> {
    derive_client_to_server(server_private, client_public, client_public, server_public)
}

pub fn hash_connection_payload(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

pub fn random_nonce() -> [u8; MIN_NONCE_SIZE] {
    use rand::RngCore;
    let mut nonce = [0u8; MIN_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn build_login_transcript(
    client_did: &str,
    server_id: &str,
    nonce: &[u8],
    client_public: &[u8; 32],
    server_public: &[u8; 32],
    payload_hash: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(LOGIN_TAG);
    append_field(&mut out, client_did.as_bytes());
    append_field(&mut out, server_id.as_bytes());
    append_field(&mut out, nonce);
    append_field(&mut out, client_public);
    append_field(&mut out, server_public);
    append_field(&mut out, payload_hash);
    out
}

fn append_field(out: &mut Vec<u8>, field: &[u8]) {
    assert!(field.len() <= u16::MAX as usize);
    out.extend_from_slice(&(field.len() as u16).to_le_bytes());
    out.extend_from_slice(field);
}

/// A per-connection inbound packet cipher. The C# `BasisPeerCipherLayer` seals every
/// user-data datagram after login as `[header][ciphertext][tag][counter]`; the header is
/// authenticated as one byte of AAD and the nonce is the little-endian counter in bytes
/// 0..8 with the remaining four bytes zero.
impl std::fmt::Debug for PacketCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketCipher")
            .field("send_counter", &self.send_counter)
            .finish_non_exhaustive()
    }
}
pub struct PacketCipher {
    cipher: ChaCha20Poly1305,
    send_counter: u64,
    replay: ReplayWindow,
}

impl PacketCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            send_counter: 0,
            replay: ReplayWindow::default(),
        }
    }

    pub fn seal(&mut self, packet: &mut Vec<u8>) -> bool {
        if packet.is_empty() {
            return false;
        }
        self.send_counter = self.send_counter.wrapping_add(1);
        let counter = self.send_counter;
        let header = packet[0];
        let plain_len = packet.len() - 1;
        let nonce = nonce_for_counter(counter);
        let tag = match self.cipher.encrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            &[header],
            &mut packet[1..1 + plain_len],
        ) {
            Ok(tag) => tag,
            Err(_) => return false,
        };
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(&counter.to_le_bytes());
        true
    }

    pub fn open(&mut self, packet: &mut Vec<u8>) -> bool {
        if packet.len() < 1 + PACKET_OVERHEAD {
            return false;
        }
        let counter_offset = packet.len() - COUNTER_SIZE;
        let counter = u64::from_le_bytes(packet[counter_offset..].try_into().unwrap());
        if !self.replay.could_accept(counter) {
            return false;
        }
        let tag_offset = counter_offset - TAG_SIZE;
        let plain_len = tag_offset - 1;
        let header = packet[0];
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&packet[tag_offset..counter_offset]);
        let nonce = nonce_for_counter(counter);
        if self
            .cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                &[header],
                &mut packet[1..1 + plain_len],
                Tag::from_slice(&tag),
            )
            .is_err()
        {
            return false;
        }
        packet.truncate(1 + plain_len);
        self.replay.accept(counter);
        true
    }
}

fn nonce_for_counter(counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

#[derive(Default)]
struct ReplayWindow {
    latest: u64,
    bits: u128,
}

impl ReplayWindow {
    const WINDOW: u64 = 128;

    fn could_accept(&self, counter: u64) -> bool {
        if counter == 0 {
            return false;
        }
        if counter > self.latest {
            return true;
        }
        let delta = self.latest - counter;
        delta < Self::WINDOW && self.bits & (1u128 << delta) == 0
    }

    fn accept(&mut self, counter: u64) {
        if counter > self.latest {
            let shift = (counter - self.latest).min(128) as u32;
            self.bits = if shift >= 128 {
                1
            } else {
                (self.bits << shift) | 1
            };
            self.latest = counter;
        } else {
            let delta = self.latest - counter;
            if delta < 128 {
                self.bits |= 1u128 << delta;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_ends_derive_the_same_client_to_server_key() {
        let (client_private, client_public) = generate_keypair();
        let (server_private, server_public) = generate_keypair();
        let client = derive_client_key(&client_private, &client_public, &server_public).unwrap();
        let server = derive_server_key(&server_private, &client_public, &server_public).unwrap();
        assert_eq!(client, server);
    }

    #[test]
    fn packet_cipher_round_trips_and_rejects_replay() {
        let key = [7u8; 32];
        let mut sender = PacketCipher::new(&key);
        let mut receiver = PacketCipher::new(&key);
        let mut packet = vec![1u8, 2, 3, 4, 5];
        assert!(sender.seal(&mut packet));
        assert_eq!(packet.len(), 5 + PACKET_OVERHEAD);
        assert!(receiver.open(&mut packet));
        assert_eq!(packet, vec![1, 2, 3, 4, 5]);
        let mut replay = packet.clone();
        // Re-sealing is a different counter, so construct a duplicate from the original
        // sealed bytes instead.
        let mut original = vec![1u8, 2, 3, 4, 5];
        assert!(sender.seal(&mut original));
        let mut duplicate = original.clone();
        assert!(receiver.open(&mut original));
        assert!(!receiver.open(&mut duplicate));
        assert!(sender.seal(&mut replay));
    }

    #[test]
    fn transcript_uses_little_endian_lengths() {
        let nonce = [1u8; 32];
        let client = [2u8; 32];
        let server = [3u8; 32];
        let hash = [4u8; 32];
        let transcript =
            build_login_transcript("did:key:x", "server", &nonce, &client, &server, &hash);
        assert!(transcript.starts_with(b"basis-did-login-v2"));
        let after_tag = LOGIN_TAG.len();
        assert_eq!(&transcript[after_tag..after_tag + 2], &9u16.to_le_bytes());
    }
}
