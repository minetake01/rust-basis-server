//! Per-receiver avatar bundle queue. The transport can drain this on a tick and
//! hand the result to `basis_protocol::bundle::build_groups`.

use basis_protocol::bundle;
use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Default)]
pub struct BundleQueue {
    pending: HashMap<SocketAddr, Vec<(u8, Vec<u8>)>>,
}

impl BundleQueue {
    pub fn push(&mut self, target: SocketAddr, channel: u8, payload: Vec<u8>) {
        self.pending
            .entry(target)
            .or_default()
            .push((channel, payload));
    }

    pub fn targets(&self) -> Vec<SocketAddr> {
        self.pending.keys().copied().collect()
    }

    pub fn len(&self, target: SocketAddr) -> usize {
        self.pending.get(&target).map(Vec::len).unwrap_or(0)
    }

    pub fn is_empty(&self, target: SocketAddr) -> bool {
        self.len(target) == 0
    }

    /// Drains one receiver into a single bundle, grouping by ascending channel.
    pub fn take_entries(&mut self, target: SocketAddr) -> Vec<(u8, Vec<u8>)> {
        self.pending.remove(&target).unwrap_or_default()
    }

    pub fn bytes(&self, target: SocketAddr) -> usize {
        self.pending
            .get(&target)
            .map(|entries| entries.iter().map(|(_, payload)| payload.len() + 4).sum())
            .unwrap_or(0)
    }

    pub fn take(&mut self, target: SocketAddr) -> Option<Vec<u8>> {
        let entries = self.pending.remove(&target)?;
        build_entries(entries)
    }

    /// Drains one receiver into bundles whose raw payload stays under `max_raw_bytes`.
    pub fn take_chunks(&mut self, target: SocketAddr, max_raw_bytes: usize) -> Vec<Vec<u8>> {
        let Some(entries) = self.pending.remove(&target) else {
            return Vec::new();
        };
        let mut chunks = Vec::new();
        let mut current = Vec::new();
        let mut bytes = 0usize;
        for entry in entries {
            let addition = entry.1.len() + 4;
            if !current.is_empty() && bytes + addition > max_raw_bytes {
                if let Some(bundle) = build_entries(std::mem::take(&mut current)) {
                    chunks.push(bundle);
                }
                bytes = 0;
            }
            bytes += addition;
            current.push(entry);
        }
        if let Some(bundle) = build_entries(current) {
            chunks.push(bundle);
        }
        chunks
    }
}

fn build_entries(entries: Vec<(u8, Vec<u8>)>) -> Option<Vec<u8>> {
    if entries.is_empty() {
        return None;
    }
    let mut by_channel: std::collections::BTreeMap<u8, Vec<Vec<u8>>> = Default::default();
    for (channel, payload) in entries {
        by_channel.entry(channel).or_default().push(payload);
    }
    let groups: Vec<(u8, Vec<Vec<u8>>)> = by_channel.into_iter().collect();
    bundle::build_groups(&groups)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn groups_by_channel_and_round_trips() {
        let mut queue = BundleQueue::default();
        queue.push(addr(1), 13, b"c".to_vec());
        queue.push(addr(1), 12, b"a".to_vec());
        queue.push(addr(1), 12, b"b".to_vec());
        assert_eq!(queue.len(addr(1)), 3);
        let bundle = queue.take(addr(1)).unwrap();
        assert!(queue.take(addr(1)).is_none());
        assert_eq!(
            bundle::decode(&bundle),
            Some(vec![
                (12, b"a".to_vec()),
                (12, b"b".to_vec()),
                (13, b"c".to_vec())
            ])
        );
    }

    #[test]
    fn large_queues_split_into_bounded_chunks() {
        let mut queue = BundleQueue::default();
        for index in 0..10 {
            queue.push(addr(1), 12, vec![index; 40]);
        }
        let chunks = queue.take_chunks(addr(1), 100);
        assert!(chunks.len() > 1);
        for chunk in chunks {
            let decoded = bundle::decode(&chunk).unwrap();
            assert!(!decoded.is_empty());
        }
    }

    #[test]
    fn receivers_are_independent() {
        let mut queue = BundleQueue::default();
        queue.push(addr(1), 12, b"a".to_vec());
        queue.push(addr(2), 12, b"b".to_vec());
        assert_eq!(queue.len(addr(1)), 1);
        assert_eq!(queue.len(addr(2)), 1);
        assert!(queue.take(addr(1)).is_some());
        assert_eq!(queue.len(addr(2)), 1);
    }
}
