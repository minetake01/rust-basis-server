//! Port of Basis.Network.Core.PermissionBitsetMap.
//!
//! APPEND ONLY: index order is part of the wire format.

use std::collections::HashSet;

pub const INDEX_TO_NODE: [&str; 28] = [
    "*",
    "basis.server.stats",
    "basis.resource.load.world",
    "basis.resource.unload.world",
    "basis.resource.load.prop",
    "basis.resource.unload.prop",
    "basis.resource.load.avatar",
    "basis.resource.unload.avatar",
    "basis.ownership.transfer",
    "basis.ownership.remove",
    "basis.ownership.get",
    "basis.contentshare.delete",
    "basis.contentshare.create",
    "basis.protection",
    "basis.configuration",
    "basis.moderation",
    "basis.moderation.ban",
    "basis.moderation.kick",
    "basis.moderation.ipban",
    "basis.moderation.unban",
    "basis.moderation.unbanip",
    "basis.moderation.message",
    "basis.moderation.messageall",
    "basis.moderation.teleport",
    "basis.moderation.announce",
    "basis.permissions.view",
    "basis.permissions.edit",
    "basis.moderation.headlessaudio",
];

pub fn byte_count() -> usize {
    INDEX_TO_NODE.len().div_ceil(8)
}

fn index_of(node: &str) -> Option<usize> {
    INDEX_TO_NODE
        .iter()
        .position(|candidate| candidate.eq_ignore_ascii_case(node))
}

/// Splits allowed nodes into the compact bitset and the dynamic extras.
pub fn encode(allowed: &[String], denied: &[String]) -> (Vec<u8>, Vec<String>) {
    let mut bitset = vec![0u8; byte_count()];
    let mut extras = Vec::new();
    let mut has_wildcard = false;

    for node in allowed {
        if node == "*" {
            has_wildcard = true;
        }
        if let Some(index) = index_of(node) {
            bitset[index >> 3] |= 1 << (index & 7);
        } else {
            extras.push(node.clone());
        }
    }
    if has_wildcard {
        for index in 0..INDEX_TO_NODE.len() {
            bitset[index >> 3] |= 1 << (index & 7);
        }
    }
    for node in denied {
        if let Some(index) = index_of(node) {
            bitset[index >> 3] &= !(1 << (index & 7));
        }
    }
    (bitset, extras)
}

/// Reconstructs the allowed node set from a bitset plus dynamic extras.
pub fn decode(bitset: &[u8], extras: &[String]) -> HashSet<String> {
    let mut result = HashSet::new();
    let max_bit = INDEX_TO_NODE.len().min(bitset.len() * 8);
    for index in 0..max_bit {
        if bitset[index >> 3] & (1 << (index & 7)) != 0 {
            result.insert(INDEX_TO_NODE[index].to_string());
        }
    }
    for extra in extras {
        result.insert(extra.clone());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn bitset_round_trips_known_and_extra_nodes() {
        let allowed = strings(&[
            "basis.resource.load.world",
            "basis.custom.extra",
            "basis.moderation.ban",
        ]);
        let (bitset, extras) = encode(&allowed, &[]);
        assert_eq!(bitset.len(), 4);
        assert_eq!(extras, strings(&["basis.custom.extra"]));
        let decoded = decode(&bitset, &extras);
        for node in &allowed {
            assert!(decoded.contains(node), "{node}");
        }
    }

    #[test]
    fn wildcard_sets_every_known_bit() {
        let (bitset, extras) = encode(&strings(&["*"]), &[]);
        assert!(extras.is_empty());
        assert_eq!(bitset, vec![0xFF, 0xFF, 0xFF, 0x0F]);
        assert_eq!(decode(&bitset, &extras).len(), INDEX_TO_NODE.len());
    }

    #[test]
    fn denied_nodes_clear_bits() {
        let (bitset, _) = encode(
            &strings(&["basis.moderation.ban", "basis.moderation.message"]),
            &strings(&["basis.moderation.ban"]),
        );
        let decoded = decode(&bitset, &[]);
        assert!(!decoded.contains("basis.moderation.ban"));
        assert!(decoded.contains("basis.moderation.message"));
    }
}
