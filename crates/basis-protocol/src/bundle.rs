//! Avatar bundle framing compatible with BasisNetworkCommons.CompressedAvatarBundleChannel.

use crate::lz4;

pub const BUNDLE_HEADER: usize = 3;
pub const CODEC_LZ4: u8 = 0;
pub const CODEC_ZSTD_DICT: u8 = 1;
const CODEC_BITS: u8 = 3;
const CODEC_MASK: u8 = (1 << CODEC_BITS) - 1;
const MAX_DICT_GENERATION: u8 = 0x1F;

/// Packs the codec id and Zstd dictionary generation into a bundle flags byte.
pub fn pack_flags(codec: u8, dictionary_generation: u8) -> u8 {
    (codec & CODEC_MASK) | ((dictionary_generation & MAX_DICT_GENERATION) << CODEC_BITS)
}

pub fn codec_of(flags: u8) -> u8 {
    flags & CODEC_MASK
}

pub fn dict_generation_of(flags: u8) -> u8 {
    (flags >> CODEC_BITS) & MAX_DICT_GENERATION
}

/// Builds a one-message LZ4 bundle for `channel`.
pub fn build_single(channel: u8, payload: &[u8]) -> Option<Vec<u8>> {
    build_groups(&[(channel, vec![payload.to_vec()])])
}

/// Builds a bundle from channel-grouped payloads. Returns `None` when a group is empty,
/// a payload exceeds u16, or the raw body would exceed u16.
pub fn build_groups(groups: &[(u8, Vec<Vec<u8>>)]) -> Option<Vec<u8>> {
    let mut raw = Vec::new();
    for (channel, payloads) in groups {
        if payloads.is_empty() {
            return None;
        }
        let mut index = 0usize;
        while index < payloads.len() {
            let count = (payloads.len() - index).min(255);
            raw.push(*channel);
            raw.push(count as u8);
            for payload in &payloads[index..index + count] {
                if payload.len() > u16::MAX as usize {
                    return None;
                }
                raw.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            }
            if *channel == 30 {
                let max_len = payloads[index..index + count]
                    .iter()
                    .map(Vec::len)
                    .max()
                    .unwrap_or(0);
                for offset in 0..max_len {
                    for payload in &payloads[index..index + count] {
                        if let Some(byte) = payload.get(offset) {
                            raw.push(*byte);
                        }
                    }
                }
            } else {
                for payload in &payloads[index..index + count] {
                    raw.extend_from_slice(payload);
                }
            }
            index += count;
        }
    }
    if raw.len() > u16::MAX as usize {
        return None;
    }
    let keyframe = groups.iter().any(|(channel, _)| *channel != 30);
    if keyframe {
        if let Some(body) = crate::zstd_dict::compress(&raw) {
            let mut out = Vec::with_capacity(BUNDLE_HEADER + body.len());
            out.push(pack_flags(CODEC_ZSTD_DICT, crate::zstd_dict::GENERATION));
            out.extend_from_slice(&(raw.len() as u16).to_le_bytes());
            out.extend_from_slice(&body);
            return Some(out);
        }
    }
    let body = lz4::encode_literal_block(&raw);
    let mut out = Vec::with_capacity(BUNDLE_HEADER + body.len());
    out.push(pack_flags(CODEC_LZ4, 0));
    out.extend_from_slice(&(raw.len() as u16).to_le_bytes());
    out.extend_from_slice(&body);
    Some(out)
}

/// Parses a bundle into its flags, declared raw length, and body.
pub fn parse(data: &[u8]) -> Option<(u8, u16, &[u8])> {
    if data.len() < BUNDLE_HEADER {
        return None;
    }
    let raw_len = u16::from_le_bytes([data[1], data[2]]);
    Some((data[0], raw_len, &data[BUNDLE_HEADER..]))
}

/// Decodes a bundle into `(channel, payload)` groups.
pub fn decode(data: &[u8]) -> Option<Vec<(u8, Vec<u8>)>> {
    let (flags, raw_len, body) = parse(data)?;
    let raw = match codec_of(flags) {
        CODEC_LZ4 => lz4::decode_block(body, raw_len as usize)?,
        CODEC_ZSTD_DICT if dict_generation_of(flags) == crate::zstd_dict::GENERATION => {
            crate::zstd_dict::decompress(body, raw_len as usize)?
        }
        _ => return None,
    };
    if raw.len() != raw_len as usize {
        return None;
    }
    let mut groups = Vec::new();
    let mut index = 0usize;
    while index < raw.len() {
        let channel = *raw.get(index)?;
        index += 1;
        let count = *raw.get(index)? as usize;
        index += 1;
        if count == 0 {
            return None;
        }
        let mut lengths = Vec::with_capacity(count);
        for _ in 0..count {
            if index + 2 > raw.len() {
                return None;
            }
            lengths.push(u16::from_le_bytes([raw[index], raw[index + 1]]) as usize);
            index += 2;
        }
        if channel == 30 {
            let total: usize = lengths.iter().sum();
            let end = index + total;
            let columns = raw.get(index..end)?;
            let max_len = lengths.iter().copied().max().unwrap_or(0);
            let mut bodies = vec![Vec::with_capacity(0); count];
            let mut column = 0usize;
            for offset in 0..max_len {
                for (body, len) in bodies.iter_mut().zip(&lengths) {
                    if offset < *len {
                        body.push(*columns.get(column)?);
                        column += 1;
                    }
                }
            }
            index = end;
            for body in bodies {
                groups.push((channel, body));
            }
        } else {
            for len in lengths {
                let end = index + len;
                let payload = raw.get(index..end)?.to_vec();
                index = end;
                groups.push((channel, payload));
            }
        }
    }
    Some(groups)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_message_bundle_round_trips() {
        let bundle = build_single(12, b"avatar payload").unwrap();
        let (flags, raw_len, _) = parse(&bundle).unwrap();
        assert_eq!(codec_of(flags), CODEC_ZSTD_DICT);
        assert_eq!(dict_generation_of(flags), crate::zstd_dict::GENERATION);
        assert!(raw_len >= 4);
        assert_eq!(
            decode(&bundle),
            Some(vec![(12, b"avatar payload".to_vec())])
        );
    }

    #[test]
    fn multi_group_bundle_round_trips() {
        let bundle = build_groups(&[
            (12, vec![b"one".to_vec(), b"two".to_vec()]),
            (13, vec![b"three".to_vec()]),
        ])
        .unwrap();
        assert_eq!(
            decode(&bundle),
            Some(vec![
                (12, b"one".to_vec()),
                (12, b"two".to_vec()),
                (13, b"three".to_vec())
            ])
        );
    }

    #[test]
    fn delta_groups_are_column_transposed_and_round_trip() {
        let bundle = build_groups(&[(30, vec![b"abc".to_vec(), b"de".to_vec()])]).unwrap();
        assert_eq!(
            decode(&bundle),
            Some(vec![(30, b"abc".to_vec()), (30, b"de".to_vec())])
        );
    }

    #[test]
    fn flags_pack_codec_and_dictionary_generation() {
        let flags = pack_flags(CODEC_ZSTD_DICT, 7);
        assert_eq!(codec_of(flags), CODEC_ZSTD_DICT);
        assert_eq!(dict_generation_of(flags), 7);
        let lz4 = pack_flags(CODEC_LZ4, 0);
        assert_eq!(codec_of(lz4), CODEC_LZ4);
        assert_eq!(dict_generation_of(lz4), 0);
    }

    #[test]
    fn rejects_truncated_and_oversize() {
        assert!(parse(&[0, 1]).is_none());
        let oversize = vec![0u8; u16::MAX as usize + 1];
        assert!(build_single(12, &oversize).is_none());
    }
}
