//! Minimal LZ4 block codec compatible with the avatar bundle wire format.
//!
//! The encoder emits a valid literal-only block (no matches). That is intentionally
//! uncompressed: the bundle scheduler can use it when compression is disabled or when a
//! payload does not benefit, while the decoder accepts normal LZ4 blocks produced by the
//! C# server.

/// Encodes `input` as a legal LZ4 block made of literals only.
pub fn encode_literal_block(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + input.len() / 255 + 16);
    let literal_len = input.len();
    let token = (literal_len.min(15) as u8) << 4;
    out.push(token);
    if literal_len >= 15 {
        let mut remaining = literal_len - 15;
        while remaining >= 255 {
            out.push(255);
            remaining -= 255;
        }
        out.push(remaining as u8);
    }
    out.extend_from_slice(input);
    out
}

/// Decodes an LZ4 block, returning at most `max_output` bytes.
pub fn decode_block(block: &[u8], max_output: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(max_output.min(block.len() * 4));
    let mut index = 0usize;
    while index < block.len() {
        let token = block[index];
        index += 1;
        let mut literal_len = (token >> 4) as usize;
        if literal_len == 15 {
            loop {
                let add = *block.get(index)? as usize;
                index += 1;
                literal_len += add;
                if add != 255 {
                    break;
                }
            }
        }
        if index + literal_len > block.len() || out.len() + literal_len > max_output {
            return None;
        }
        out.extend_from_slice(&block[index..index + literal_len]);
        index += literal_len;
        if index == block.len() {
            break;
        }
        if index + 2 > block.len() {
            return None;
        }
        let offset = u16::from_le_bytes([block[index], block[index + 1]]) as usize;
        index += 2;
        if offset == 0 || offset > out.len() {
            return None;
        }
        let mut match_len = (token & 0x0F) as usize;
        if match_len == 15 {
            loop {
                let add = *block.get(index)? as usize;
                index += 1;
                match_len += add;
                if add != 255 {
                    break;
                }
            }
        }
        match_len += 4;
        if out.len() + match_len > max_output {
            return None;
        }
        let start = out.len() - offset;
        for i in 0..match_len {
            let byte = out[start + i];
            out.push(byte);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_blocks_round_trip() {
        for input in [
            b"".as_slice(),
            b"a".as_slice(),
            b"hello avatar".as_slice(),
            &[7u8; 300],
        ] {
            let encoded = encode_literal_block(input);
            assert_eq!(decode_block(&encoded, input.len()), Some(input.to_vec()));
        }
    }

    #[test]
    fn decodes_a_match_sequence() {
        // token: 4 literals, match length 0 (+4); offset 4; literals "abcd"; then "abcd".
        let block = [0x40, b'a', b'b', b'c', b'd', 4, 0];
        assert_eq!(decode_block(&block, 8), Some(b"abcdabcd".to_vec()));
    }

    #[test]
    fn rejects_invalid_offsets() {
        let block = [0x04, b'a', b'b', b'c', b'd', 9, 0];
        assert_eq!(decode_block(&block, 32), None);
    }
}
