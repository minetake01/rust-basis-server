//! Port of Basis.Network.Core.PermissionCompression.
//!
//! Wire format: `[flag:1][payload]`, flag 0 = raw UTF-8, flag 1 = Deflate.
//! Strings are NUL-joined before compression.

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::io::{Read, Write};

const MAX_DECOMPRESSED_BYTES: u64 = 1024 * 1024;

pub fn compress(strings: &[String]) -> Vec<u8> {
    if strings.is_empty() {
        return Vec::new();
    }
    let raw = strings.join("\0").into_bytes();
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    if encoder.write_all(&raw).is_err() {
        return Vec::new();
    }
    let Ok(deflated) = encoder.finish() else {
        return Vec::new();
    };
    if deflated.len() < raw.len() {
        let mut out = Vec::with_capacity(deflated.len() + 1);
        out.push(1);
        out.extend_from_slice(&deflated);
        out
    } else {
        let mut out = Vec::with_capacity(raw.len() + 1);
        out.push(0);
        out.extend_from_slice(&raw);
        out
    }
}

pub fn decompress(data: &[u8], expected_count: usize) -> Vec<String> {
    if data.is_empty() || expected_count == 0 {
        return Vec::new();
    }
    let flag = data[0];
    let payload: Vec<u8> = if flag == 1 {
        let mut decoder = DeflateDecoder::new(&data[1..]).take(MAX_DECOMPRESSED_BYTES + 1);
        let mut output = Vec::new();
        if decoder.read_to_end(&mut output).is_err() {
            return Vec::new();
        }
        if output.len() as u64 > MAX_DECOMPRESSED_BYTES {
            return Vec::new();
        }
        output
    } else {
        data[1..].to_vec()
    };
    String::from_utf8_lossy(&payload)
        .split('\0')
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(values: &[&str]) {
        let input: Vec<String> = values.iter().map(|value| value.to_string()).collect();
        let payload = compress(&input);
        assert_eq!(decompress(&payload, input.len()), input);
    }

    #[test]
    fn representative_arrays_round_trip() {
        round_trip(&["a"]);
        round_trip(&["basis.custom.one", "basis.custom.two"]);
        round_trip(&["com.acme.plugin.permission"]);
        round_trip(&["first", "", "third"]);
        round_trip(&[""]);
        round_trip(&["日本語のノード", "ünïcode.pérm", "emoji.\u{1F600}.node"]);
    }

    #[test]
    fn empty_inputs_are_empty() {
        assert!(compress(&[]).is_empty());
        assert!(decompress(&[], 3).is_empty());
        let valid = compress(&["x".to_string(), "y".to_string()]);
        assert!(decompress(&valid, 0).is_empty());
    }

    #[test]
    fn tiny_input_uses_raw_flag() {
        let payload = compress(&["a".to_string()]);
        assert_eq!(payload[0], 0);
        assert_eq!(decompress(&payload, 1), vec!["a".to_string()]);
    }

    #[test]
    fn decompression_cap_rejects_oversize_payload() {
        let big = "a".repeat(1_100_000);
        let payload = compress(&[big]);
        assert_eq!(payload[0], 1, "large input should be Deflate-compressed");
        assert!(decompress(&payload, 1).is_empty());
    }

    #[test]
    fn seeded_random_strings_round_trip() {
        let alphabet = b"abcdefghijklmnopqrstuvwxyz.-_0123456789";
        let mut state = 9001u64;
        let mut strings = Vec::with_capacity(100);
        for _ in 0..100 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let length = 1 + (state as usize % 30);
            let mut value = String::with_capacity(length);
            for _ in 0..length {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                value.push(alphabet[state as usize % alphabet.len()] as char);
            }
            strings.push(value);
        }
        let payload = compress(&strings);
        assert_eq!(decompress(&payload, strings.len()), strings);
    }
}
