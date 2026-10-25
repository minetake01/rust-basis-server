//! Avatar keyframe repacking.
//!
//! The client sends one High-quality keyframe payload. Distant peers do not need the full
//! 159-byte form, so the server re-quantizes the smallest-three bone fields and finger channels
//! into Medium/Low/VeryLow, matching the C# `AvatarQualityRepacker`. The high-only end-effector
//! block is intentionally dropped for lower tiers, exactly as the C# repacker does.

use basis_protocol::AvatarQuality;

const POSITION_BYTES: usize = 9;
const ROTATION_BYTES_HIGH: usize = 94;
const TAIL_BYTES: usize = 21;
const HIGH_PAYLOAD_BYTES: usize = 159;

const BONE_SLOTS: usize = 21;
const FINGER_SLOTS: usize = 10;
const FIELD_COUNT: usize = BONE_SLOTS + FINGER_SLOTS;

// DOF per wire bone slot: 3 = smallest-three, 2 = hinge+twist, 1 = single angle.
const BONE_DOF: [u8; BONE_SLOTS] = [
    3, 3, 3, 3, 3, 3, 3, 3, 3, // body ball joints
    2, 2, 2, 2, // lower arms / lower legs
    2, 2, 2, 2, 2, 2, // shoulders / hands / feet
    1, 1, // toes
];

const BPC: [[u8; 9]; 4] = [
    [5, 5, 5, 5, 5, 5, 5, 5, 5],          // VeryLow
    [6, 6, 6, 6, 6, 6, 6, 6, 6],          // Low
    [8, 8, 8, 8, 8, 8, 8, 8, 8],          // Medium
    [12, 12, 12, 12, 12, 12, 12, 12, 12], // High
];
const HINGE_BITS: [usize; 4] = [6, 7, 9, 13];
const TWIST_BITS: [usize; 4] = [5, 6, 8, 12];
const SINGLE_BITS: [usize; 4] = [4, 4, 5, 7];
const CURL_BITS: [usize; 4] = [5, 6, 7, 8];
const SPLAY_BITS: [usize; 4] = [3, 4, 5, 6];

#[inline]
fn q_index(q: AvatarQuality) -> usize {
    match q {
        AvatarQuality::VeryLow => 0,
        AvatarQuality::Low => 1,
        AvatarQuality::Medium => 2,
        AvatarQuality::High => 3,
    }
}

#[inline]
fn field_width(q: AvatarQuality, slot: usize) -> usize {
    let qi = q_index(q);
    match BONE_DOF[slot] {
        3 => 2 + 3 * BPC[qi][slot] as usize,
        2 => HINGE_BITS[qi] + TWIST_BITS[qi],
        _ => SINGLE_BITS[qi],
    }
}

fn field_offsets(q: AvatarQuality) -> ([usize; FIELD_COUNT], usize) {
    let mut offsets = [0usize; FIELD_COUNT];
    let mut pos = 0usize;
    for (slot, offset) in offsets.iter_mut().take(BONE_SLOTS).enumerate() {
        *offset = pos;
        pos += field_width(q, slot);
    }
    let finger_width = CURL_BITS[q_index(q)] + SPLAY_BITS[q_index(q)];
    for offset in offsets.iter_mut().skip(BONE_SLOTS) {
        *offset = pos;
        pos += finger_width;
    }
    (offsets, pos)
}

pub fn rotation_bits(q: AvatarQuality) -> usize {
    field_offsets(q).1
}

pub fn rotation_bytes(q: AvatarQuality) -> usize {
    rotation_bits(q).div_ceil(8)
}

pub fn payload_bytes(q: AvatarQuality) -> usize {
    POSITION_BYTES + rotation_bytes(q) + TAIL_BYTES + if q == AvatarQuality::High { 35 } else { 0 }
}

fn read_bits(src: &[u8], bit_pos: usize, count: usize) -> u64 {
    debug_assert!(count <= 64);
    let mut out = 0u64;
    for i in 0..count {
        let bit = (src[(bit_pos + i) >> 3] >> ((bit_pos + i) & 7)) & 1;
        out |= (bit as u64) << i;
    }
    out
}

fn write_bits(dst: &mut [u8], bit_pos: usize, value: u64, count: usize) {
    debug_assert!(count <= 64);
    for i in 0..count {
        let bit = ((value >> i) & 1) as u8;
        let byte = &mut dst[(bit_pos + i) >> 3];
        let mask = 1u8 << ((bit_pos + i) & 7);
        if bit == 0 {
            *byte &= !mask;
        } else {
            *byte |= mask;
        }
    }
}

#[inline]
fn rescale(value: u64, src_bits: usize, dst_bits: usize) -> u64 {
    if src_bits == dst_bits {
        return value;
    }
    if dst_bits == 0 {
        return 0;
    }
    let src_max = (1u64 << src_bits) - 1;
    let dst_max = (1u64 << dst_bits) - 1;
    (value * dst_max + src_max / 2) / src_max
}

/// Repacks a High-quality payload into `target`. Returns `None` for malformed input.
pub fn repack_high(high: &[u8], target: AvatarQuality) -> Option<Vec<u8>> {
    if high.len() < HIGH_PAYLOAD_BYTES {
        return None;
    }
    if target == AvatarQuality::High {
        return Some(high[..HIGH_PAYLOAD_BYTES].to_vec());
    }

    let source_offsets = field_offsets(AvatarQuality::High).0;
    let (target_offsets, target_bits) = field_offsets(target);
    let target_rotation_bytes = target_bits.div_ceil(8);
    let mut out = vec![0u8; payload_bytes(target)];
    out[..POSITION_BYTES].copy_from_slice(&high[..POSITION_BYTES]);

    let src_rot_base = POSITION_BYTES;
    let dst_rot_base = POSITION_BYTES;
    let src_bpc = BPC[q_index(AvatarQuality::High)];
    let dst_bpc = BPC[q_index(target)];
    let src_hinge = HINGE_BITS[q_index(AvatarQuality::High)];
    let dst_hinge = HINGE_BITS[q_index(target)];
    let src_twist = TWIST_BITS[q_index(AvatarQuality::High)];
    let dst_twist = TWIST_BITS[q_index(target)];
    let src_single = SINGLE_BITS[q_index(AvatarQuality::High)];
    let dst_single = SINGLE_BITS[q_index(target)];

    for slot in 0..BONE_SLOTS {
        let src_bit = src_rot_base * 8 + source_offsets[slot];
        let dst_bit = dst_rot_base * 8 + target_offsets[slot];
        match BONE_DOF[slot] {
            3 => {
                let total = 2 + 3 * src_bpc[slot] as usize;
                let raw = read_bits(high, src_bit, total);
                let idx = raw & 0x3;
                let src = src_bpc[slot] as usize;
                let dst = dst_bpc[slot] as usize;
                let mask = (1u64 << src) - 1;
                let qa = (raw >> 2) & mask;
                let qb = (raw >> (2 + src)) & mask;
                let qc = (raw >> (2 + 2 * src)) & mask;
                let da = rescale(qa, src, dst);
                let db = rescale(qb, src, dst);
                let dc = rescale(qc, src, dst);
                let packed = idx | (da << 2) | (db << (2 + dst)) | (dc << (2 + 2 * dst));
                write_bits(&mut out, dst_bit, packed, 2 + 3 * dst);
            }
            2 => {
                let hinge = read_bits(high, src_bit, src_hinge);
                let twist = read_bits(high, src_bit + src_hinge, src_twist);
                let packed = rescale(hinge, src_hinge, dst_hinge)
                    | (rescale(twist, src_twist, dst_twist) << dst_hinge);
                write_bits(&mut out, dst_bit, packed, dst_hinge + dst_twist);
            }
            _ => {
                let value = read_bits(high, src_bit, src_single);
                write_bits(
                    &mut out,
                    dst_bit,
                    rescale(value, src_single, dst_single),
                    dst_single,
                );
            }
        }
    }

    let src_curl = CURL_BITS[q_index(AvatarQuality::High)];
    let dst_curl = CURL_BITS[q_index(target)];
    let src_splay = SPLAY_BITS[q_index(AvatarQuality::High)];
    let dst_splay = SPLAY_BITS[q_index(target)];
    for finger in 0..FINGER_SLOTS {
        let field = BONE_SLOTS + finger;
        let src_bit = src_rot_base * 8 + source_offsets[field];
        let dst_bit = dst_rot_base * 8 + target_offsets[field];
        let curl = read_bits(high, src_bit, src_curl);
        let splay = read_bits(high, src_bit + src_curl, src_splay);
        let packed =
            rescale(curl, src_curl, dst_curl) | (rescale(splay, src_splay, dst_splay) << dst_curl);
        write_bits(&mut out, dst_bit, packed, dst_curl + dst_splay);
    }

    let src_tail = POSITION_BYTES + ROTATION_BYTES_HIGH;
    let dst_tail = POSITION_BYTES + target_rotation_bytes;
    out[dst_tail..dst_tail + TAIL_BYTES].copy_from_slice(&high[src_tail..src_tail + TAIL_BYTES]);
    Some(out)
}

/// Decodes the int24-millimetre position at the start of an avatar payload.
pub fn decode_position(payload: &[u8]) -> Option<[f32; 3]> {
    if payload.len() < POSITION_BYTES {
        return None;
    }
    let axis = |offset: usize| {
        let raw = payload[offset] as i32
            | ((payload[offset + 1] as i32) << 8)
            | ((payload[offset + 2] as i32) << 16);
        ((raw << 8) >> 8) as f32 * 0.001
    };
    Some([axis(0), axis(3), axis(6)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_sizes_match_the_wire_ladder() {
        assert_eq!(payload_bytes(AvatarQuality::VeryLow), 74);
        assert_eq!(payload_bytes(AvatarQuality::Low), 83);
        assert_eq!(payload_bytes(AvatarQuality::Medium), 97);
        assert_eq!(payload_bytes(AvatarQuality::High), 159);
    }

    #[test]
    fn high_is_preserved() {
        let high = vec![0x5au8; 159];
        assert_eq!(repack_high(&high, AvatarQuality::High).unwrap(), high);
    }

    #[test]
    fn lower_tiers_keep_position_and_tail() {
        let mut high = vec![0u8; 159];
        high[..9].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        high[103..124].copy_from_slice(&[0xAA; 21]);
        for q in [
            AvatarQuality::VeryLow,
            AvatarQuality::Low,
            AvatarQuality::Medium,
        ] {
            let out = repack_high(&high, q).unwrap();
            assert_eq!(out.len(), payload_bytes(q));
            assert_eq!(&out[..9], &high[..9]);
            let tail = 9 + rotation_bytes(q);
            assert_eq!(&out[tail..tail + 21], &high[103..124]);
        }
    }

    #[test]
    fn matches_the_csharp_repacker_oracle() {
        let high: Vec<u8> = (0..159u16).map(|i| i as u8).collect();
        assert_eq!(
            hex::encode(repack_high(&high, AvatarQuality::Medium).unwrap()).to_uppercase(),
            "000102030405060708A10CD0000F115201557118A11BD01D032232226532A8A22BD22E0333323365339833BB333E4441344464479448C74CF6542145958AE9C46AB51A4ECBF582C1A211AD266768696A6B6C6D6E6F707172737475767778797A7B"
        );
        assert_eq!(
            hex::encode(repack_high(&high, AvatarQuality::Low).unwrap()).to_uppercase(),
            "0001020304050607082941C34E2005559C811E7431089250CAA8E8422FBFA33CDD820EFBE413414D94492434433E159456655D546519D7791B86E14855026768696A6B6C6D6E6F707172737475767778797A7B"
        );
        assert_eq!(
            hex::encode(repack_high(&high, AvatarQuality::VeryLow).unwrap()).to_uppercase(),
            "0001020304050607081560E88214146ED081C310429478468B36DF98D3061E7BF6026C114B126DE459282D3517A53567EE31C628456768696A6B6C6D6E6F707172737475767778797A7B"
        );
    }

    #[test]
    fn rejects_short_input() {
        assert!(repack_high(&[0u8; 158], AvatarQuality::Low).is_none());
    }
}
