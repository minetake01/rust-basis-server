//! Avatar keyframe quality reduction.

pub mod repack;

pub use repack::{decode_position, payload_bytes, repack_high, rotation_bits, rotation_bytes};
