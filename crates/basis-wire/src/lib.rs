//! NetDataReader/NetDataWriter-compatible primitives and the localized unsafe fast path.

pub mod fast;
pub mod wire;

pub use wire::{Reader, WireError, WireResult, Writer};
