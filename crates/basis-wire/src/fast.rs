//! Localized unsafe fast paths.
//!
//! Every function here has a narrow, caller-checked contract: the offset and length
//! preconditions are established by the packet parser before the call. The functions are
//! `#[inline(always)]` so the compiler can fold the bounds-checked caller condition into the
//! load; this is the only place in the server where raw pointer reads and writes are used.

use std::ptr;

/// # Safety
/// `buf.len() >= offset + 2`.
#[inline(always)]
pub unsafe fn read_u16_le_unchecked(buf: &[u8], offset: usize) -> u16 {
    debug_assert!(
        offset + 2 <= buf.len(),
        "read_u16_le_unchecked out of bounds"
    );
    // SAFETY: the caller guarantees two readable bytes at `offset`; the pointer is derived
    // from a live slice and `read_unaligned` accepts any alignment.
    unsafe { u16::from_le(ptr::read_unaligned(buf.as_ptr().add(offset) as *const u16)) }
}

/// # Safety
/// `buf.len() >= offset + 4`.
#[inline(always)]
pub unsafe fn read_u32_le_unchecked(buf: &[u8], offset: usize) -> u32 {
    debug_assert!(
        offset + 4 <= buf.len(),
        "read_u32_le_unchecked out of bounds"
    );
    // SAFETY: the caller guarantees four readable bytes at `offset`.
    unsafe { u32::from_le(ptr::read_unaligned(buf.as_ptr().add(offset) as *const u32)) }
}

/// # Safety
/// `buf.len() >= offset + 2`.
#[inline(always)]
pub unsafe fn write_u16_le_unchecked(buf: &mut [u8], offset: usize, value: u16) {
    debug_assert!(
        offset + 2 <= buf.len(),
        "write_u16_le_unchecked out of bounds"
    );
    // SAFETY: the caller guarantees two writable bytes at `offset`.
    unsafe {
        ptr::write_unaligned(buf.as_mut_ptr().add(offset) as *mut u16, value.to_le());
    }
}

/// # Safety
/// `buf.len() >= offset + len` and `src.len() >= len`.
#[inline(always)]
pub unsafe fn copy_bytes_unchecked(buf: &mut [u8], offset: usize, src: &[u8], len: usize) {
    debug_assert!(
        offset + len <= buf.len(),
        "copy_bytes_unchecked dst out of bounds"
    );
    debug_assert!(len <= src.len(), "copy_bytes_unchecked src out of bounds");
    // SAFETY: both ranges are checked above and cannot overlap because `src` is a distinct
    // immutable slice; `copy_nonoverlapping` is the correct primitive.
    unsafe {
        ptr::copy_nonoverlapping(src.as_ptr(), buf.as_mut_ptr().add(offset), len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unaligned_reads_match_safe_decoding() {
        let buf = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        for offset in 0..=1 {
            let safe = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
            let fast = unsafe { read_u16_le_unchecked(&buf, offset) };
            assert_eq!(safe, fast);
        }
        let safe32 = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(safe32, unsafe { read_u32_le_unchecked(&buf, 0) });
    }

    #[test]
    fn unaligned_write_matches_safe_encoding() {
        let mut a = [0u8; 4];
        let mut b = [0u8; 4];
        a[1..3].copy_from_slice(&0xABCDu16.to_le_bytes());
        unsafe { write_u16_le_unchecked(&mut b, 1, 0xABCD) };
        assert_eq!(a, b);
    }
}
