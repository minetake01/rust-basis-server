//! Zstd dictionary codec for avatar bundles, byte-compatible with
//! `BasisAvatarBundleZstd` (magicless frame, no content size, no checksum, no dictionary id).

use std::ffi::c_void;

pub const GENERATION: u8 = 1;
pub const DICTIONARY: &[u8] = include_bytes!("avatar_bundle_dictionary.bin");

const MAGICLESS: i32 = 1;
const FORMAT_C: u32 = 10; // ZSTD_c_experimentalParam2
const FORMAT_D: u32 = 1000; // ZSTD_d_experimentalParam1
const LEVEL: i32 = -2;
const CONTENT_SIZE_FLAG: u32 = 200;
const CHECKSUM_FLAG: u32 = 201;
const DICT_ID_FLAG: u32 = 202;

fn is_error(code: usize) -> bool {
    unsafe { zstd_sys::ZSTD_isError(code) != 0 }
}

/// Compresses `raw` into a magicless dictionary frame.
pub fn compress(raw: &[u8]) -> Option<Vec<u8>> {
    if DICTIONARY.is_empty() {
        return None;
    }
    unsafe {
        let context = zstd_sys::ZSTD_createCCtx();
        if context.is_null() {
            return None;
        }
        let set = |parameter: u32, value: i32| {
            let parameter = std::mem::transmute::<u32, zstd_sys::ZSTD_cParameter>(parameter);
            let code = zstd_sys::ZSTD_CCtx_setParameter(context, parameter, value);
            !is_error(code)
        };
        let configured = set(100, LEVEL)
            && set(FORMAT_C, MAGICLESS)
            && set(CONTENT_SIZE_FLAG, 0)
            && set(CHECKSUM_FLAG, 0)
            && set(DICT_ID_FLAG, 0);
        let loaded = !is_error(zstd_sys::ZSTD_CCtx_loadDictionary(
            context,
            DICTIONARY.as_ptr() as *const c_void,
            DICTIONARY.len(),
        ));
        let mut output = vec![0u8; zstd_sys::ZSTD_compressBound(raw.len())];
        let written = if configured && loaded {
            zstd_sys::ZSTD_compress2(
                context,
                output.as_mut_ptr() as *mut c_void,
                output.len(),
                raw.as_ptr() as *const c_void,
                raw.len(),
            )
        } else {
            0
        };
        zstd_sys::ZSTD_freeCCtx(context);
        if written == 0 || is_error(written) {
            return None;
        }
        output.truncate(written);
        Some(output)
    }
}

/// Decompresses a magicless dictionary frame, bounded by `max_output`.
pub fn decompress(data: &[u8], max_output: usize) -> Option<Vec<u8>> {
    if DICTIONARY.is_empty() {
        return None;
    }
    unsafe {
        let context = zstd_sys::ZSTD_createDCtx();
        if context.is_null() {
            return None;
        }
        let format = zstd_sys::ZSTD_DCtx_setParameter(
            context,
            std::mem::transmute::<u32, zstd_sys::ZSTD_dParameter>(FORMAT_D),
            MAGICLESS,
        );
        let loaded = !is_error(zstd_sys::ZSTD_DCtx_loadDictionary(
            context,
            DICTIONARY.as_ptr() as *const c_void,
            DICTIONARY.len(),
        ));
        let mut output = vec![0u8; max_output];
        let written = if !is_error(format) && loaded {
            zstd_sys::ZSTD_decompressDCtx(
                context,
                output.as_mut_ptr() as *mut c_void,
                output.len(),
                data.as_ptr() as *const c_void,
                data.len(),
            )
        } else {
            usize::MAX
        };
        zstd_sys::ZSTD_freeDCtx(context);
        if written == usize::MAX || is_error(written) {
            return None;
        }
        output.truncate(written);
        Some(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_against_the_embedded_dictionary() {
        let raw = b"avatar bundle payload with dictionary references".repeat(4);
        let compressed = compress(&raw).expect("compress");
        assert!(!compressed.is_empty());
        let decoded = decompress(&compressed, raw.len()).expect("decompress");
        assert_eq!(decoded, raw);
    }

    #[test]
    fn rejects_output_larger_than_the_bound() {
        let raw = vec![7u8; 512];
        let compressed = compress(&raw).expect("compress");
        assert!(decompress(&compressed, 128).is_none());
    }
}
