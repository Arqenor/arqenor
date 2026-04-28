//! Streaming SHA-256 helpers with explicit per-file size caps.
//!
//! Replaces the workspace's previous `std::fs::read(path) → Sha256::digest`
//! pattern, which loaded entire files into memory before hashing — fine for
//! small artefacts but a guaranteed OOM on attacker-controlled paths or large
//! image files. Every hashing site in the platform crate routes through this
//! module so the cap is enforced uniformly.
//!
//! ```rust,ignore
//! use arqenor_platform::hash::{sha256_file_streaming, DEFAULT_MAX_HASH_SIZE};
//! let digest = sha256_file_streaming(path, DEFAULT_MAX_HASH_SIZE)?;
//! ```

use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// Default per-file size cap for streaming hashes — 512 MiB.
///
/// Tuned to comfortably cover legitimate Windows/Linux system binaries
/// (largest known: ~150 MiB) while bailing out long before a hostile or
/// runaway file can exhaust process memory.
pub const DEFAULT_MAX_HASH_SIZE: u64 = 512 * 1024 * 1024;

/// Errors produced by the streaming hash helpers.
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("file too large: {actual} > {max}")]
    TooLarge { actual: u64, max: u64 },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Stream SHA-256 of a file in 64 KiB chunks, refusing to hash files larger
/// than `max_size` bytes (returns [`HashError::TooLarge`]).
///
/// The size cap is checked against `metadata().len()` *before* any reads
/// happen, so an oversized file never allocates a 1-shot buffer.
pub fn sha256_file_streaming(path: &Path, max_size: u64) -> Result<[u8; 32], HashError> {
    let mut file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    let len = metadata.len();
    if len > max_size {
        return Err(HashError::TooLarge {
            actual: len,
            max: max_size,
        });
    }

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// Convenience wrapper returning the hex string form, or `None` on any error
/// (size cap, I/O). For legacy call sites that previously fell back to a
/// sentinel string when reading failed.
pub fn sha256_file_hex(path: &Path, max_size: u64) -> Option<String> {
    sha256_file_streaming(path, max_size).ok().map(hex::encode)
}

/// Streaming-style SHA-256 over an in-memory byte slice. Provided so callers
/// can route every digest through this module even when the bytes are already
/// resident (e.g. PE images already mapped for parsing).
pub fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(contents: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let unique = format!(
            "arqenor-hash-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        );
        let path = dir.join(unique);
        let mut f = std::fs::File::create(&path).expect("tmp create");
        f.write_all(contents).expect("tmp write");
        path
    }

    #[test]
    fn hashes_small_file_correctly() {
        let path = write_tmp(b"abc");
        // SHA-256("abc") well-known vector.
        let expected_hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let digest = sha256_file_streaming(&path, DEFAULT_MAX_HASH_SIZE).expect("hash ok");
        assert_eq!(hex::encode(digest), expected_hex);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn refuses_files_above_cap() {
        // Build a 4 KiB file and use a 1 KiB cap to force the error.
        let path = write_tmp(&vec![0u8; 4096]);
        let err = sha256_file_streaming(&path, 1024).expect_err("must fail");
        match err {
            HashError::TooLarge { actual, max } => {
                assert_eq!(actual, 4096);
                assert_eq!(max, 1024);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn hex_helper_returns_none_when_oversized() {
        let path = write_tmp(&vec![1u8; 2048]);
        assert!(sha256_file_hex(&path, 64).is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sha256_bytes_matches_streaming() {
        let path = write_tmp(b"hello world");
        let streamed = sha256_file_streaming(&path, DEFAULT_MAX_HASH_SIZE).expect("hash");
        let in_memory = sha256_bytes(b"hello world");
        assert_eq!(streamed, in_memory);
        let _ = std::fs::remove_file(path);
    }
}
