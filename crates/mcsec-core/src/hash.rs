//! File hashes used to identify jars across Modrinth, CurseForge, and the
//! results store.

use serde::Serialize;
use sha1::{Digest, Sha1};
use sha2::Sha512;

/// Hashes of one file's exact bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileHashes {
    /// Lowercase hex SHA-1. Both platforms publish this, so it is the
    /// deduplication key.
    pub sha1: String,
    /// Lowercase hex SHA-512, as published by Modrinth.
    pub sha512: String,
    /// CurseForge's file fingerprint.
    pub curseforge_fingerprint: u32,
}

impl FileHashes {
    pub fn compute(data: &[u8]) -> Self {
        Self {
            sha1: hex::encode(Sha1::digest(data)),
            sha512: hex::encode(Sha512::digest(data)),
            curseforge_fingerprint: curseforge_fingerprint(data),
        }
    }
}

/// CurseForge's fingerprint, which is MurmurHash2 with seed 1 over the file
/// with every tab, line feed, carriage return, and space byte removed.
pub fn curseforge_fingerprint(data: &[u8]) -> u32 {
    let len = data
        .iter()
        .filter(|&&b| !is_fingerprint_whitespace(b))
        .count();
    let bytes = data
        .iter()
        .copied()
        .filter(|&b| !is_fingerprint_whitespace(b));
    murmur2(bytes, len as u32, 1)
}

fn is_fingerprint_whitespace(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | b'\r' | b' ')
}

/// 32-bit MurmurHash2 over a byte stream of known length. Taking an iterator
/// lets the fingerprint skip whitespace without copying the file.
fn murmur2(mut bytes: impl Iterator<Item = u8>, len: u32, seed: u32) -> u32 {
    const M: u32 = 0x5bd1_e995;
    const R: u32 = 24;

    let mut h = seed ^ len;
    let mut chunk = [0u8; 4];
    let mut filled;

    loop {
        filled = 0;
        while filled < 4 {
            match bytes.next() {
                Some(b) => {
                    chunk[filled] = b;
                    filled += 1;
                }
                None => break,
            }
        }
        if filled < 4 {
            break;
        }
        let mut k = u32::from_le_bytes(chunk);
        k = k.wrapping_mul(M);
        k ^= k >> R;
        k = k.wrapping_mul(M);
        h = h.wrapping_mul(M);
        h ^= k;
    }

    // Tail bytes, mixed in the same order as the reference implementation's
    // fallthrough switch.
    if filled == 3 {
        h ^= u32::from(chunk[2]) << 16;
    }
    if filled >= 2 {
        h ^= u32::from(chunk[1]) << 8;
    }
    if filled >= 1 {
        h ^= u32::from(chunk[0]);
        h = h.wrapping_mul(M);
    }

    h ^= h >> 13;
    h = h.wrapping_mul(M);
    h ^= h >> 15;
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn murmur2_slice(data: &[u8], seed: u32) -> u32 {
        murmur2(data.iter().copied(), data.len() as u32, seed)
    }

    // Reference values come from the murmurhash2 Python package, an
    // independent implementation of the same algorithm.
    #[test]
    fn murmur2_matches_reference() {
        assert_eq!(murmur2_slice(b"", 1), 1540447798);
        assert_eq!(murmur2_slice(b"a", 1), 626045324);
        assert_eq!(murmur2_slice(b"ab", 1), 1692487918);
        assert_eq!(murmur2_slice(b"abc", 1), 1621425345);
        assert_eq!(murmur2_slice(b"abcd", 1), 3376380438);
        assert_eq!(
            murmur2_slice(b"The quick brown fox jumps over the lazy dog", 1),
            504383975
        );
    }

    #[test]
    fn fingerprint_ignores_whitespace() {
        assert_eq!(
            curseforge_fingerprint(b"a b\tc\r\nd"),
            murmur2_slice(b"abcd", 1)
        );
    }

    #[test]
    fn computes_known_digests() {
        let hashes = FileHashes::compute(b"abc");
        assert_eq!(hashes.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert!(hashes.sha512.starts_with("ddaf35a193617aba"));
    }
}
