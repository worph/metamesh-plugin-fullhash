//! MidHash256 - O(1) file identification hash
//!
//! Computes a SHA-256 hash of the file size and middle portion,
//! providing constant-time file identification regardless of file size.
//!
//! Algorithm:
//! - Files ≤1MB: SHA-256(size_u64_be || entire_content)
//! - Files >1MB: SHA-256(size_u64_be || middle_1MB)

use anyhow::Result;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Size threshold: files at or below this size are hashed entirely
const SIZE_THRESHOLD: u64 = 1024 * 1024; // 1MB

/// Sample size for files larger than threshold
const SAMPLE_SIZE: usize = 1024 * 1024; // 1MB

/// Compute midhash256 for a file
///
/// Returns the raw 32-byte SHA-256 hash
pub fn compute_midhash256(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let file_size = metadata.len();

    let mut hasher = Sha256::new();

    // Always include file size as 8-byte big-endian prefix
    hasher.update(file_size.to_be_bytes());

    if file_size <= SIZE_THRESHOLD {
        // Small file: hash entire content
        let mut buffer = Vec::with_capacity(file_size as usize);
        file.read_to_end(&mut buffer)?;
        hasher.update(&buffer);
    } else {
        // Large file: hash middle 1MB
        let middle_start = (file_size - SAMPLE_SIZE as u64) / 2;
        file.seek(SeekFrom::Start(middle_start))?;

        let mut buffer = vec![0u8; SAMPLE_SIZE];
        file.read_exact(&mut buffer)?;
        hasher.update(&buffer);
    }

    let hash = hasher.finalize();
    Ok(hash.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_small_file() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"hello world").unwrap();
        file.flush().unwrap();

        let hash = compute_midhash256(file.path()).unwrap();
        assert_eq!(hash.len(), 32);

        // Same content should produce same hash
        let hash2 = compute_midhash256(file.path()).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_different_sizes_different_hashes() {
        // Two files with same content but different sizes should have different hashes
        // because we include the size in the hash
        let mut file1 = NamedTempFile::new().unwrap();
        file1.write_all(b"hello").unwrap();
        file1.flush().unwrap();

        let mut file2 = NamedTempFile::new().unwrap();
        file2.write_all(b"hello world").unwrap();
        file2.flush().unwrap();

        let hash1 = compute_midhash256(file1.path()).unwrap();
        let hash2 = compute_midhash256(file2.path()).unwrap();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_empty_file() {
        let file = NamedTempFile::new().unwrap();
        let hash = compute_midhash256(file.path()).unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_exactly_1mb_file() {
        let mut file = NamedTempFile::new().unwrap();
        let data = vec![0xab; SIZE_THRESHOLD as usize];
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        let hash = compute_midhash256(file.path()).unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_large_file_middle_sampling() {
        // Create a file larger than 1MB with known content
        let mut file = NamedTempFile::new().unwrap();

        // Write 2MB: first 512KB of 'A', middle 1MB of 'B', last 512KB of 'C'
        let first_half = vec![b'A'; 512 * 1024];
        let middle = vec![b'B'; 1024 * 1024];
        let last_half = vec![b'C'; 512 * 1024];

        file.write_all(&first_half).unwrap();
        file.write_all(&middle).unwrap();
        file.write_all(&last_half).unwrap();
        file.flush().unwrap();

        let hash = compute_midhash256(file.path()).unwrap();
        assert_eq!(hash.len(), 32);

        // Create another file with same middle but different edges
        let mut file2 = NamedTempFile::new().unwrap();
        let first_half2 = vec![b'X'; 512 * 1024];
        let last_half2 = vec![b'Y'; 512 * 1024];

        file2.write_all(&first_half2).unwrap();
        file2.write_all(&middle).unwrap();
        file2.write_all(&last_half2).unwrap();
        file2.flush().unwrap();

        let hash2 = compute_midhash256(file2.path()).unwrap();

        // Both files have same size and same middle 1MB, so hashes should match
        assert_eq!(hash, hash2);
    }
}
