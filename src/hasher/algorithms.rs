use crate::config::HashAlgorithm;
use anyhow::Result;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use sha3::{Sha3_256, Sha3_384};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use super::btih_v2::{compute_info_hash, compute_merkle_root, BT_BLOCK_SIZE};
use super::cid::to_cid;
use super::midhash256::compute_midhash256;

/// Hash a file using all enabled algorithms in a single I/O pass
///
/// All algorithms except Midhash256 are computed in the same pass:
/// - Standard algorithms update their hashers with each buffer chunk
/// - BitTorrent v2 computes 16KB block hashes from the same data
///
/// Midhash256 requires a separate O(1) read (middle 1MB only).
pub fn hash_file(
    path: &Path,
    enabled: &HashSet<HashAlgorithm>,
    buffer_size: usize,
) -> Result<HashMap<String, String>> {
    let mut results = HashMap::new();

    // Check what we need to compute
    let needs_bt = enabled.contains(&HashAlgorithm::BtPiecesRoot)
        || enabled.contains(&HashAlgorithm::BtInfoHash);

    // Get filename for BT v2 info hash (needed before we start)
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Main single-pass computation (standard + BT v2)
    let (standard_results, bt_leaf_hashes, file_size) =
        hash_file_single_pass(path, enabled, buffer_size, needs_bt)?;
    results.extend(standard_results);

    // Finalize BT v2 hashes from collected leaf hashes
    if needs_bt {
        let pieces_root = compute_merkle_root(&bt_leaf_hashes);

        if enabled.contains(&HashAlgorithm::BtPiecesRoot) {
            results.insert(
                HashAlgorithm::BtPiecesRoot.key().to_string(),
                to_cid(&pieces_root, HashAlgorithm::BtPiecesRoot),
            );
        }

        if enabled.contains(&HashAlgorithm::BtInfoHash) {
            match compute_info_hash(&filename, file_size, &pieces_root) {
                Ok(info_hash) => {
                    results.insert(
                        HashAlgorithm::BtInfoHash.key().to_string(),
                        to_cid(&info_hash, HashAlgorithm::BtInfoHash),
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to compute BT info hash: {}", e);
                }
            }
        }
    }

    // Midhash256 requires separate O(1) read (only reads middle 1MB)
    if enabled.contains(&HashAlgorithm::Midhash256) {
        match compute_midhash256(path) {
            Ok(hash) => {
                results.insert(
                    HashAlgorithm::Midhash256.key().to_string(),
                    to_cid(&hash, HashAlgorithm::Midhash256),
                );
            }
            Err(e) => {
                tracing::warn!("Failed to compute midhash256: {}", e);
            }
        }
    }

    Ok(results)
}

/// Single-pass file hashing for all standard algorithms + BT v2 leaf collection
///
/// Returns: (standard hash results, BT v2 leaf hashes, file size)
fn hash_file_single_pass(
    path: &Path,
    enabled: &HashSet<HashAlgorithm>,
    buffer_size: usize,
    collect_bt_leaves: bool,
) -> Result<(HashMap<String, String>, Vec<[u8; 32]>, u64)> {
    let file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let mut reader = BufReader::with_capacity(buffer_size, file);
    let mut buffer = vec![0u8; buffer_size];

    // Initialize standard hashers (only if enabled)
    let mut sha256 = enabled
        .contains(&HashAlgorithm::Sha256)
        .then(Sha256::new);
    let mut sha1 = enabled.contains(&HashAlgorithm::Sha1).then(Sha1::new);
    let mut md5 = enabled.contains(&HashAlgorithm::Md5).then(Md5::new);
    let mut crc32 = enabled
        .contains(&HashAlgorithm::Crc32)
        .then(crc32fast::Hasher::new);
    let mut sha3_256 = enabled
        .contains(&HashAlgorithm::Sha3_256)
        .then(Sha3_256::new);
    let mut sha3_384 = enabled
        .contains(&HashAlgorithm::Sha3_384)
        .then(Sha3_384::new);

    // BT v2: collect leaf hashes (SHA-256 of each 16KB block)
    let mut bt_leaf_hashes: Vec<[u8; 32]> = Vec::new();
    let mut bt_block_buffer = vec![0u8; BT_BLOCK_SIZE];
    let mut bt_block_offset = 0usize;

    let mut bytes_read: u64 = 0;

    // Single read pass
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        let chunk = &buffer[..n];
        bytes_read += n as u64;

        // Update all standard hashers
        if let Some(ref mut h) = sha256 {
            h.update(chunk);
        }
        if let Some(ref mut h) = sha1 {
            h.update(chunk);
        }
        if let Some(ref mut h) = md5 {
            h.update(chunk);
        }
        if let Some(ref mut h) = crc32 {
            h.update(chunk);
        }
        if let Some(ref mut h) = sha3_256 {
            h.update(chunk);
        }
        if let Some(ref mut h) = sha3_384 {
            h.update(chunk);
        }

        // BT v2: Process chunk into 16KB blocks
        if collect_bt_leaves {
            let mut chunk_offset = 0;
            while chunk_offset < n {
                let space_in_block = BT_BLOCK_SIZE - bt_block_offset;
                let bytes_to_copy = space_in_block.min(n - chunk_offset);

                bt_block_buffer[bt_block_offset..bt_block_offset + bytes_to_copy]
                    .copy_from_slice(&chunk[chunk_offset..chunk_offset + bytes_to_copy]);

                bt_block_offset += bytes_to_copy;
                chunk_offset += bytes_to_copy;

                // Block is full, hash it
                if bt_block_offset == BT_BLOCK_SIZE {
                    let mut hasher = Sha256::new();
                    hasher.update(&bt_block_buffer);
                    bt_leaf_hashes.push(hasher.finalize().into());
                    bt_block_offset = 0;
                }
            }
        }

        // Log progress for large files (every 100MB)
        if bytes_read % (100 * 1024 * 1024) == 0 && file_size > 100 * 1024 * 1024 {
            let pct = (bytes_read as f64 / file_size as f64 * 100.0) as u32;
            tracing::debug!(
                "Hashing progress: {}% ({}/{})",
                pct,
                bytes_read,
                file_size
            );
        }
    }

    // BT v2: Handle final partial block (pad with zeros as per BEP 52)
    if collect_bt_leaves {
        if file_size == 0 {
            // Empty file: single leaf of all zeros
            bt_leaf_hashes.push([0u8; 32]);
        } else if bt_block_offset > 0 {
            // Pad remaining bytes with zeros
            bt_block_buffer[bt_block_offset..].fill(0);
            let mut hasher = Sha256::new();
            hasher.update(&bt_block_buffer);
            bt_leaf_hashes.push(hasher.finalize().into());
        }
    }

    // Finalize standard hashes and format as CIDs
    let mut results = HashMap::new();

    if let Some(h) = sha256 {
        let hash = h.finalize();
        results.insert(
            HashAlgorithm::Sha256.key().to_string(),
            to_cid(&hash, HashAlgorithm::Sha256),
        );
    }

    if let Some(h) = sha1 {
        let hash = h.finalize();
        results.insert(
            HashAlgorithm::Sha1.key().to_string(),
            to_cid(&hash, HashAlgorithm::Sha1),
        );
    }

    if let Some(h) = md5 {
        let hash = h.finalize();
        results.insert(
            HashAlgorithm::Md5.key().to_string(),
            to_cid(&hash, HashAlgorithm::Md5),
        );
    }

    if let Some(h) = crc32 {
        let hash = h.finalize().to_be_bytes();
        results.insert(
            HashAlgorithm::Crc32.key().to_string(),
            to_cid(&hash, HashAlgorithm::Crc32),
        );
    }

    if let Some(h) = sha3_256 {
        let hash = h.finalize();
        results.insert(
            HashAlgorithm::Sha3_256.key().to_string(),
            to_cid(&hash, HashAlgorithm::Sha3_256),
        );
    }

    if let Some(h) = sha3_384 {
        let hash = h.finalize();
        results.insert(
            HashAlgorithm::Sha3_384.key().to_string(),
            to_cid(&hash, HashAlgorithm::Sha3_384),
        );
    }

    Ok((results, bt_leaf_hashes, file_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_hash_file_standard() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"hello world").unwrap();
        file.flush().unwrap();

        let enabled: HashSet<_> = vec![HashAlgorithm::Sha256, HashAlgorithm::Md5]
            .into_iter()
            .collect();

        let results = hash_file(file.path(), &enabled, 1024).unwrap();

        assert!(results.contains_key("cid_sha2-256"));
        assert!(results.contains_key("cid_md5"));
        assert!(!results.contains_key("cid_sha1"));
    }

    #[test]
    fn test_hash_file_with_midhash() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"test content for midhash").unwrap();
        file.flush().unwrap();

        let enabled: HashSet<_> = vec![HashAlgorithm::Sha256, HashAlgorithm::Midhash256]
            .into_iter()
            .collect();

        let results = hash_file(file.path(), &enabled, 1024).unwrap();

        assert!(results.contains_key("cid_sha2-256"));
        assert!(results.contains_key("cid_midhash256"));
    }

    #[test]
    fn test_hash_file_with_bittorrent() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"test content for bittorrent").unwrap();
        file.flush().unwrap();

        let enabled: HashSet<_> = vec![HashAlgorithm::BtPiecesRoot, HashAlgorithm::BtInfoHash]
            .into_iter()
            .collect();

        let results = hash_file(file.path(), &enabled, 1024).unwrap();

        assert!(results.contains_key("cid_bt_pieces_root"));
        assert!(results.contains_key("cid_bt_info_hash"));
    }

    #[test]
    fn test_hash_file_all_algorithms() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"comprehensive test content").unwrap();
        file.flush().unwrap();

        let enabled: HashSet<_> = HashAlgorithm::all().into_iter().collect();

        let results = hash_file(file.path(), &enabled, 1024).unwrap();

        // All 9 algorithms should be present
        assert!(results.contains_key("cid_sha2-256"));
        assert!(results.contains_key("cid_sha1"));
        assert!(results.contains_key("cid_md5"));
        assert!(results.contains_key("cid_crc32"));
        assert!(results.contains_key("cid_sha3-256"));
        assert!(results.contains_key("cid_sha3-384"));
        assert!(results.contains_key("cid_midhash256"));
        assert!(results.contains_key("cid_bt_pieces_root"));
        assert!(results.contains_key("cid_bt_info_hash"));
    }

    #[test]
    fn test_bt_hashes_match_standalone() {
        // Verify that single-pass BT hashes match the standalone implementation
        let mut file = NamedTempFile::new().unwrap();
        // Use data larger than one BT block to test multi-block handling
        let data = vec![0xab; BT_BLOCK_SIZE * 2 + 1000];
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        // Compute via single-pass
        let enabled: HashSet<_> = vec![HashAlgorithm::BtPiecesRoot, HashAlgorithm::BtInfoHash]
            .into_iter()
            .collect();
        let single_pass_results = hash_file(file.path(), &enabled, 1024 * 1024).unwrap();

        // Compute via standalone (which still exists for comparison)
        use super::super::btih_v2::compute_btv2_hashes;
        let standalone = compute_btv2_hashes(file.path()).unwrap();
        let standalone_pieces_root = to_cid(&standalone.pieces_root, HashAlgorithm::BtPiecesRoot);
        let standalone_info_hash = to_cid(&standalone.info_hash, HashAlgorithm::BtInfoHash);

        // Results should match
        assert_eq!(
            single_pass_results.get("cid_bt_pieces_root").unwrap(),
            &standalone_pieces_root,
            "Pieces root mismatch"
        );
        assert_eq!(
            single_pass_results.get("cid_bt_info_hash").unwrap(),
            &standalone_info_hash,
            "Info hash mismatch"
        );
    }

    #[test]
    fn test_empty_file_bt() {
        let file = NamedTempFile::new().unwrap();

        let enabled: HashSet<_> = vec![HashAlgorithm::BtPiecesRoot, HashAlgorithm::BtInfoHash]
            .into_iter()
            .collect();
        let results = hash_file(file.path(), &enabled, 1024).unwrap();

        assert!(results.contains_key("cid_bt_pieces_root"));
        assert!(results.contains_key("cid_bt_info_hash"));
    }
}
