//! BitTorrent v2 Hash Computation (BEP 52)
//!
//! Computes two hashes for BitTorrent v2 compatibility:
//! - pieces_root: Merkle tree root of 16KB block hashes
//! - info_hash: SHA-256 of bencoded info dictionary
//!
//! Reference: https://www.bittorrent.org/beps/bep_0052.html

use anyhow::Result;
use bendy::encoding::{AsString, SingleItemEncoder, ToBencode};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Block size for BitTorrent v2 (16 KiB)
pub const BT_BLOCK_SIZE: usize = 16 * 1024;

/// Piece size (must be power of 2, minimum 16 KiB)
/// We use 16 KiB for maximum granularity
const PIECE_SIZE: usize = 16 * 1024;

/// Result of BitTorrent v2 hash computation
pub struct BtV2Hashes {
    /// Merkle tree root of file pieces (32 bytes)
    pub pieces_root: [u8; 32],
    /// SHA-256 of bencoded info dict (32 bytes)
    pub info_hash: [u8; 32],
}

/// Compute BitTorrent v2 hashes for a file
pub fn compute_btv2_hashes(path: &Path) -> Result<BtV2Hashes> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    let file_size = metadata.len();

    // Get filename for info dict
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Compute leaf hashes (hash of each 16KB block)
    let leaf_hashes = compute_leaf_hashes(&file, file_size)?;

    // Build merkle tree and get root
    let pieces_root = compute_merkle_root(&leaf_hashes);

    // Compute info hash
    let info_hash = compute_info_hash(&filename, file_size, &pieces_root)?;

    Ok(BtV2Hashes {
        pieces_root,
        info_hash,
    })
}

/// Compute SHA-256 hash of each 16KB block
fn compute_leaf_hashes(file: &File, file_size: u64) -> Result<Vec<[u8; 32]>> {
    if file_size == 0 {
        // Empty file: single leaf of all zeros
        return Ok(vec![[0u8; 32]]);
    }

    let mut reader = BufReader::with_capacity(BT_BLOCK_SIZE * 4, file);
    let mut buffer = vec![0u8; BT_BLOCK_SIZE];
    let mut leaf_hashes = Vec::new();

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        // Pad last block with zeros if needed (as per BEP 52)
        if bytes_read < BT_BLOCK_SIZE {
            buffer[bytes_read..].fill(0);
        }

        let mut hasher = Sha256::new();
        hasher.update(&buffer[..BT_BLOCK_SIZE]);
        let hash: [u8; 32] = hasher.finalize().into();
        leaf_hashes.push(hash);

        // If this was a partial read, we're done
        if bytes_read < BT_BLOCK_SIZE {
            break;
        }
    }

    Ok(leaf_hashes)
}

/// Compute Merkle tree root from leaf hashes
///
/// BEP 52 merkle tree:
/// - Leaves are SHA-256 hashes of 16KB blocks
/// - Internal nodes are SHA-256(left || right)
/// - Tree is padded to power of 2 with zero hashes
pub fn compute_merkle_root(leaf_hashes: &[[u8; 32]]) -> [u8; 32] {
    if leaf_hashes.is_empty() {
        return [0u8; 32];
    }

    if leaf_hashes.len() == 1 {
        return leaf_hashes[0];
    }

    // Pad to next power of 2
    let target_size = leaf_hashes.len().next_power_of_two();
    let mut current_level: Vec<[u8; 32]> = leaf_hashes.to_vec();

    // Pad with zero hashes
    while current_level.len() < target_size {
        current_level.push([0u8; 32]);
    }

    // Build tree bottom-up
    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len() / 2);

        for chunk in current_level.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);
            hasher.update(&chunk[1]);
            let hash: [u8; 32] = hasher.finalize().into();
            next_level.push(hash);
        }

        current_level = next_level;
    }

    current_level[0]
}

/// Info dictionary structure for bencoding
struct InfoDict<'a> {
    file_tree: FileTree<'a>,
    meta_version: i64,
    name: &'a str,
    piece_length: i64,
}

/// File tree structure (single file case)
struct FileTree<'a> {
    filename: &'a str,
    length: i64,
    pieces_root: &'a [u8; 32],
}

impl ToBencode for InfoDict<'_> {
    const MAX_DEPTH: usize = 5;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), bendy::encoding::Error> {
        encoder.emit_dict(|mut e| {
            // file tree (required for v2)
            e.emit_pair(b"file tree", &self.file_tree)?;
            // meta version (2 for v2-only torrents)
            e.emit_pair(b"meta version", self.meta_version)?;
            // name
            e.emit_pair(b"name", self.name)?;
            // piece length
            e.emit_pair(b"piece length", self.piece_length)?;
            Ok(())
        })
    }
}

impl ToBencode for FileTree<'_> {
    const MAX_DEPTH: usize = 4;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), bendy::encoding::Error> {
        encoder.emit_dict(|mut e| {
            // File tree is: { filename: { "": { length: N, pieces root: HASH } } }
            e.emit_pair(self.filename.as_bytes(), FileEntry {
                length: self.length,
                pieces_root: self.pieces_root,
            })?;
            Ok(())
        })
    }
}

struct FileEntry<'a> {
    length: i64,
    pieces_root: &'a [u8; 32],
}

impl ToBencode for FileEntry<'_> {
    const MAX_DEPTH: usize = 3;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), bendy::encoding::Error> {
        encoder.emit_dict(|mut e| {
            // Empty string key contains file attributes
            e.emit_pair(b"", FileAttrs {
                length: self.length,
                pieces_root: self.pieces_root,
            })?;
            Ok(())
        })
    }
}

struct FileAttrs<'a> {
    length: i64,
    pieces_root: &'a [u8; 32],
}

impl ToBencode for FileAttrs<'_> {
    const MAX_DEPTH: usize = 2;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), bendy::encoding::Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair(b"length", self.length)?;
            e.emit_pair(b"pieces root", AsString(self.pieces_root))?;
            Ok(())
        })
    }
}

/// Compute info hash (SHA-256 of bencoded info dict)
pub fn compute_info_hash(filename: &str, file_size: u64, pieces_root: &[u8; 32]) -> Result<[u8; 32]> {
    let info = InfoDict {
        file_tree: FileTree {
            filename,
            length: file_size as i64,
            pieces_root,
        },
        meta_version: 2,
        name: filename,
        piece_length: PIECE_SIZE as i64,
    };

    let encoded = info
        .to_bencode()
        .map_err(|e| anyhow::anyhow!("Failed to bencode info dict: {:?}", e))?;

    let mut hasher = Sha256::new();
    hasher.update(&encoded);
    Ok(hasher.finalize().into())
}

/// Format info hash as magnet link URN
///
/// Format: urn:btmh:1220<hex_hash>
/// Where 1220 = 0x12 (SHA-256 code) + 0x20 (32 bytes length)
pub fn format_magnet_urn(info_hash: &[u8; 32]) -> String {
    let hex = info_hash
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    format!("urn:btmh:1220{}", hex)
}

/// Format full magnet link
pub fn format_magnet_link(info_hash: &[u8; 32], filename: &str) -> String {
    let urn = format_magnet_urn(info_hash);
    let encoded_name = urlencoding_filename(filename);
    format!("magnet:?xt={}&dn={}", urn, encoded_name)
}

/// Simple URL encoding for filename (spaces and special chars)
fn urlencoding_filename(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            ' ' => "%20".to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_empty_file() {
        let file = NamedTempFile::new().unwrap();
        let hashes = compute_btv2_hashes(file.path()).unwrap();

        assert_eq!(hashes.pieces_root.len(), 32);
        assert_eq!(hashes.info_hash.len(), 32);
    }

    #[test]
    fn test_small_file() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"hello world").unwrap();
        file.flush().unwrap();

        let hashes = compute_btv2_hashes(file.path()).unwrap();

        assert_eq!(hashes.pieces_root.len(), 32);
        assert_eq!(hashes.info_hash.len(), 32);

        // Verify determinism
        let hashes2 = compute_btv2_hashes(file.path()).unwrap();
        assert_eq!(hashes.pieces_root, hashes2.pieces_root);
        assert_eq!(hashes.info_hash, hashes2.info_hash);
    }

    #[test]
    fn test_exactly_one_block() {
        let mut file = NamedTempFile::new().unwrap();
        let data = vec![0xab; BT_BLOCK_SIZE];
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        let hashes = compute_btv2_hashes(file.path()).unwrap();
        assert_eq!(hashes.pieces_root.len(), 32);
    }

    #[test]
    fn test_multiple_blocks() {
        let mut file = NamedTempFile::new().unwrap();
        // 3 full blocks + partial
        let data = vec![0xcd; BT_BLOCK_SIZE * 3 + 100];
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        let hashes = compute_btv2_hashes(file.path()).unwrap();
        assert_eq!(hashes.pieces_root.len(), 32);
        assert_eq!(hashes.info_hash.len(), 32);
    }

    #[test]
    fn test_merkle_root_single_leaf() {
        let leaf = [0xab; 32];
        let root = compute_merkle_root(&[leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_merkle_root_two_leaves() {
        let leaf1 = [0x11; 32];
        let leaf2 = [0x22; 32];

        let root = compute_merkle_root(&[leaf1, leaf2]);

        // Manually compute expected root
        let mut hasher = Sha256::new();
        hasher.update(&leaf1);
        hasher.update(&leaf2);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(root, expected);
    }

    #[test]
    fn test_magnet_urn_format() {
        let hash = [0u8; 32];
        let urn = format_magnet_urn(&hash);
        assert!(urn.starts_with("urn:btmh:1220"));
        assert_eq!(urn.len(), "urn:btmh:1220".len() + 64); // 64 hex chars
    }

    #[test]
    fn test_magnet_link_format() {
        let hash = [0xab; 32];
        let link = format_magnet_link(&hash, "test file.mkv");
        assert!(link.starts_with("magnet:?xt=urn:btmh:1220"));
        assert!(link.contains("&dn=test%20file.mkv"));
    }
}
