use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashAlgorithm {
    #[serde(rename = "cid_sha2-256")]
    Sha256,
    #[serde(rename = "cid_sha1")]
    Sha1,
    #[serde(rename = "cid_md5")]
    Md5,
    #[serde(rename = "cid_crc32")]
    Crc32,
    #[serde(rename = "cid_sha3-256")]
    Sha3_256,
    #[serde(rename = "cid_sha3-384")]
    Sha3_384,
    #[serde(rename = "cid_midhash256")]
    Midhash256,
    #[serde(rename = "cid_bt_pieces_root")]
    BtPiecesRoot,
    #[serde(rename = "cid_bt_info_hash")]
    BtInfoHash,
}

// Multicodec hash codes
// Standard codes from https://github.com/multiformats/multicodec
pub const SHA256_CODE: u64 = 0x12;
pub const SHA1_CODE: u64 = 0x11;
pub const MD5_CODE: u64 = 0xd5;
pub const CRC32_CODE: u64 = 0x0132;
pub const SHA3_256_CODE: u64 = 0x16;
pub const SHA3_384_CODE: u64 = 0x15;

// Custom hash codes
pub const MIDHASH256_CODE: u64 = 0x1000; // Custom, not in official registry

// Official BitTorrent v2 code
pub const BT_PIECES_ROOT_CODE: u64 = 0xb702; // Official bittorrent-pieces-root

// Custom BitTorrent v2 info-hash code (BEP 52), matching meta-hash's
// cid_btih_v2. The info hash is a SHA-256 of the bencoded info dict, but it
// MUST carry a distinct multihash code (not 0x12) so it can't be confused
// with the full-file sha2-256 in the bare-CID key-set — see METADATA_KEYS.md
// §2/§14.13. Consumers (meta-dup, meta-watch) disambiguate set members by
// this code.
pub const BTIH_V2_CODE: u64 = 0x10B7;

impl HashAlgorithm {
    pub fn all() -> Vec<HashAlgorithm> {
        vec![
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha1,
            HashAlgorithm::Md5,
            HashAlgorithm::Crc32,
            HashAlgorithm::Sha3_256,
            HashAlgorithm::Sha3_384,
            HashAlgorithm::Midhash256,
            HashAlgorithm::BtPiecesRoot,
            HashAlgorithm::BtInfoHash,
        ]
    }

    /// Standard algorithms that can be computed in a single I/O pass
    pub fn standard_algorithms() -> Vec<HashAlgorithm> {
        vec![
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha1,
            HashAlgorithm::Md5,
            HashAlgorithm::Crc32,
            HashAlgorithm::Sha3_256,
            HashAlgorithm::Sha3_384,
        ]
    }

    /// Special algorithms that require separate file reads
    pub fn special_algorithms() -> Vec<HashAlgorithm> {
        vec![
            HashAlgorithm::Midhash256,
            HashAlgorithm::BtPiecesRoot,
            HashAlgorithm::BtInfoHash,
        ]
    }

    /// Returns true if this algorithm requires a separate file read
    pub fn is_special(&self) -> bool {
        matches!(
            self,
            HashAlgorithm::Midhash256 | HashAlgorithm::BtPiecesRoot | HashAlgorithm::BtInfoHash
        )
    }

    pub fn key(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "cid_sha2-256",
            HashAlgorithm::Sha1 => "cid_sha1",
            HashAlgorithm::Md5 => "cid_md5",
            HashAlgorithm::Crc32 => "cid_crc32",
            HashAlgorithm::Sha3_256 => "cid_sha3-256",
            HashAlgorithm::Sha3_384 => "cid_sha3-384",
            HashAlgorithm::Midhash256 => "cid_midhash256",
            HashAlgorithm::BtPiecesRoot => "cid_bt_pieces_root",
            HashAlgorithm::BtInfoHash => "cid_bt_info_hash",
        }
    }

    pub fn from_key(key: &str) -> Option<HashAlgorithm> {
        match key {
            "cid_sha2-256" => Some(HashAlgorithm::Sha256),
            "cid_sha1" => Some(HashAlgorithm::Sha1),
            "cid_md5" => Some(HashAlgorithm::Md5),
            "cid_crc32" => Some(HashAlgorithm::Crc32),
            "cid_sha3-256" => Some(HashAlgorithm::Sha3_256),
            "cid_sha3-384" => Some(HashAlgorithm::Sha3_384),
            "cid_midhash256" => Some(HashAlgorithm::Midhash256),
            "cid_bt_pieces_root" => Some(HashAlgorithm::BtPiecesRoot),
            "cid_bt_info_hash" => Some(HashAlgorithm::BtInfoHash),
            _ => None,
        }
    }

    /// Returns the multicodec code for this hash algorithm
    pub fn multicodec(&self) -> u64 {
        match self {
            HashAlgorithm::Sha256 => SHA256_CODE,
            HashAlgorithm::Sha1 => SHA1_CODE,
            HashAlgorithm::Md5 => MD5_CODE,
            HashAlgorithm::Crc32 => CRC32_CODE,
            HashAlgorithm::Sha3_256 => SHA3_256_CODE,
            HashAlgorithm::Sha3_384 => SHA3_384_CODE,
            HashAlgorithm::Midhash256 => MIDHASH256_CODE,
            HashAlgorithm::BtPiecesRoot => BT_PIECES_ROOT_CODE,
            HashAlgorithm::BtInfoHash => BTIH_V2_CODE, // distinct from sha2-256 (§14.13)
        }
    }
}

#[derive(Debug, Clone)]
pub struct PluginConfig {
    pub enabled_hashes: HashSet<HashAlgorithm>,
    pub cache_path: String,
    pub buffer_size: usize,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled_hashes: HashAlgorithm::all().into_iter().collect(),
            cache_path: std::env::var("CACHE_PATH").unwrap_or_else(|_| "/cache".to_string()),
            buffer_size: 1024 * 1024, // 1MB
        }
    }
}

impl PluginConfig {
    pub fn parse_enabled_hashes(s: &str) -> HashSet<HashAlgorithm> {
        s.split(',')
            .filter_map(|k| HashAlgorithm::from_key(k.trim()))
            .collect()
    }
}

pub type SharedConfig = Arc<RwLock<PluginConfig>>;

pub fn create_shared_config() -> SharedConfig {
    Arc::new(RwLock::new(PluginConfig::default()))
}
