use axum::Json;
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Serialize)]
pub struct ManifestResponse {
    pub id: &'static str,
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
    pub author: &'static str,
    pub dependencies: Vec<String>,
    pub priority: u32,
    pub color: &'static str,
    #[serde(rename = "defaultQueue")]
    pub default_queue: &'static str,
    pub timeout: u64,
    pub schema: Value,
    pub config: Value,
}

pub async fn manifest() -> Json<ManifestResponse> {
    Json(ManifestResponse {
        id: "full-hash",
        name: "Full File Hash",
        version: env!("CARGO_PKG_VERSION"),
        description: "High-performance parallel hashing with optimized I/O",
        author: "MetaMesh",
        dependencies: vec![],
        priority: 100,
        color: "#FF5722",
        default_queue: "background",
        timeout: 300000,
        schema: json!({
            "cid_sha2-256": {
                "label": "SHA-256 Hash",
                "type": "cid",
                "readonly": true,
                "hint": "SHA-256 hash in CID format (multicodec 0x12)"
            },
            "cid_sha1": {
                "label": "SHA-1 Hash",
                "type": "cid",
                "readonly": true,
                "hint": "SHA-1 hash in CID format (multicodec 0x11)"
            },
            "cid_md5": {
                "label": "MD5 Hash",
                "type": "cid",
                "readonly": true,
                "hint": "MD5 hash in CID format (multicodec 0xd5)"
            },
            "cid_crc32": {
                "label": "CRC32 Checksum",
                "type": "cid",
                "readonly": true,
                "hint": "CRC32 checksum in CID format (multicodec 0x0132)"
            },
            "cid_sha3-256": {
                "label": "SHA3-256 Hash",
                "type": "cid",
                "readonly": true,
                "hint": "SHA3-256 hash in CID format (multicodec 0x16)"
            },
            "cid_sha3-384": {
                "label": "SHA3-384 Hash",
                "type": "cid",
                "readonly": true,
                "hint": "SHA3-384 hash in CID format (multicodec 0x15)"
            },
            "cid_midhash256": {
                "label": "MidHash256",
                "type": "cid",
                "readonly": true,
                "hint": "O(1) file identification hash - SHA-256 of size + middle 1MB (custom multicodec 0x1000)"
            },
            "cid_bt_pieces_root": {
                "label": "BitTorrent v2 Pieces Root",
                "type": "cid",
                "readonly": true,
                "hint": "Merkle tree root of 16KB blocks (official multicodec 0xb702)"
            },
            "cid_bt_info_hash": {
                "label": "BitTorrent v2 Info Hash",
                "type": "cid",
                "readonly": true,
                "hint": "BitTorrent v2 info hash: SHA-256 of bencoded info dict (btih-v2 multicodec 0x10B7)"
            }
        }),
        config: json!({
            "enabledHashes": {
                "type": "string",
                "label": "Enabled hash algorithms (comma-separated)",
                // These keys select WHICH digests to compute — they are an
                // internal algorithm-selection vocabulary, NOT record field
                // names. Results are stored on the record as a bare-CID
                // key-set (cids/<cid> = "true"); the algorithm is recovered
                // from each CID's multicodec, never a field name. The
                // pieces-root is computed but not stored as a file-identity
                // member (METADATA_KEYS.md §14.13).
                "default": "cid_sha2-256,cid_sha1,cid_md5,cid_crc32,cid_sha3-256,cid_sha3-384,cid_midhash256,cid_bt_pieces_root,cid_bt_info_hash",
                "required": false
            }
        }),
    })
}
