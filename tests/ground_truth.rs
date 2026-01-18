//! Ground Truth Integration Tests
//!
//! These tests verify our hash implementations against known-good values
//! computed using standard third-party tools (sha256sum, sha1sum, md5sum, Python hashlib).
//!
//! Reference file: Sintel trailer (480p) - Creative Commons licensed
//! Source: https://download.blender.org/durian/trailer/sintel_trailer-480p.mp4
//!
//! To regenerate ground truth values, run:
//!   cd testdata && ./compute_ground_truth.sh

use metamesh_plugin_fast_full_hash::config::HashAlgorithm;
use metamesh_plugin_fast_full_hash::hasher::hash_file;
use std::collections::HashSet;
use std::path::Path;

/// Reference file details
const REFERENCE_FILE: &str = "testdata/sintel_trailer-480p.mp4";
const REFERENCE_SIZE: u64 = 4372373;

/// Ground truth hash values (hex strings)
/// Computed using standard Unix tools and Python hashlib
mod expected {
    pub const SHA256: &str = "b670602fa00934ca27c4351bb0efe7ea7a07fae57284e44226025eeed7c51254";
    pub const SHA1: &str = "9b678890fb8ca401c28e7ca09171ec008a154b97";
    pub const MD5: &str = "df6ed4bbc93613c68c8525e21bbddf98";
    pub const CRC32: &str = "61accd5e";
    pub const SHA3_256: &str = "fefc0c74ebd79a9872464ebbb35a0545db97431a6c9a96d36c061244883e9213";
    pub const SHA3_384: &str = "da29f6604c96d09332531a4a2f4881b7bd2401a995053db868d5aea4056ada0b45c0ba69016e931bc468c38788afad94";
    pub const MIDHASH256: &str = "297a6662a49c60da0cf2a75407a0eb0045a36f838d2921ab602483b708157773";
    pub const BT_PIECES_ROOT: &str =
        "424febb4268900457464928a99547dacd07d2075cbbd7ae27fdf5c8d2d982817";
    pub const BT_INFO_HASH: &str =
        "e2f048c0c8bb56c910c05b9efb4f39d2ff6fd0cf01e96e1dacecb56a067f8418";
}

/// Convert hex string to bytes
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Extract raw hash from CID (parse the CID and get the hash bytes)
fn extract_hash_from_cid(cid_str: &str) -> Vec<u8> {
    use cid::Cid;
    let cid = Cid::try_from(cid_str).expect("Invalid CID");
    cid.hash().digest().to_vec()
}

/// Check if reference file exists, skip test if not
fn check_reference_file() -> Option<&'static Path> {
    let path = Path::new(REFERENCE_FILE);
    if !path.exists() {
        eprintln!(
            "Skipping ground truth test: reference file not found at {}",
            REFERENCE_FILE
        );
        eprintln!("To download, run: cd testdata && ./compute_ground_truth.sh");
        return None;
    }

    // Verify file size
    let metadata = std::fs::metadata(path).expect("Failed to read file metadata");
    if metadata.len() != REFERENCE_SIZE {
        eprintln!(
            "WARNING: Reference file size mismatch. Expected {}, got {}",
            REFERENCE_SIZE,
            metadata.len()
        );
        eprintln!("Ground truth values may not match. Re-run compute_ground_truth.sh");
    }

    Some(path)
}

#[test]
fn test_sha256_ground_truth() {
    let Some(path) = check_reference_file() else {
        return;
    };

    let enabled: HashSet<_> = vec![HashAlgorithm::Sha256].into_iter().collect();
    let results = hash_file(path, &enabled, 1024 * 1024).expect("Hashing failed");

    let cid = results.get("cid_sha2-256").expect("SHA-256 not computed");
    let hash_bytes = extract_hash_from_cid(cid);
    let expected_bytes = hex_to_bytes(expected::SHA256);

    assert_eq!(
        hash_bytes, expected_bytes,
        "SHA-256 mismatch!\nExpected: {}\nGot: {}",
        expected::SHA256,
        hex::encode(&hash_bytes)
    );
}

#[test]
fn test_sha1_ground_truth() {
    let Some(path) = check_reference_file() else {
        return;
    };

    let enabled: HashSet<_> = vec![HashAlgorithm::Sha1].into_iter().collect();
    let results = hash_file(path, &enabled, 1024 * 1024).expect("Hashing failed");

    let cid = results.get("cid_sha1").expect("SHA-1 not computed");
    let hash_bytes = extract_hash_from_cid(cid);
    let expected_bytes = hex_to_bytes(expected::SHA1);

    assert_eq!(
        hash_bytes, expected_bytes,
        "SHA-1 mismatch!\nExpected: {}\nGot: {}",
        expected::SHA1,
        hex::encode(&hash_bytes)
    );
}

#[test]
fn test_md5_ground_truth() {
    let Some(path) = check_reference_file() else {
        return;
    };

    let enabled: HashSet<_> = vec![HashAlgorithm::Md5].into_iter().collect();
    let results = hash_file(path, &enabled, 1024 * 1024).expect("Hashing failed");

    let cid = results.get("cid_md5").expect("MD5 not computed");
    let hash_bytes = extract_hash_from_cid(cid);
    let expected_bytes = hex_to_bytes(expected::MD5);

    assert_eq!(
        hash_bytes, expected_bytes,
        "MD5 mismatch!\nExpected: {}\nGot: {}",
        expected::MD5,
        hex::encode(&hash_bytes)
    );
}

#[test]
fn test_crc32_ground_truth() {
    let Some(path) = check_reference_file() else {
        return;
    };

    let enabled: HashSet<_> = vec![HashAlgorithm::Crc32].into_iter().collect();
    let results = hash_file(path, &enabled, 1024 * 1024).expect("Hashing failed");

    let cid = results.get("cid_crc32").expect("CRC32 not computed");
    let hash_bytes = extract_hash_from_cid(cid);
    let expected_bytes = hex_to_bytes(expected::CRC32);

    assert_eq!(
        hash_bytes, expected_bytes,
        "CRC32 mismatch!\nExpected: {}\nGot: {}",
        expected::CRC32,
        hex::encode(&hash_bytes)
    );
}

#[test]
fn test_sha3_256_ground_truth() {
    let Some(path) = check_reference_file() else {
        return;
    };

    let enabled: HashSet<_> = vec![HashAlgorithm::Sha3_256].into_iter().collect();
    let results = hash_file(path, &enabled, 1024 * 1024).expect("Hashing failed");

    let cid = results.get("cid_sha3-256").expect("SHA3-256 not computed");
    let hash_bytes = extract_hash_from_cid(cid);
    let expected_bytes = hex_to_bytes(expected::SHA3_256);

    assert_eq!(
        hash_bytes, expected_bytes,
        "SHA3-256 mismatch!\nExpected: {}\nGot: {}",
        expected::SHA3_256,
        hex::encode(&hash_bytes)
    );
}

#[test]
fn test_sha3_384_ground_truth() {
    let Some(path) = check_reference_file() else {
        return;
    };

    let enabled: HashSet<_> = vec![HashAlgorithm::Sha3_384].into_iter().collect();
    let results = hash_file(path, &enabled, 1024 * 1024).expect("Hashing failed");

    let cid = results.get("cid_sha3-384").expect("SHA3-384 not computed");
    let hash_bytes = extract_hash_from_cid(cid);
    let expected_bytes = hex_to_bytes(expected::SHA3_384);

    assert_eq!(
        hash_bytes, expected_bytes,
        "SHA3-384 mismatch!\nExpected: {}\nGot: {}",
        expected::SHA3_384,
        hex::encode(&hash_bytes)
    );
}

#[test]
fn test_midhash256_ground_truth() {
    let Some(path) = check_reference_file() else {
        return;
    };

    let enabled: HashSet<_> = vec![HashAlgorithm::Midhash256].into_iter().collect();
    let results = hash_file(path, &enabled, 1024 * 1024).expect("Hashing failed");

    let cid = results
        .get("cid_midhash256")
        .expect("MidHash256 not computed");
    let hash_bytes = extract_hash_from_cid(cid);
    let expected_bytes = hex_to_bytes(expected::MIDHASH256);

    assert_eq!(
        hash_bytes, expected_bytes,
        "MidHash256 mismatch!\nExpected: {}\nGot: {}",
        expected::MIDHASH256,
        hex::encode(&hash_bytes)
    );
}

#[test]
fn test_bt_pieces_root_ground_truth() {
    let Some(path) = check_reference_file() else {
        return;
    };

    let enabled: HashSet<_> = vec![HashAlgorithm::BtPiecesRoot].into_iter().collect();
    let results = hash_file(path, &enabled, 1024 * 1024).expect("Hashing failed");

    let cid = results
        .get("cid_bt_pieces_root")
        .expect("BT Pieces Root not computed");
    let hash_bytes = extract_hash_from_cid(cid);
    let expected_bytes = hex_to_bytes(expected::BT_PIECES_ROOT);

    assert_eq!(
        hash_bytes, expected_bytes,
        "BT Pieces Root mismatch!\nExpected: {}\nGot: {}",
        expected::BT_PIECES_ROOT,
        hex::encode(&hash_bytes)
    );
}

#[test]
fn test_bt_info_hash_ground_truth() {
    let Some(path) = check_reference_file() else {
        return;
    };

    let enabled: HashSet<_> = vec![HashAlgorithm::BtInfoHash].into_iter().collect();
    let results = hash_file(path, &enabled, 1024 * 1024).expect("Hashing failed");

    let cid = results
        .get("cid_bt_info_hash")
        .expect("BT Info Hash not computed");
    let hash_bytes = extract_hash_from_cid(cid);
    let expected_bytes = hex_to_bytes(expected::BT_INFO_HASH);

    assert_eq!(
        hash_bytes, expected_bytes,
        "BT Info Hash mismatch!\nExpected: {}\nGot: {}",
        expected::BT_INFO_HASH,
        hex::encode(&hash_bytes)
    );
}

#[test]
fn test_all_algorithms_ground_truth() {
    let Some(path) = check_reference_file() else {
        return;
    };

    // Compute all algorithms in single pass
    let enabled: HashSet<_> = HashAlgorithm::all().into_iter().collect();
    let results = hash_file(path, &enabled, 1024 * 1024).expect("Hashing failed");

    // Verify all 9 algorithms
    let test_cases = vec![
        ("cid_sha2-256", expected::SHA256, "SHA-256"),
        ("cid_sha1", expected::SHA1, "SHA-1"),
        ("cid_md5", expected::MD5, "MD5"),
        ("cid_crc32", expected::CRC32, "CRC32"),
        ("cid_sha3-256", expected::SHA3_256, "SHA3-256"),
        ("cid_sha3-384", expected::SHA3_384, "SHA3-384"),
        ("cid_midhash256", expected::MIDHASH256, "MidHash256"),
        (
            "cid_bt_pieces_root",
            expected::BT_PIECES_ROOT,
            "BT Pieces Root",
        ),
        ("cid_bt_info_hash", expected::BT_INFO_HASH, "BT Info Hash"),
    ];

    let mut failures = Vec::new();

    for (key, expected_hex, name) in test_cases {
        let cid = match results.get(key) {
            Some(c) => c,
            None => {
                failures.push(format!("{}: NOT COMPUTED", name));
                continue;
            }
        };

        let hash_bytes = extract_hash_from_cid(cid);
        let expected_bytes = hex_to_bytes(expected_hex);

        if hash_bytes != expected_bytes {
            failures.push(format!(
                "{}: MISMATCH\n  Expected: {}\n  Got: {}",
                name,
                expected_hex,
                hex::encode(&hash_bytes)
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "Ground truth verification failed:\n{}",
            failures.join("\n\n")
        );
    }
}
