use crate::config::HashAlgorithm;
use cid::Cid;
use multihash::Multihash;

/// CID codec for raw binary data
const RAW_CODEC: u64 = 0x55;

/// Maximum multihash size (64 bytes for SHA3-512)
const MAX_HASH_SIZE: usize = 64;

/// Convert raw hash bytes to proper CIDv1 format
///
/// CID structure:
/// - Version: 1
/// - Codec: 0x55 (raw binary data)
/// - Multihash: hash_code (varint) + hash_length (varint) + hash_bytes
///
/// Returns base32lower encoded CID with 'b' multibase prefix
pub fn to_cid(hash: &[u8], algo: HashAlgorithm) -> String {
    let hash_code = algo.multicodec();

    // Create multihash: wrap hash bytes with algorithm code
    let multihash: Multihash<MAX_HASH_SIZE> =
        Multihash::wrap(hash_code, hash).expect("Hash size exceeds maximum");

    // Create CIDv1 with raw codec
    let cid = Cid::new_v1(RAW_CODEC, multihash);

    // Return base32lower string (multibase 'b' prefix is default for CIDv1)
    cid.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cid_format() {
        // Test with a known SHA-256 hash
        let hash = [0u8; 32]; // 32 zero bytes
        let cid = to_cid(&hash, HashAlgorithm::Sha256);

        // CIDv1 base32lower starts with 'b'
        assert!(cid.starts_with('b'), "CID should start with 'b' multibase prefix");

        // Verify we can parse it back
        let parsed = Cid::try_from(cid.as_str()).expect("Should parse valid CID");
        assert_eq!(parsed.version(), cid::Version::V1);
        assert_eq!(parsed.codec(), RAW_CODEC);
        assert_eq!(parsed.hash().code(), 0x12); // SHA-256 code
    }

    #[test]
    fn test_all_algorithms() {
        let test_data = b"test data for hashing";

        for algo in HashAlgorithm::all() {
            // Create a fake hash of appropriate size
            let hash_size = match algo {
                HashAlgorithm::Sha256 | HashAlgorithm::Sha3_256 | HashAlgorithm::Midhash256 => 32,
                HashAlgorithm::Sha1 => 20,
                HashAlgorithm::Md5 => 16,
                HashAlgorithm::Crc32 => 4,
                HashAlgorithm::Sha3_384 => 48,
                HashAlgorithm::BtPiecesRoot | HashAlgorithm::BtInfoHash => 32,
            };

            let hash = vec![0xab; hash_size];
            let cid = to_cid(&hash, algo);

            // All CIDs should start with 'b' (base32lower)
            assert!(
                cid.starts_with('b'),
                "CID for {:?} should start with 'b'",
                algo
            );

            // All CIDs should be parseable
            let parsed = Cid::try_from(cid.as_str())
                .expect(&format!("Should parse valid CID for {:?}", algo));

            assert_eq!(parsed.version(), cid::Version::V1);
            assert_eq!(parsed.codec(), RAW_CODEC);
            assert_eq!(
                parsed.hash().code(),
                algo.multicodec(),
                "Multicodec mismatch for {:?}",
                algo
            );
        }
    }

    #[test]
    fn test_cid_determinism() {
        // Same hash should always produce same CID
        let hash = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let cid1 = to_cid(&hash, HashAlgorithm::Md5);
        let cid2 = to_cid(&hash, HashAlgorithm::Md5);
        assert_eq!(cid1, cid2);
    }

    #[test]
    fn test_different_algorithms_different_cids() {
        // Same hash bytes with different algorithms should produce different CIDs
        let hash = [0u8; 32];
        let sha256_cid = to_cid(&hash, HashAlgorithm::Sha256);
        let sha3_256_cid = to_cid(&hash, HashAlgorithm::Sha3_256);
        assert_ne!(sha256_cid, sha3_256_cid);
    }
}
