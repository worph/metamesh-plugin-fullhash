use crate::config::HashAlgorithm;
use anyhow::Result;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use sha3::{Sha3_256, Sha3_384};
use std::collections::{HashMap, HashSet};

use super::btih_v2::{compute_info_hash, compute_merkle_root, BT_BLOCK_SIZE};
use super::cid::to_cid;

/// Hash data from an async byte stream
///
/// Processes chunks as they arrive from the network, maintaining O(1) memory
/// regardless of file size. All hashers are updated incrementally.
pub async fn hash_stream<S, E>(
    mut stream: S,
    filename: &str,
    file_size: Option<u64>,
    enabled: &HashSet<HashAlgorithm>,
) -> Result<HashMap<String, String>>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::error::Error + Send + Sync + 'static,
{
    let mut results = HashMap::new();

    let needs_bt = enabled.contains(&HashAlgorithm::BtPiecesRoot)
        || enabled.contains(&HashAlgorithm::BtInfoHash);
    let needs_midhash = enabled.contains(&HashAlgorithm::Midhash256);

    // Initialize standard hashers
    let mut sha256 = enabled.contains(&HashAlgorithm::Sha256).then(Sha256::new);
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

    // BT v2 state
    let mut bt_leaf_hashes: Vec<[u8; 32]> = Vec::new();
    let mut bt_block_buffer = vec![0u8; BT_BLOCK_SIZE];
    let mut bt_block_offset = 0usize;

    // Midhash256 state - we need to buffer the middle section
    // This is the one algorithm that can't be purely streaming
    const MIDHASH_SAMPLE_SIZE: usize = 1024 * 1024; // 1MB
    let mut midhash_collector: Option<MidhashCollector> = if needs_midhash {
        Some(MidhashCollector::new(file_size, MIDHASH_SAMPLE_SIZE))
    } else {
        None
    };

    let mut bytes_read: u64 = 0;
    let known_size = file_size.unwrap_or(0);

    // Process stream chunks as they arrive
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| anyhow::anyhow!("Stream error: {}", e))?;
        let chunk = chunk.as_ref();
        let chunk_start = bytes_read;
        bytes_read += chunk.len() as u64;

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
        if needs_bt {
            let mut chunk_offset = 0;
            while chunk_offset < chunk.len() {
                let space_in_block = BT_BLOCK_SIZE - bt_block_offset;
                let bytes_to_copy = space_in_block.min(chunk.len() - chunk_offset);

                bt_block_buffer[bt_block_offset..bt_block_offset + bytes_to_copy]
                    .copy_from_slice(&chunk[chunk_offset..chunk_offset + bytes_to_copy]);

                bt_block_offset += bytes_to_copy;
                chunk_offset += bytes_to_copy;

                if bt_block_offset == BT_BLOCK_SIZE {
                    let mut hasher = Sha256::new();
                    hasher.update(&bt_block_buffer);
                    bt_leaf_hashes.push(hasher.finalize().into());
                    bt_block_offset = 0;
                }
            }
        }

        // Midhash: collect the middle section
        if let Some(ref mut collector) = midhash_collector {
            collector.process_chunk(chunk, chunk_start);
        }

        // Progress logging
        if known_size > 100 * 1024 * 1024 && bytes_read % (100 * 1024 * 1024) < chunk.len() as u64 {
            let pct = (bytes_read as f64 / known_size as f64 * 100.0) as u32;
            tracing::debug!(
                "Stream hashing progress: {}% ({}/{})",
                pct,
                bytes_read,
                known_size
            );
        }
    }

    let actual_size = bytes_read;

    // Finalize BT v2
    if needs_bt {
        if actual_size == 0 {
            bt_leaf_hashes.push([0u8; 32]);
        } else if bt_block_offset > 0 {
            bt_block_buffer[bt_block_offset..].fill(0);
            let mut hasher = Sha256::new();
            hasher.update(&bt_block_buffer);
            bt_leaf_hashes.push(hasher.finalize().into());
        }

        let pieces_root = compute_merkle_root(&bt_leaf_hashes);

        if enabled.contains(&HashAlgorithm::BtPiecesRoot) {
            results.insert(
                HashAlgorithm::BtPiecesRoot.key().to_string(),
                to_cid(&pieces_root, HashAlgorithm::BtPiecesRoot),
            );
        }

        if enabled.contains(&HashAlgorithm::BtInfoHash) {
            if let Ok(info_hash) = compute_info_hash(filename, actual_size, &pieces_root) {
                results.insert(
                    HashAlgorithm::BtInfoHash.key().to_string(),
                    to_cid(&info_hash, HashAlgorithm::BtInfoHash),
                );
            }
        }
    }

    // Finalize midhash256
    if let Some(collector) = midhash_collector {
        let hash = collector.finalize(actual_size);
        results.insert(
            HashAlgorithm::Midhash256.key().to_string(),
            to_cid(&hash, HashAlgorithm::Midhash256),
        );
    }

    // Finalize standard hashes
    if let Some(h) = sha256 {
        results.insert(
            HashAlgorithm::Sha256.key().to_string(),
            to_cid(&h.finalize(), HashAlgorithm::Sha256),
        );
    }
    if let Some(h) = sha1 {
        results.insert(
            HashAlgorithm::Sha1.key().to_string(),
            to_cid(&h.finalize(), HashAlgorithm::Sha1),
        );
    }
    if let Some(h) = md5 {
        results.insert(
            HashAlgorithm::Md5.key().to_string(),
            to_cid(&h.finalize(), HashAlgorithm::Md5),
        );
    }
    if let Some(h) = crc32 {
        results.insert(
            HashAlgorithm::Crc32.key().to_string(),
            to_cid(&h.finalize().to_be_bytes(), HashAlgorithm::Crc32),
        );
    }
    if let Some(h) = sha3_256 {
        results.insert(
            HashAlgorithm::Sha3_256.key().to_string(),
            to_cid(&h.finalize(), HashAlgorithm::Sha3_256),
        );
    }
    if let Some(h) = sha3_384 {
        results.insert(
            HashAlgorithm::Sha3_384.key().to_string(),
            to_cid(&h.finalize(), HashAlgorithm::Sha3_384),
        );
    }

    Ok(results)
}

/// Collects the middle section of a file for midhash256
///
/// If file size is known upfront, only buffers the exact middle 1MB.
/// If unknown, buffers more conservatively and extracts middle at the end.
struct MidhashCollector {
    /// Sample size (1MB)
    sample_size: usize,
    /// Buffered data for middle section
    buffer: Vec<u8>,
    /// Start offset of middle section (calculated from known size)
    middle_start: Option<u64>,
    /// Have we finished collecting?
    done: bool,
}

impl MidhashCollector {
    fn new(known_size: Option<u64>, sample_size: usize) -> Self {
        let middle_start = known_size.and_then(|size| {
            if (size as usize) <= sample_size {
                None // Small file, collect everything
            } else {
                Some((size - sample_size as u64) / 2)
            }
        });

        // Pre-allocate based on whether we know the size
        let capacity = if known_size.is_some() {
            sample_size
        } else {
            // Unknown size - we'll need to buffer everything
            // Start with a reasonable default
            sample_size * 2
        };

        Self {
            sample_size,
            buffer: Vec::with_capacity(capacity),
            middle_start,
            done: false,
        }
    }

    fn process_chunk(&mut self, chunk: &[u8], chunk_start: u64) {
        if self.done {
            return;
        }

        match self.middle_start {
            Some(middle_start) => {
                // We know the file size - only collect the middle section
                let middle_end = middle_start + self.sample_size as u64;
                let chunk_end = chunk_start + chunk.len() as u64;

                // Check if this chunk overlaps with our target range
                if chunk_end <= middle_start || chunk_start >= middle_end {
                    return; // No overlap
                }

                // Calculate overlap within the chunk
                let copy_start = if chunk_start < middle_start {
                    (middle_start - chunk_start) as usize
                } else {
                    0
                };
                let copy_end = if chunk_end > middle_end {
                    chunk.len() - (chunk_end - middle_end) as usize
                } else {
                    chunk.len()
                };

                if copy_start < chunk.len() && copy_end > copy_start {
                    self.buffer.extend_from_slice(&chunk[copy_start..copy_end]);
                }

                if self.buffer.len() >= self.sample_size {
                    self.done = true;
                }
            }
            None => {
                // Unknown size or small file - collect everything
                // We'll extract the middle at the end
                self.buffer.extend_from_slice(chunk);
            }
        }
    }

    fn finalize(self, actual_size: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(actual_size.to_le_bytes());

        if (actual_size as usize) <= self.sample_size {
            // Small file: hash entire content
            hasher.update(&self.buffer);
        } else if self.middle_start.is_some() {
            // We collected exactly the middle
            hasher.update(&self.buffer);
        } else {
            // We collected everything, extract middle now
            let middle_start = (self.buffer.len() - self.sample_size) / 2;
            hasher.update(&self.buffer[middle_start..middle_start + self.sample_size]);
        }

        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;

    #[tokio::test]
    async fn test_hash_stream_basic() {
        let data = b"hello world";
        let chunks: Vec<Result<Bytes, std::io::Error>> =
            vec![Ok(Bytes::from_static(data))];
        let stream = stream::iter(chunks);

        let enabled: HashSet<_> = vec![HashAlgorithm::Sha256, HashAlgorithm::Md5]
            .into_iter()
            .collect();

        let results = hash_stream(stream, "test.txt", Some(data.len() as u64), &enabled)
            .await
            .unwrap();

        assert!(results.contains_key("cid_sha2-256"));
        assert!(results.contains_key("cid_md5"));
    }

    #[tokio::test]
    async fn test_hash_stream_chunked() {
        // Split "hello world" into multiple chunks
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from_static(b"hello")),
            Ok(Bytes::from_static(b" ")),
            Ok(Bytes::from_static(b"world")),
        ];
        let stream = stream::iter(chunks);

        let enabled: HashSet<_> = vec![HashAlgorithm::Sha256].into_iter().collect();

        let results = hash_stream(stream, "test.txt", Some(11), &enabled)
            .await
            .unwrap();

        // Single chunk version
        let single_chunks: Vec<Result<Bytes, std::io::Error>> =
            vec![Ok(Bytes::from_static(b"hello world"))];
        let single_stream = stream::iter(single_chunks);

        let single_results = hash_stream(single_stream, "test.txt", Some(11), &enabled)
            .await
            .unwrap();

        // Results should match regardless of chunking
        assert_eq!(
            results.get("cid_sha2-256"),
            single_results.get("cid_sha2-256")
        );
    }

    #[tokio::test]
    async fn test_hash_stream_empty() {
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![];
        let stream = stream::iter(chunks);

        let enabled: HashSet<_> = vec![HashAlgorithm::Sha256, HashAlgorithm::BtPiecesRoot]
            .into_iter()
            .collect();

        let results = hash_stream(stream, "empty.txt", Some(0), &enabled)
            .await
            .unwrap();

        assert!(results.contains_key("cid_sha2-256"));
        assert!(results.contains_key("cid_bt_pieces_root"));
    }
}
