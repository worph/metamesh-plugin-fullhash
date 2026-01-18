use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

const CACHE_VERSION: u32 = 1;
const CACHE_FILENAME: &str = "hash_cache.bin";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub filename: String,
    pub size: u64,
    pub mtime: i64,
    pub hashes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheIndex {
    pub version: u32,
    pub entries: HashMap<String, CacheEntry>,
}

impl Default for CacheIndex {
    fn default() -> Self {
        Self {
            version: CACHE_VERSION,
            entries: HashMap::new(),
        }
    }
}

impl CacheIndex {
    /// Generate cache key from file metadata
    pub fn make_key(filename: &str, size: u64, mtime: i64) -> String {
        format!("{}-{}-{}", filename, size, mtime)
    }

    /// Get cached entry if it exists and matches file metadata
    pub fn get(&self, filename: &str, size: u64, mtime: i64) -> Option<&CacheEntry> {
        let key = Self::make_key(filename, size, mtime);
        self.entries.get(&key)
    }

    /// Insert or update a cache entry
    pub fn insert(&mut self, filename: String, size: u64, mtime: i64, hashes: HashMap<String, String>) {
        let key = Self::make_key(&filename, size, mtime);
        self.entries.insert(
            key,
            CacheEntry {
                filename,
                size,
                mtime,
                hashes,
            },
        );
    }
}

pub struct CacheManager {
    cache_path: PathBuf,
    index: Arc<RwLock<CacheIndex>>,
}

impl CacheManager {
    pub fn new(cache_dir: &str) -> Self {
        let cache_path = PathBuf::from(cache_dir).join(CACHE_FILENAME);
        Self {
            cache_path,
            index: Arc::new(RwLock::new(CacheIndex::default())),
        }
    }

    /// Load cache from disk
    pub async fn load(&self) -> Result<()> {
        if !self.cache_path.exists() {
            tracing::info!("No existing cache found at {:?}", self.cache_path);
            return Ok(());
        }

        let path = self.cache_path.clone();
        let index = tokio::task::spawn_blocking(move || -> Result<CacheIndex> {
            let file = File::open(&path).context("Failed to open cache file")?;
            let reader = BufReader::new(file);
            let index: CacheIndex =
                bincode::deserialize_from(reader).context("Failed to deserialize cache")?;

            // Version check
            if index.version != CACHE_VERSION {
                tracing::warn!(
                    "Cache version mismatch (got {}, expected {}), starting fresh",
                    index.version,
                    CACHE_VERSION
                );
                return Ok(CacheIndex::default());
            }

            Ok(index)
        })
        .await??;

        tracing::info!("Loaded {} cache entries", index.entries.len());
        *self.index.write().await = index;
        Ok(())
    }

    /// Save cache to disk atomically
    pub async fn save(&self) -> Result<()> {
        let index = self.index.read().await.clone();
        let cache_path = self.cache_path.clone();

        tokio::task::spawn_blocking(move || -> Result<()> {
            // Ensure parent directory exists
            if let Some(parent) = cache_path.parent() {
                fs::create_dir_all(parent)?;
            }

            // Write to temp file first
            let temp_path = cache_path.with_extension("tmp");
            {
                let file = File::create(&temp_path)?;
                let writer = BufWriter::new(file);
                bincode::serialize_into(writer, &index)?;
            }

            // Atomic rename
            fs::rename(&temp_path, &cache_path)?;
            Ok(())
        })
        .await??;

        Ok(())
    }

    /// Get cached hashes for a file
    pub async fn get(&self, filename: &str, size: u64, mtime: i64) -> Option<HashMap<String, String>> {
        let index = self.index.read().await;
        index.get(filename, size, mtime).map(|e| e.hashes.clone())
    }

    /// Store hashes in cache
    pub async fn insert(&self, filename: String, size: u64, mtime: i64, hashes: HashMap<String, String>) {
        let mut index = self.index.write().await;
        index.insert(filename, size, mtime, hashes);
    }

    /// Get missing hash algorithms for a file (not in cache or not computed)
    pub async fn get_missing_algos(
        &self,
        filename: &str,
        size: u64,
        mtime: i64,
        required: &[&str],
    ) -> Vec<String> {
        let index = self.index.read().await;
        let cached = index.get(filename, size, mtime);

        required
            .iter()
            .filter(|algo| {
                cached
                    .map(|e| !e.hashes.contains_key(**algo))
                    .unwrap_or(true)
            })
            .map(|s| s.to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_cache_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let cache = CacheManager::new(temp_dir.path().to_str().unwrap());

        // Insert some data
        let mut hashes = HashMap::new();
        hashes.insert("cid_sha2-256".to_string(), "baejbeitest".to_string());
        cache
            .insert("test.mkv".to_string(), 1000, 12345, hashes.clone())
            .await;

        // Save and reload
        cache.save().await.unwrap();

        let cache2 = CacheManager::new(temp_dir.path().to_str().unwrap());
        cache2.load().await.unwrap();

        let result = cache2.get("test.mkv", 1000, 12345).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().get("cid_sha2-256").unwrap(), "baejbeitest");
    }
}
