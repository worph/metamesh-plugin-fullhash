use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::HashAlgorithm;

/// Cache entry for a single file
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub filename: String,
    pub size: u64,
    pub mtime: i64,
    pub hash: String,
}

/// Per-algorithm CSV index manager
///
/// Each algorithm has its own CSV file: index-{algorithm}.csv
/// Format: path,size,mtime,hash
///
/// Uses append-only writes for efficiency (like meta-hash does)
struct AlgorithmIndex {
    file_path: PathBuf,
    /// In-memory cache: key = "filename|size|mtime", value = hash
    entries: HashMap<String, String>,
    /// Track which entries are new and need to be appended
    pending_writes: Vec<CacheEntry>,
}

impl AlgorithmIndex {
    fn new(cache_dir: &Path, algorithm: &str) -> Self {
        let file_path = cache_dir.join(format!("index-{}.csv", algorithm));
        Self {
            file_path,
            entries: HashMap::new(),
            pending_writes: Vec::new(),
        }
    }

    fn make_key(filename: &str, size: u64, mtime: i64) -> String {
        format!("{}|{}|{}", filename, size, mtime)
    }

    /// Load existing entries from CSV file
    fn load(&mut self) -> Result<()> {
        if !self.file_path.exists() {
            return Ok(());
        }

        let file = File::open(&self.file_path)
            .with_context(|| format!("Failed to open index file: {:?}", self.file_path))?;
        let reader = BufReader::new(file);

        let mut first_line = true;
        for line in reader.lines() {
            let line = line?;

            // Skip header
            if first_line {
                first_line = false;
                if line.starts_with("path,") {
                    continue;
                }
            }

            // Parse CSV line: path,size,mtime,hash
            let parts: Vec<&str> = line.splitn(4, ',').collect();
            if parts.len() == 4 {
                let filename = parts[0].to_string();
                let size: u64 = parts[1].parse().unwrap_or(0);
                let mtime: i64 = parts[2].parse().unwrap_or(0);
                let hash = parts[3].to_string();

                let key = Self::make_key(&filename, size, mtime);
                self.entries.insert(key, hash);
            }
        }

        Ok(())
    }

    /// Get cached hash for a file
    fn get(&self, filename: &str, size: u64, mtime: i64) -> Option<&String> {
        let key = Self::make_key(filename, size, mtime);
        self.entries.get(&key)
    }

    /// Add a hash to the cache (queues for append)
    fn insert(&mut self, filename: String, size: u64, mtime: i64, hash: String) {
        let key = Self::make_key(&filename, size, mtime);

        // Only queue for write if not already in cache
        if !self.entries.contains_key(&key) {
            self.pending_writes.push(CacheEntry {
                filename: filename.clone(),
                size,
                mtime,
                hash: hash.clone(),
            });
            self.entries.insert(key, hash);
        }
    }

    /// Append pending entries to CSV file
    fn flush(&mut self) -> Result<()> {
        if self.pending_writes.is_empty() {
            return Ok(());
        }

        // Ensure parent directory exists
        if let Some(parent) = self.file_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Check if file exists to determine if we need a header
        let needs_header = !self.file_path.exists() || fs::metadata(&self.file_path)?.len() == 0;

        // Open file in append mode
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)?;

        // Write header if needed
        if needs_header {
            writeln!(file, "path,size,mtime,hash")?;
        }

        // Append new entries
        for entry in &self.pending_writes {
            writeln!(file, "{},{},{},{}", entry.filename, entry.size, entry.mtime, entry.hash)?;
        }

        // Ensure data is flushed to disk
        file.flush()?;
        file.sync_all()?;

        let count = self.pending_writes.len();
        self.pending_writes.clear();

        tracing::debug!("Appended {} entries to {:?}", count, self.file_path);

        Ok(())
    }
}

/// Cache manager that handles multiple algorithm indexes
pub struct CacheManager {
    cache_dir: PathBuf,
    /// Per-algorithm indexes
    indexes: Arc<RwLock<HashMap<String, AlgorithmIndex>>>,
    /// Track which algorithms have been loaded
    loaded: Arc<RwLock<HashSet<String>>>,
}

impl CacheManager {
    pub fn new(cache_dir: &str) -> Self {
        Self {
            cache_dir: PathBuf::from(cache_dir),
            indexes: Arc::new(RwLock::new(HashMap::new())),
            loaded: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Load all indexes (called at startup)
    pub async fn load(&self) -> Result<()> {
        // Load indexes for all known algorithms
        for algo in HashAlgorithm::all() {
            self.ensure_loaded(algo.key()).await?;
        }
        Ok(())
    }

    /// Ensure a specific algorithm's index is loaded
    async fn ensure_loaded(&self, algorithm: &str) -> Result<()> {
        let mut loaded = self.loaded.write().await;
        if loaded.contains(algorithm) {
            return Ok(());
        }

        let mut indexes = self.indexes.write().await;
        let mut index = AlgorithmIndex::new(&self.cache_dir, algorithm);

        if let Err(e) = index.load() {
            tracing::warn!("Failed to load index for {}: {}", algorithm, e);
        } else {
            tracing::info!("Loaded {} entries for {}", index.entries.len(), algorithm);
        }

        indexes.insert(algorithm.to_string(), index);
        loaded.insert(algorithm.to_string());

        Ok(())
    }

    /// Get cached hashes for a file (returns all available hashes)
    pub async fn get(&self, filename: &str, size: u64, mtime: i64) -> Option<HashMap<String, String>> {
        let indexes = self.indexes.read().await;
        let mut results = HashMap::new();

        for (algo, index) in indexes.iter() {
            if let Some(hash) = index.get(filename, size, mtime) {
                results.insert(algo.clone(), hash.clone());
            }
        }

        if results.is_empty() {
            None
        } else {
            Some(results)
        }
    }

    /// Store hashes in cache (queues for append)
    pub async fn insert(&self, filename: String, size: u64, mtime: i64, hashes: HashMap<String, String>) {
        let mut indexes = self.indexes.write().await;

        for (algo, hash) in hashes {
            // Create index if it doesn't exist
            if !indexes.contains_key(&algo) {
                let mut index = AlgorithmIndex::new(&self.cache_dir, &algo);
                let _ = index.load(); // Ignore errors, will create new file
                indexes.insert(algo.clone(), index);
            }

            if let Some(index) = indexes.get_mut(&algo) {
                index.insert(filename.clone(), size, mtime, hash);
            }
        }
    }

    /// Flush all pending writes to disk (MUST be called before reporting done)
    pub async fn save(&self) -> Result<()> {
        let mut indexes = self.indexes.write().await;
        let mut total_written = 0;

        for (algo, index) in indexes.iter_mut() {
            let pending = index.pending_writes.len();
            if pending > 0 {
                index.flush().with_context(|| format!("Failed to flush index for {}", algo))?;
                total_written += pending;
            }
        }

        if total_written > 0 {
            tracing::info!("Flushed {} total cache entries to disk", total_written);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_cache_append_mode() {
        let temp_dir = TempDir::new().unwrap();
        let cache = CacheManager::new(temp_dir.path().to_str().unwrap());

        // Insert first entry
        let mut hashes1 = HashMap::new();
        hashes1.insert("cid_sha2-256".to_string(), "baejbeitest1".to_string());
        cache.insert("test1.mkv".to_string(), 1000, 12345, hashes1).await;
        cache.save().await.unwrap();

        // Insert second entry
        let mut hashes2 = HashMap::new();
        hashes2.insert("cid_sha2-256".to_string(), "baejbeitest2".to_string());
        cache.insert("test2.mkv".to_string(), 2000, 12346, hashes2).await;
        cache.save().await.unwrap();

        // Verify file contents (should have header + 2 entries)
        let csv_path = temp_dir.path().join("index-cid_sha2-256.csv");
        let content = fs::read_to_string(&csv_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();

        assert_eq!(lines.len(), 3); // header + 2 entries
        assert!(lines[0].starts_with("path,"));
        assert!(lines[1].contains("test1.mkv"));
        assert!(lines[2].contains("test2.mkv"));
    }

    #[tokio::test]
    async fn test_cache_reload() {
        let temp_dir = TempDir::new().unwrap();

        // First cache instance
        {
            let cache = CacheManager::new(temp_dir.path().to_str().unwrap());
            let mut hashes = HashMap::new();
            hashes.insert("cid_sha2-256".to_string(), "baejbeitest".to_string());
            cache.insert("test.mkv".to_string(), 1000, 12345, hashes).await;
            cache.save().await.unwrap();
        }

        // Second cache instance (reload)
        {
            let cache = CacheManager::new(temp_dir.path().to_str().unwrap());
            cache.load().await.unwrap();

            let result = cache.get("test.mkv", 1000, 12345).await;
            assert!(result.is_some());
            assert_eq!(result.unwrap().get("cid_sha2-256").unwrap(), "baejbeitest");
        }
    }

    #[tokio::test]
    async fn test_no_duplicate_writes() {
        let temp_dir = TempDir::new().unwrap();
        let cache = CacheManager::new(temp_dir.path().to_str().unwrap());

        // Insert same entry twice
        let mut hashes = HashMap::new();
        hashes.insert("cid_sha2-256".to_string(), "baejbeitest".to_string());
        cache.insert("test.mkv".to_string(), 1000, 12345, hashes.clone()).await;
        cache.insert("test.mkv".to_string(), 1000, 12345, hashes).await;
        cache.save().await.unwrap();

        // Verify only one entry in file
        let csv_path = temp_dir.path().join("index-cid_sha2-256.csv");
        let content = fs::read_to_string(&csv_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();

        assert_eq!(lines.len(), 2); // header + 1 entry
    }
}
