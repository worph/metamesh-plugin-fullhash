use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use crate::cache::CacheManager;
use crate::client::MetaCoreClient;
use crate::config::{HashAlgorithm, SharedConfig};
use crate::hasher::hash_file;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessRequest {
    pub task_id: String,
    pub cid: String,
    pub file_path: String,
    pub callback_url: String,
    pub meta_core_url: String,
    #[serde(default)]
    pub existing_meta: HashMap<String, String>,
}

#[derive(Serialize)]
pub struct ProcessResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallbackPayload {
    pub task_id: String,
    pub status: &'static str,
    pub duration: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

pub struct ProcessState {
    pub config: SharedConfig,
    pub cache: Arc<CacheManager>,
}

pub async fn process(
    State(state): State<Arc<ProcessState>>,
    Json(req): Json<ProcessRequest>,
) -> Json<ProcessResponse> {
    // Validate required fields
    if req.task_id.is_empty() || req.file_path.is_empty() || req.callback_url.is_empty() {
        return Json(ProcessResponse {
            status: "rejected",
            error: Some("Missing required fields".to_string()),
        });
    }

    // Spawn async processing task
    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        process_file(state_clone, req).await;
    });

    Json(ProcessResponse {
        status: "accepted",
        error: None,
    })
}

async fn process_file(state: Arc<ProcessState>, req: ProcessRequest) {
    let start = Instant::now();
    let task_id = req.task_id.clone();
    let callback_url = req.callback_url.clone();

    let result = do_process_file(state, req).await;

    let duration = start.elapsed().as_millis() as u64;

    let payload = match result {
        Ok(ProcessResult::Completed) => CallbackPayload {
            task_id,
            status: "completed",
            duration,
            error: None,
            reason: None,
        },
        Ok(ProcessResult::Skipped(reason)) => CallbackPayload {
            task_id,
            status: "skipped",
            duration,
            error: None,
            reason: Some(reason),
        },
        Err(e) => CallbackPayload {
            task_id,
            status: "failed",
            duration,
            error: Some(e.to_string()),
            reason: None,
        },
    };

    // Send callback
    if let Err(e) = send_callback(&callback_url, &payload).await {
        tracing::error!("Failed to send callback: {}", e);
    }
}

enum ProcessResult {
    Completed,
    Skipped(String),
}

async fn do_process_file(
    state: Arc<ProcessState>,
    req: ProcessRequest,
) -> anyhow::Result<ProcessResult> {
    let path = Path::new(&req.file_path);

    // Check if file exists
    if !path.exists() {
        anyhow::bail!("File not found: {}", req.file_path);
    }

    // Get file metadata
    let metadata = std::fs::metadata(path)?;
    let size = metadata.len();
    let mtime = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Get config
    let config = state.config.read().await.clone();

    // Determine which hashes we need to compute
    let required_keys: Vec<&str> = config
        .enabled_hashes
        .iter()
        .map(|a| a.key())
        .collect();

    // Check existing metadata - skip if all hashes already present
    let missing_from_meta: Vec<&str> = required_keys
        .iter()
        .filter(|k| !req.existing_meta.contains_key(**k))
        .copied()
        .collect();

    if missing_from_meta.is_empty() {
        return Ok(ProcessResult::Skipped(
            "All hashes already computed".to_string(),
        ));
    }

    // Check cache for remaining hashes
    let cached = state.cache.get(&filename, size, mtime).await;
    let mut results: HashMap<String, String> = HashMap::new();

    let to_compute: Vec<HashAlgorithm> = missing_from_meta
        .iter()
        .filter_map(|key| {
            if let Some(ref cached_hashes) = cached {
                if let Some(hash) = cached_hashes.get(*key) {
                    results.insert(key.to_string(), hash.clone());
                    return None;
                }
            }
            HashAlgorithm::from_key(key)
        })
        .collect();

    // If all hashes were in cache, we're done
    if to_compute.is_empty() {
        tracing::info!("All hashes from cache for {}", filename);
    } else {
        // Compute missing hashes
        tracing::info!(
            "Computing {} hashes for {} ({} bytes)",
            to_compute.len(),
            filename,
            size
        );

        let enabled_set = to_compute.iter().copied().collect();
        let computed = tokio::task::spawn_blocking({
            let path = path.to_path_buf();
            let buffer_size = config.buffer_size;
            move || hash_file(&path, &enabled_set, buffer_size)
        })
        .await??;

        // Merge computed hashes into results
        for (key, value) in &computed {
            results.insert(key.clone(), value.clone());
        }

        // Update cache with new hashes
        let mut all_hashes = cached.unwrap_or_default();
        all_hashes.extend(computed);
        state
            .cache
            .insert(filename.clone(), size, mtime, all_hashes)
            .await;

        // Save cache periodically (could be optimized with debouncing)
        if let Err(e) = state.cache.save().await {
            tracing::warn!("Failed to save cache: {}", e);
        }
    }

    // Store results to meta-core
    if !results.is_empty() {
        match MetaCoreClient::new(&req.meta_core_url) {
            Ok(client) => {
                if let Err(e) = client.merge_metadata(&req.cid, &results).await {
                    tracing::warn!("Failed to store metadata to meta-core: {}", e);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to create meta-core client: {}", e);
            }
        }
    }

    Ok(ProcessResult::Completed)
}

async fn send_callback(url: &str, payload: &CallbackPayload) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let resp = client.post(url).json(payload).send().await?;

    if !resp.status().is_success() {
        anyhow::bail!("Callback failed with status {}", resp.status());
    }

    Ok(())
}
