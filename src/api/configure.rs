use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::api::process::ProcessState;
use crate::config::PluginConfig;

#[derive(Deserialize)]
pub struct ConfigureRequest {
    pub config: HashMap<String, String>,
}

#[derive(Serialize)]
pub struct ConfigureResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn configure(
    State(state): State<Arc<ProcessState>>,
    Json(req): Json<ConfigureRequest>,
) -> Json<ConfigureResponse> {
    let mut cfg = state.config.write().await;

    // Handle enabledHashes config
    if let Some(hashes) = req.config.get("enabledHashes") {
        let enabled = PluginConfig::parse_enabled_hashes(hashes);
        if enabled.is_empty() {
            return Json(ConfigureResponse {
                status: "error",
                error: Some("No valid hash algorithms specified".to_string()),
            });
        }
        cfg.enabled_hashes = enabled;
        tracing::info!("Updated enabled hashes: {:?}", cfg.enabled_hashes);
    }

    // Handle buffer size config
    if let Some(size) = req.config.get("bufferSize") {
        match size.parse::<usize>() {
            Ok(s) if s >= 4096 => {
                cfg.buffer_size = s;
                tracing::info!("Updated buffer size: {}", s);
            }
            Ok(_) => {
                return Json(ConfigureResponse {
                    status: "error",
                    error: Some("Buffer size must be at least 4096 bytes".to_string()),
                });
            }
            Err(_) => {
                return Json(ConfigureResponse {
                    status: "error",
                    error: Some("Invalid buffer size".to_string()),
                });
            }
        }
    }

    Json(ConfigureResponse {
        status: "ok",
        error: None,
    })
}
