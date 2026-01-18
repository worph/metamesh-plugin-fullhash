use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RETRIES: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_millis(500);

pub struct MetaCoreClient {
    client: Client,
    base_url: String,
}

impl MetaCoreClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    /// Set a single property for a hash ID
    pub async fn set_property(&self, hash_id: &str, key: &str, value: &str) -> Result<()> {
        let url = format!("{}/api/meta/{}/{}", self.base_url, hash_id, key);

        for attempt in 1..=MAX_RETRIES {
            match self
                .client
                .put(&url)
                .json(&json!({ "value": value }))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    return Ok(());
                }
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    if attempt == MAX_RETRIES {
                        anyhow::bail!(
                            "Failed to set property {} for {}: {} - {}",
                            key,
                            hash_id,
                            status,
                            body
                        );
                    }
                    tracing::warn!(
                        "Retry {}/{} for set_property: {} - {}",
                        attempt,
                        MAX_RETRIES,
                        status,
                        body
                    );
                }
                Err(e) => {
                    if attempt == MAX_RETRIES {
                        return Err(e).context(format!(
                            "Failed to set property {} for {}",
                            key, hash_id
                        ));
                    }
                    tracing::warn!("Retry {}/{} for set_property: {}", attempt, MAX_RETRIES, e);
                }
            }
            tokio::time::sleep(RETRY_DELAY).await;
        }

        Ok(())
    }

    /// Merge multiple properties at once
    pub async fn merge_metadata(
        &self,
        hash_id: &str,
        metadata: &HashMap<String, String>,
    ) -> Result<()> {
        // Try batch endpoint first
        let url = format!("{}/api/meta/{}", self.base_url, hash_id);

        match self.client.patch(&url).json(metadata).send().await {
            Ok(resp) if resp.status().is_success() => {
                return Ok(());
            }
            Ok(resp) if resp.status().as_u16() == 404 => {
                // Batch endpoint not available, fall back to individual sets
                tracing::debug!("Batch endpoint not available, using individual sets");
            }
            Ok(resp) => {
                let status = resp.status();
                tracing::warn!("Batch merge failed with {}, falling back to individual sets", status);
            }
            Err(e) => {
                tracing::warn!("Batch merge error: {}, falling back to individual sets", e);
            }
        }

        // Fall back to individual property sets
        for (key, value) in metadata {
            self.set_property(hash_id, key, value).await?;
        }

        Ok(())
    }

    /// Health check
    pub async fn health(&self) -> Result<bool> {
        let url = format!("{}/health", self.base_url);
        match self.client.get(&url).send().await {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = MetaCoreClient::new("http://localhost:9000");
        assert!(client.is_ok());
    }

    #[test]
    fn test_url_normalization() {
        let client = MetaCoreClient::new("http://localhost:9000/").unwrap();
        assert_eq!(client.base_url, "http://localhost:9000");
    }
}
