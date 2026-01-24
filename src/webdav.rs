use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::Stream;
use reqwest::Client;

/// WebDAV client for streaming file access
pub struct WebDavClient {
    client: Client,
    base_url: String,
}

impl WebDavClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Build full URL for a file path
    /// The input path is a filesystem path like /files/watch/movie.mkv
    /// The WebDAV server exposes /files as /webdav, so we strip /files prefix
    fn file_url(&self, path: &str) -> String {
        // Strip /files prefix since WebDAV mounts /files at the base URL
        let clean_path = path
            .trim_start_matches('/')
            .strip_prefix("files/")
            .unwrap_or(path.trim_start_matches('/'));
        format!("{}/{}", self.base_url, clean_path)
    }

    /// Stream file contents via HTTP GET
    pub async fn get_file(&self, path: &str) -> Result<WebDavReader> {
        let url = self.file_url(path);

        let response = self.client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("Failed to GET {}", url))?;

        if !response.status().is_success() {
            anyhow::bail!("WebDAV GET failed: {} for {}", response.status(), url);
        }

        let content_length = response.content_length();

        Ok(WebDavReader {
            inner: response,
            size: content_length,
        })
    }

    /// Get file size without downloading content (HEAD request)
    pub async fn get_size(&self, path: &str) -> Result<u64> {
        let url = self.file_url(path);

        let response = self.client
            .head(&url)
            .send()
            .await
            .with_context(|| format!("Failed to HEAD {}", url))?;

        if !response.status().is_success() {
            anyhow::bail!("WebDAV HEAD failed: {} for {}", response.status(), url);
        }

        response
            .content_length()
            .ok_or_else(|| anyhow::anyhow!("No Content-Length header for {}", url))
    }
}

/// Async reader wrapper for WebDAV response
pub struct WebDavReader {
    inner: reqwest::Response,
    size: Option<u64>,
}

impl WebDavReader {
    pub fn size(&self) -> Option<u64> {
        self.size
    }

    /// Read all bytes (for smaller files or when you need the whole thing)
    pub async fn bytes(self) -> Result<Vec<u8>> {
        self.inner.bytes().await
            .map(|b| b.to_vec())
            .context("Failed to read response bytes")
    }

    /// Get a stream of bytes for streaming processing
    /// This is the efficient path - data is processed as it arrives
    pub fn bytes_stream(self) -> impl Stream<Item = Result<Bytes, reqwest::Error>> {
        self.inner.bytes_stream()
    }

    /// Get the underlying response for streaming
    pub fn into_response(self) -> reqwest::Response {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_url() {
        let client = WebDavClient::new("http://localhost/webdav");
        // /files prefix should be stripped
        assert_eq!(client.file_url("/files/watch/test.mkv"), "http://localhost/webdav/watch/test.mkv");
        assert_eq!(client.file_url("files/watch/test.mkv"), "http://localhost/webdav/watch/test.mkv");

        // Trailing slash in base URL should be handled
        let client2 = WebDavClient::new("http://localhost/webdav/");
        assert_eq!(client2.file_url("/files/watch/test.mkv"), "http://localhost/webdav/watch/test.mkv");

        // Paths without /files prefix should work too
        assert_eq!(client.file_url("watch/test.mkv"), "http://localhost/webdav/watch/test.mkv");
    }
}
