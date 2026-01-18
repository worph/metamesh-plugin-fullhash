use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use metamesh_plugin_fast_full_hash::api::{configure, health, manifest, process, ProcessState};
use metamesh_plugin_fast_full_hash::cache::CacheManager;
use metamesh_plugin_fast_full_hash::config::create_shared_config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Get configuration from environment
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let cache_path = std::env::var("CACHE_PATH").unwrap_or_else(|_| "/cache".to_string());

    // Initialize shared state
    let config = create_shared_config();
    let cache = Arc::new(CacheManager::new(&cache_path));

    // Load existing cache
    if let Err(e) = cache.load().await {
        tracing::warn!("Failed to load cache: {}", e);
    }

    // Create shared app state
    let app_state = Arc::new(ProcessState {
        config,
        cache,
    });

    // Build router
    let app = Router::new()
        .route("/health", get(health))
        .route("/manifest", get(manifest))
        .route("/configure", post(configure))
        .route("/process", post(process))
        .with_state(app_state)
        .layer(TraceLayer::new_for_http());

    // Start server
    let addr = format!("0.0.0.0:{}", port);
    tracing::info!("Starting fast-full-hash plugin on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
