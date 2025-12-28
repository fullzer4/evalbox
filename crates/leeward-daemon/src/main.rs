//! leeward-daemon - Persistent sandbox daemon with worker pool

use std::path::PathBuf;
use tokio::net::UnixListener;
use tracing_subscriber::EnvFilter;
use anyhow::Result;

mod config;
mod pool;
mod protocol;
mod server;

use config::DaemonConfig;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("leeward=info".parse()?))
        .init();

    tracing::info!("leeward-daemon starting");

    // Load config
    let config = DaemonConfig::default();
    tracing::info!(
        workers = config.num_workers,
        socket = ?config.socket_path,
        "configuration loaded"
    );

    // Create socket directory if needed
    if let Some(parent) = config.socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Remove existing socket
    let _ = std::fs::remove_file(&config.socket_path);

    // Bind socket
    let listener = UnixListener::bind(&config.socket_path)?;
    tracing::info!(socket = ?config.socket_path, "listening");

    // Initialize worker pool
    let pool = pool::WorkerPool::new(config.num_workers, config.sandbox_config.clone())?;
    tracing::info!(workers = config.num_workers, "worker pool initialized");

    // Run server
    server::run(listener, pool, config).await?;

    Ok(())
}
