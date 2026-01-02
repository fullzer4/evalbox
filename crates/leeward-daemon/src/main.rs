//! leeward-daemon - Persistent sandbox daemon with pre-forked worker pool
//!
//! Performance optimizations:
//! - Pre-forked workers with clone3 + CLONE_INTO_CGROUP
//! - io_uring for zero-copy IPC
//! - Shared memory (memfd) for results
//! - SECCOMP_USER_NOTIF for non-fatal syscall filtering

use anyhow::Result;
use tokio::net::UnixListener;
use tracing_subscriber::EnvFilter;

mod config;
mod iouring;
mod pool;
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

    // Validate Python
    let python_path = &config.sandbox_config.python_path;

    match std::process::Command::new(python_path)
        .arg("--version")
        .output()
    {
        Ok(output) => {
            let version = String::from_utf8_lossy(&output.stdout)
                .trim()
                .to_string();
            let version = if version.is_empty() {
                String::from_utf8_lossy(&output.stderr).trim().to_string()
            } else {
                version
            };
            tracing::info!(python = ?python_path, version = %version, "Python ready");
        }
        Err(e) => {
            anyhow::bail!("Python not found or not executable: {}", e);
        }
    }

    // Bind socket
    let listener = UnixListener::bind(&config.socket_path)?;
    tracing::info!(socket = ?config.socket_path, "listening");

    // Initialize worker pool
    let pool = pool::WorkerPool::new(config.num_workers, config.sandbox_config.clone())?;
    tracing::info!(workers = config.num_workers, "worker pool initialized");

    // Run server
    server::run(listener, pool, config).await.map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(())
}
