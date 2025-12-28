//! Error types for leeward-core

use thiserror::Error;

#[derive(Error, Debug)]
pub enum LeewardError {
    #[error("namespace error: {0}")]
    Namespace(String),

    #[error("seccomp error: {0}")]
    Seccomp(String),

    #[error("landlock error: {0}")]
    Landlock(String),

    #[error("cgroups error: {0}")]
    Cgroups(String),

    #[error("mount error: {0}")]
    Mount(String),

    #[error("execution error: {0}")]
    Execution(String),

    #[error("timeout after {0} seconds")]
    Timeout(u64),

    #[error("memory limit exceeded: {0} bytes")]
    MemoryLimitExceeded(u64),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("nix error: {0}")]
    Nix(#[from] nix::Error),

    #[error("configuration error: {0}")]
    Config(String),
}
