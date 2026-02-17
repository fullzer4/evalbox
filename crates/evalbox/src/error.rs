//! Error types for evalbox.

use std::path::PathBuf;
use thiserror::Error;

/// Main error type for evalbox operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("sandbox: {0}")]
    Sandbox(String),

    #[error("validation: {0}")]
    Validation(String),

    #[error("invalid config: {0}")]
    InvalidConfig(String),

    #[error("system requirements: {0}")]
    SystemRequirements(String),

    #[error("compilation failed:\n{stderr}")]
    Compilation {
        stderr: String,
        exit_code: Option<i32>,
    },

    #[error("runtime not found: {runtime}\n  searched:\n{searched}")]
    RuntimeNotFound { runtime: String, searched: String },

    #[error("probe error: {0}")]
    Probe(#[from] ProbeError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<evalbox_sandbox::ExecutorError> for Error {
    fn from(e: evalbox_sandbox::ExecutorError) -> Self {
        Self::Sandbox(e.to_string())
    }
}

impl From<evalbox_sandbox::ResolveError> for Error {
    fn from(e: evalbox_sandbox::ResolveError) -> Self {
        Self::Validation(e.to_string())
    }
}

/// Result type for evalbox operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for runtime probing operations.
#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("runtime not found: {runtime}\n  searched:\n{searched}")]
    NotFound { runtime: String, searched: String },

    #[error("probe script failed: {0}")]
    ProbeScriptFailed(String),

    #[error("failed to parse probe output: {0}")]
    ParseError(String),

    #[error("ELF parsing error for {path}: {message}")]
    ElfError { path: PathBuf, message: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("binary is not executable: {0}")]
    NotExecutable(PathBuf),
}
