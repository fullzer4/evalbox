//! Landlock filesystem sandboxing

use crate::{LeewardError, Result};
use std::path::PathBuf;

/// Configuration for Landlock filesystem restrictions
#[derive(Debug, Clone, Default)]
pub struct LandlockConfig {
    /// Paths with read-only access
    pub ro_paths: Vec<PathBuf>,
    /// Paths with read-write access
    pub rw_paths: Vec<PathBuf>,
    /// Paths with execute permission
    pub exec_paths: Vec<PathBuf>,
}

impl LandlockConfig {
    /// Add a read-only path
    #[must_use]
    pub fn ro(mut self, path: impl Into<PathBuf>) -> Self {
        self.ro_paths.push(path.into());
        self
    }

    /// Add a read-write path
    #[must_use]
    pub fn rw(mut self, path: impl Into<PathBuf>) -> Self {
        self.rw_paths.push(path.into());
        self
    }

    /// Add an executable path
    #[must_use]
    pub fn exec(mut self, path: impl Into<PathBuf>) -> Self {
        self.exec_paths.push(path.into());
        self
    }

    /// Apply Landlock restrictions to the current process
    pub fn apply(&self) -> Result<()> {
        // TODO: Implement using landlock crate
        tracing::debug!(
            ro = self.ro_paths.len(),
            rw = self.rw_paths.len(),
            exec = self.exec_paths.len(),
            "applying landlock rules"
        );
        Ok(())
    }
}
