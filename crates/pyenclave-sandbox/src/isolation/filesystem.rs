//! Isolamento de filesystem: mounts, pivot_root, /dev setup.
//!
//! TODO: Copiar implementação de pyenclave-core/src/fs.rs

use anyhow::{Context, Result};

pub struct FilesystemConfig {
    pub root_size_mb: Option<u64>,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            root_size_mb: Some(256),
        }
    }
}

/// Configura filesystem isolado
pub fn setup_filesystem(_config: &FilesystemConfig) -> Result<()> {
    // TODO: Implementar (copiar de pyenclave-core/src/fs.rs)
    anyhow::bail!("Filesystem isolation not yet implemented in pyenclave-sandbox")
}
