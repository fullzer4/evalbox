//! Probe trait and RuntimeInfo types.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::ProbeError;

pub use evalbox_sandbox::Mount;

#[derive(Debug, Clone)]
pub struct RuntimeInfo {
    pub binary: PathBuf,
    pub mounts: Vec<Mount>,
    pub env: HashMap<String, String>,
    pub shared_libs: Vec<PathBuf>,
}

impl RuntimeInfo {
    pub fn new(binary: PathBuf) -> Self {
        Self {
            binary,
            mounts: Vec::new(),
            env: HashMap::new(),
            shared_libs: Vec::new(),
        }
    }

    pub fn mount(mut self, mount: Mount) -> Self {
        self.mounts.push(mount);
        self
    }

    pub fn mounts(mut self, mounts: impl IntoIterator<Item = Mount>) -> Self {
        self.mounts.extend(mounts);
        self
    }

    pub fn env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    pub fn shared_lib(mut self, path: PathBuf) -> Self {
        self.shared_libs.push(path);
        self
    }
}

/// Detects a runtime and determines mounts/env needed for sandbox execution.
pub trait Probe: Send + Sync {
    fn name(&self) -> &str;

    /// Find runtime binary via env vars → PATH → common locations.
    fn detect(&self) -> Option<PathBuf>;

    /// Analyze binary to determine filesystem and environment requirements.
    fn probe(&self, binary: &Path) -> Result<RuntimeInfo, ProbeError>;
}
