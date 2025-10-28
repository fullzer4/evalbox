//! Limites de recursos: rlimits, no_new_privs, cgroups.
//!
//! TODO: Copiar implementação de pyenclave-core/src/limits.rs

use anyhow::{Context, Result};

pub struct LimitConfig {
    pub cpu_time_seconds: Option<u64>,
    pub memory_mb: Option<u64>,
    pub max_processes: Option<u64>,
    pub max_file_size_mb: Option<u64>,
}

impl Default for LimitConfig {
    fn default() -> Self {
        Self {
            cpu_time_seconds: None,
            memory_mb: None,
            max_processes: None,
            max_file_size_mb: None,
        }
    }
}

/// Aplica PR_SET_NO_NEW_PRIVS (necessário antes de seccomp)
pub fn apply_no_new_privs() -> Result<()> {
    unsafe {
        prctl::set_no_new_privileges(true)
            .map_err(|e| anyhow::anyhow!("Failed to set no_new_privs: errno {}", e))?;
    }
    Ok(())
}

/// Aplica limites de recursos (rlimits)
pub fn apply_limits(_config: &LimitConfig) -> Result<()> {
    // TODO: Implementar (copiar de pyenclave-core/src/limits.rs)
    anyhow::bail!("Resource limits not yet implemented in pyenclave-sandbox")
}
