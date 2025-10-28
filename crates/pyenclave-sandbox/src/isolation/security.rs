//! Políticas de segurança: seccomp-BPF e Landlock.
//!
//! TODO: Copiar implementação de pyenclave-core/src/policy/*

use anyhow::{Context, Result};

pub struct SecurityConfig {
    pub seccomp_profile: Option<String>,
    pub landlock_enabled: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            seccomp_profile: Some("default".to_string()),
            landlock_enabled: true,
        }
    }
}

/// Aplica políticas de segurança (seccomp + Landlock)
pub fn apply_security(_config: &SecurityConfig) -> Result<()> {
    // TODO: Implementar (copiar de pyenclave-core/src/policy/*)
    anyhow::bail!("Security policies not yet implemented in pyenclave-sandbox")
}
