//! Coleta de métricas: rusage, exit reason, etc.
//!
//! TODO: Copiar implementação de pyenclave-core/src/telemetry.rs

use anyhow::{Context, Result};
use crate::types::ExecutionResult;

pub struct ProcessMetrics {
    pub cpu_time_ms: Option<u64>,
    pub peak_rss_kb: Option<u64>,
}

/// Coleta métricas de um resultado de execução
pub fn collect_metrics(_result: &ExecutionResult) -> Result<ProcessMetrics> {
    // TODO: Implementar (copiar de pyenclave-core/src/telemetry.rs)
    Ok(ProcessMetrics {
        cpu_time_ms: None,
        peak_rss_kb: None,
    })
}
