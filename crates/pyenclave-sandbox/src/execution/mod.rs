//! Módulo de execução: processos, limites e telemetria.
//!
//! Gerencia a execução de comandos e coleta de métricas.

pub mod process;
pub mod limits;
pub mod telemetry;

// Re-exports principais
pub use process::{CommandSpec, execute_command};
pub use limits::{LimitConfig, apply_limits, apply_no_new_privs};
pub use telemetry::{ProcessMetrics, collect_metrics};
