//! # pyenclave-sandbox
//!
//! Biblioteca Rust pura para sandboxing de processos Linux.
//!
//! Providencia isolamento via:
//! - **Namespaces**: user, mount, pid, ipc, uts, (optional) net
//! - **Seccomp-BPF**: Bloqueio de syscalls perigosas
//! - **Landlock**: Controle de acesso ao filesystem
//! - **rlimits**: Limites de recursos (CPU, memory, processes, etc)
//!
//! ## Exemplo de uso
//!
//! ```no_run
//! use pyenclave_sandbox::{RunSpec, Runtime};
//!
//! # fn main() -> anyhow::Result<()> {
//! let spec = RunSpec::builder()
//!     .interpreter("/usr/bin/python3".to_string())
//!     .argv(vec!["-c".to_string(), "print('hello')".to_string()])
//!     .build();
//!
//! let runtime = Runtime::new(spec)?;
//! let result = runtime.execute()?;
//!
//! println!("Exit code: {:?}", result.exit_code);
//! println!("Stdout: {}", String::from_utf8_lossy(&result.stdout));
//! # Ok(())
//! # }
//! ```
//!
//! ## Arquitetura
//!
//! A biblioteca está organizada em módulos focados:
//!
//! - `types`: Definições de tipos (RunSpec, ExecutionResult, etc)
//! - `error`: Sistema de erros (Error, Result)
//! - `probe`: Detecção de capacidades do host
//! - `isolation`: Módulos de isolamento
//!   - `namespaces`: Criação e configuração de namespaces
//!   - `filesystem`: Montagem de filesystem isolado
//!   - `security`: Aplicação de políticas (seccomp + Landlock)
//! - `execution`: Execução de processos
//!   - `process`: Fork, exec, pipes
//!   - `limits`: Aplicação de rlimits
//!   - `telemetry`: Coleta de métricas (rusage)
//! - `runtime`: Orquestrador do pipeline completo

pub mod types;
pub mod error;
pub mod probe;
pub mod isolation;
pub mod execution;
pub mod runtime;

// Re-exports para API pública conveniente
pub use types::{
    RunSpec, RunSpecBuilder, ExecutionResult, 
    InterpreterSpec, MountPlan, PolicySpec, LimitSpec
};
pub use error::{Error, Result};
pub use probe::{probe_host, HostReport};
pub use runtime::Runtime;

/// Prelude com imports comuns
pub mod prelude {
    pub use crate::{
        RunSpec, ExecutionResult, Runtime,
        Error, Result, probe_host,
    };
}
