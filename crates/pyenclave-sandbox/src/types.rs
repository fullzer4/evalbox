//! Tipos principais da sandbox: RunSpec, ExecutionResult, etc.
//!
//! Define as estruturas de configuração e resultado de execução.

use std::collections::HashMap;
use std::path::PathBuf;

/// Especificação completa de uma execução na sandbox.
#[derive(Debug, Clone, Default)]
pub struct RunSpec {
    pub interpreter: InterpreterSpec,
    pub argv: Vec<String>,
    pub mounts: MountPlan,
    pub policy: PolicySpec,
    pub limits: LimitSpec,
    pub cwd: Option<String>,
    pub umask: Option<u32>,
    pub env: HashMap<String, String>,
}

impl RunSpec {
    /// Cria um builder para construir RunSpec
    pub fn builder() -> RunSpecBuilder {
        RunSpecBuilder::default()
    }
    
    /// Valida a especificação
    pub fn validate(&self) -> Result<(), String> {
        if self.argv.is_empty() {
            return Err("argv cannot be empty".to_string());
        }
        
        if self.interpreter.path.is_none() && self.interpreter.label.is_none() {
            return Err("interpreter must have either path or label".to_string());
        }
        
        Ok(())
    }
}

/// Builder para RunSpec
#[derive(Debug, Clone, Default)]
pub struct RunSpecBuilder {
    spec: RunSpec,
}

impl RunSpecBuilder {
    pub fn interpreter(mut self, path: String) -> Self {
        self.spec.interpreter.path = Some(path);
        self
    }
    
    pub fn argv(mut self, argv: Vec<String>) -> Self {
        self.spec.argv = argv;
        self
    }
    
    pub fn mounts(mut self, mounts: MountPlan) -> Self {
        self.spec.mounts = mounts;
        self
    }
    
    pub fn policy(mut self, policy: PolicySpec) -> Self {
        self.spec.policy = policy;
        self
    }
    
    pub fn limits(mut self, limits: LimitSpec) -> Self {
        self.spec.limits = limits;
        self
    }
    
    pub fn env(mut self, env: HashMap<String, String>) -> Self {
        self.spec.env = env;
        self
    }
    
    pub fn cwd(mut self, cwd: String) -> Self {
        self.spec.cwd = Some(cwd);
        self
    }
    
    pub fn build(self) -> RunSpec {
        self.spec
    }
}

/// Especificação do interpretador Python
#[derive(Debug, Clone, Default)]
pub struct InterpreterSpec {
    pub label: Option<String>,  // Ex: "3.12"
    pub path: Option<String>,   // Ex: "/usr/bin/python3.12"
}

/// Plano de montagem de filesystem
#[derive(Debug, Clone, Default)]
pub struct MountPlan {
    /// Mounts read-only: (source, target)
    pub ro: Vec<(String, String)>,
    /// Mounts read-write: (source, target)
    pub rw: Vec<(String, String)>,
    /// Criar /tmp efêmero
    pub ephemeral_tmp: bool,
}

/// Política de segurança
#[derive(Debug, Clone, Default)]
pub struct PolicySpec {
    pub seccomp_profile: Option<String>,
    pub landlock: bool,
    pub network: bool,
}

/// Limites de recursos
#[derive(Debug, Clone, Default)]
pub struct LimitSpec {
    pub time_limit_s: Option<u64>,
    pub memory_limit_mb: Option<u64>,
    pub max_procs: Option<u64>,
    pub fsize_mb: Option<u64>,
}

/// Resultado da execução
#[derive(Debug, Clone, Default)]
pub struct ExecutionResult {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub signal: Option<i32>,
    pub cpu_time_ms: Option<u64>,
    pub peak_rss_kb: Option<u64>,
    pub reason: Option<String>,
}

impl ExecutionResult {
    /// Adiciona métricas ao resultado
    pub fn with_metrics(mut self, cpu_time_ms: Option<u64>, peak_rss_kb: Option<u64>) -> Self {
        self.cpu_time_ms = cpu_time_ms;
        self.peak_rss_kb = peak_rss_kb;
        self
    }
}

/// Razão da terminação do processo
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    Success,
    Failed,
    Signal,
    Timeout,
    OutOfMemory,
    Unknown,
}

impl ExitReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExitReason::Success => "ok",
            ExitReason::Failed => "failed",
            ExitReason::Signal => "signal",
            ExitReason::Timeout => "timeout",
            ExitReason::OutOfMemory => "oom",
            ExitReason::Unknown => "unknown",
        }
    }
}
