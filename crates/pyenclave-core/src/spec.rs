//! Internal types for RunSpec, MountPlan, PolicySpec and LimitSpec.

#[derive(Debug, Clone, Default)]
pub struct InterpreterSpec {
    pub label: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct MountPlan {
    /// Read-only mounts: vec![("host_path", "/guest_path")]
    pub ro: Vec<(String, String)>,
    /// Read-write mounts: vec![("host_path", "/guest_path")]
    pub rw: Vec<(String, String)>,
    /// Whether to create an ephemeral /tmp
    pub ephemeral_tmp: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PolicySpec {
    pub seccomp_profile: Option<String>,
    pub landlock: bool,
    pub network: bool,
}

#[derive(Debug, Clone, Default)]
pub struct LimitSpec {
    pub time_limit_s: Option<u64>,
    pub memory_limit_mb: Option<u64>,
    pub max_procs: Option<u64>,
    pub fsize_mb: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct RunSpec {
    pub interpreter: InterpreterSpec,
    pub argv: Vec<String>,
    pub mounts: MountPlan,
    pub policy: PolicySpec,
    pub limits: LimitSpec,
    pub cwd: Option<String>,
    pub umask: Option<u32>,
    /// Environment variables as K=V pairs
    pub env: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct RunResult {
    pub exit_code: Option<i32>,
    pub reason: Option<String>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub cpu_time_ms: Option<u64>,
    pub peak_rss_kb: Option<u64>,
    pub logs: Vec<String>,
}
