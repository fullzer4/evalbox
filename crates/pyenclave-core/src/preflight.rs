//! Checagens do host: userns, seccomp, landlock, cgroups (skeleton).

#[derive(Debug, Clone, Default)]
pub struct HostReport {
    pub userns: bool,
    pub seccomp: bool,
    pub landlock: bool,
    pub landlock_abi: Option<u32>,
    pub cgroups_v2: bool,
    pub arch: Option<String>,
    pub kernel: Option<String>,
}

pub fn probe_host() -> HostReport {
    // TODO: detectar capacidades reais (userns/unshare, seccomp, landlock ABI, cgroups)
    HostReport::default()
}
