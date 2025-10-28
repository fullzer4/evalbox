//! Detecção de capacidades do host: user namespaces, seccomp, Landlock, cgroups v2.
//!
//! Este módulo verifica quais features de segurança estão disponíveis no sistema.

use std::fs;
use std::path::Path;

/// Relatório de capacidades do host
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

/// Verifica capacidades de segurança do host.
///
/// Retorna um relatório com todas as features disponíveis.
pub fn probe_host() -> HostReport {
    let mut report = HostReport::default();
    
    // Detect architecture
    report.arch = Some(std::env::consts::ARCH.to_string());
    
    // Detect kernel version
    report.kernel = detect_kernel_version();
    
    // Detect user namespaces
    report.userns = detect_user_namespaces();
    
    // Detect seccomp
    report.seccomp = detect_seccomp();
    
    // Detect Landlock
    let (has_landlock, abi) = detect_landlock();
    report.landlock = has_landlock;
    report.landlock_abi = abi;
    
    // Detect cgroups v2
    report.cgroups_v2 = detect_cgroups_v2();
    
    report
}

fn detect_kernel_version() -> Option<String> {
    // Read /proc/version or use uname
    if let Ok(version) = fs::read_to_string("/proc/version") {
        // Format: "Linux version 6.6.52-1-lts (linux@archlinux) ..."
        if let Some(start) = version.find("version ") {
            let rest = &version[start + 8..];
            if let Some(end) = rest.find(' ') {
                return Some(rest[..end].to_string());
            }
        }
    }
    
    // Fallback: use libc uname
    use nix::sys::utsname::uname;
    if let Ok(info) = uname() {
        return Some(info.release().to_string_lossy().to_string());
    }
    
    None
}

fn detect_user_namespaces() -> bool {
    // Check if user namespaces are enabled
    let max_ns_path = Path::new("/proc/sys/user/max_user_namespaces");
    if max_ns_path.exists() {
        if let Ok(content) = fs::read_to_string(max_ns_path) {
            if let Ok(max) = content.trim().parse::<i32>() {
                return max > 0;
            }
        }
    }
    
    // Fallback: assume available (most modern systems)
    true
}

fn detect_seccomp() -> bool {
    // Check via /proc/self/status
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        // Look for line "Seccomp: N"
        for line in status.lines() {
            if line.starts_with("Seccomp:") {
                return true;
            }
        }
    }
    
    // Modern kernels (3.5+) always have seccomp
    true
}

fn detect_landlock() -> (bool, Option<u32>) {
    // Landlock is available since kernel 5.13
    // Check by trying to create a ruleset
    
    // For now, check if kernel is >= 5.13
    if let Some(kernel) = detect_kernel_version() {
        let parts: Vec<&str> = kernel.split('.').collect();
        if parts.len() >= 2 {
            if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                if major > 5 || (major == 5 && minor >= 13) {
                    // Kernel supports Landlock, assume ABI v1 (conservative)
                    // TODO: use landlock_create_ruleset syscall to detect real ABI
                    return (true, Some(1));
                }
            }
        }
    }
    
    (false, None)
}

fn detect_cgroups_v2() -> bool {
    // Check if /sys/fs/cgroup is mounted as cgroups v2
    let cgroup_controllers = Path::new("/sys/fs/cgroup/cgroup.controllers");
    cgroup_controllers.exists()
}
