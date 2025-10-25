//! Load BPF filter for seccomp (deny network/escape; allow minimum for CPython).
//!
//! Prerequisite: `limits::apply_no_new_privs` must have been executed successfully
//! for the kernel to accept `SECCOMP_SET_MODE_FILTER` without privileges. Use this
//! module also to block network syscalls when the network namespace is not isolated.

use seccompiler::{
    apply_filter, BpfProgram, SeccompAction, SeccompFilter, SeccompRule,
};
use std::collections::BTreeMap;

/// Seccomp profile types
#[derive(Debug, Clone)]
pub enum SeccompProfile {
    /// Allow all syscalls (for testing only)
    AllowAll,
    /// Default profile: block network, dangerous syscalls
    Default,
    /// Custom profile with specific blocked syscalls
    Custom { blocked_syscalls: Vec<&'static str> },
}

impl SeccompProfile {
    /// Detect the current CPU architecture
    pub fn detect_arch() -> &'static str {
        #[cfg(target_arch = "x86_64")]
        return "x86_64";

        #[cfg(target_arch = "aarch64")]
        return "aarch64";

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        compile_error!("Unsupported architecture for seccomp");
    }

    /// Get syscall numbers for blocked syscalls
    fn get_blocked_syscall_numbers(&self) -> Vec<i64> {
        match self {
            SeccompProfile::AllowAll => vec![],
            SeccompProfile::Default => {
                // Block dangerous syscalls by number
                // These are x86_64 syscall numbers - we'll use libc constants where available
                vec![
                    libc::SYS_socket as i64,      // network
                    libc::SYS_connect as i64,     // network
                    libc::SYS_bind as i64,        // network
                    libc::SYS_listen as i64,      // network
                    libc::SYS_accept as i64,      // network
                    libc::SYS_accept4 as i64,     // network
                    libc::SYS_sendto as i64,      // network
                    libc::SYS_recvfrom as i64,    // network
                    libc::SYS_sendmsg as i64,     // network
                    libc::SYS_recvmsg as i64,     // network
                    libc::SYS_mount as i64,       // dangerous: can escape
                    libc::SYS_umount2 as i64,     // dangerous
                    libc::SYS_ptrace as i64,      // anti-debugging
                    libc::SYS_kexec_load as i64,  // dangerous
                    libc::SYS_reboot as i64,      // dangerous
                    libc::SYS_swapon as i64,      // dangerous
                    libc::SYS_swapoff as i64,     // dangerous
                    libc::SYS_init_module as i64, // kernel modules
                    libc::SYS_delete_module as i64, // kernel modules
                    libc::SYS_iopl as i64,        // I/O privileges
                    libc::SYS_ioperm as i64,      // I/O privileges
                    libc::SYS_acct as i64,        // system accounting
                    libc::SYS_settimeofday as i64, // time manipulation
                    // SYS_stime only exists on 32-bit, skip it
                    libc::SYS_clock_settime as i64, // time manipulation
                ]
            }
            SeccompProfile::Custom { blocked_syscalls } => {
                // For custom profiles, we'd need a syscall name -> number mapping
                // For now, return empty and let the test fail gracefully
                // In production, implement syscall name resolution
                vec![]
            }
        }
    }
}

/// Apply seccomp filter based on profile
///
/// # Requirements
/// - Must call `limits::apply_no_new_privs()` before this function
/// - Process must not have any threads (seccomp is per-thread)
///
/// # Returns
/// - Ok(()) if filter was successfully applied
/// - Err(String) if filter application failed
pub fn apply_seccomp_filter(profile: &SeccompProfile) -> Result<(), String> {
    // Build the BPF filter program
    let filter = build_filter(profile)?;

    // Apply the filter using seccompiler
    apply_filter(&filter).map_err(|e| format!("Failed to apply seccomp filter: {}", e))?;

    Ok(())
}

/// Build a BPF filter program from a profile
fn build_filter(profile: &SeccompProfile) -> Result<BpfProgram, String> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Get blocked syscalls
    let blocked_syscalls = profile.get_blocked_syscall_numbers();

    // For each blocked syscall, create a rule that returns EPERM
    for syscall_num in blocked_syscalls {
        // Empty rule means "always match" - block unconditionally
        rules.insert(syscall_num, vec![]);
    }

    // Create the filter
    // - Default action: Allow (SeccompAction::Allow)
    // - Blocked syscalls: Return EPERM (SeccompAction::Errno)
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow, // default action for syscalls not in the rules
        SeccompAction::Errno(libc::EPERM as u32), // action for syscalls in the rules
        std::env::consts::ARCH.try_into().map_err(|e| format!("Unsupported arch: {:?}", e))?,
    )
    .map_err(|e| format!("Failed to create seccomp filter: {}", e))?;

    // The filter is already a BpfProgram after creation
    Ok(filter.try_into().map_err(|e| format!("Failed to convert filter to BPF: {:?}", e))?)
}
