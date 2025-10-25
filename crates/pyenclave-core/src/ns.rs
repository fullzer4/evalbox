//! Namespace creation (user, mount, pid, ipc, uts, net) and /proc.
//!
//! When creating a PID namespace, it's mandatory to mount a new `/proc` inside
//! the enclave (after `pivot_root`) for tools to work correctly.

use nix::sched::{unshare, CloneFlags};
use std::fs::{self, OpenOptions};
use std::io::Write;

#[derive(Debug)]
pub struct NsHandle {
    pub user: bool,
    pub mount: bool,
    pub pid: bool,
    pub ipc: bool,
    pub uts: bool,
    pub net: bool,
}

#[derive(Debug, Clone)]
pub struct UserNamespaceConfig {
    /// UID mapping: (host_uid, namespace_uid, count)
    /// Example: (1000, 0, 1) → host UID 1000 appears as UID 0 in namespace
    pub uid_map: Option<(u32, u32, u32)>,
    
    /// GID mapping: (host_gid, namespace_gid, count)
    pub gid_map: Option<(u32, u32, u32)>,
}

impl Default for UserNamespaceConfig {
    fn default() -> Self {
        // Default mapping: current user → root in namespace
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        
        Self {
            uid_map: Some((uid, 0, 1)),
            gid_map: Some((gid, 0, 1)),
        }
    }
}

pub fn create_user_namespace(config: &UserNamespaceConfig) -> Result<NsHandle, String> {
    // 1. Create user namespace
    unshare(CloneFlags::CLONE_NEWUSER)
        .map_err(|e| format!("Failed to unshare user namespace: {}", e))?;
    
    // 2. Disable setgroups (required to allow mapping without privileges)
    write_file("/proc/self/setgroups", "deny")
        .map_err(|e| format!("Failed to write setgroups: {}", e))?;
    
    // 3. Configure UID mapping
    if let Some((host_uid, ns_uid, count)) = config.uid_map {
        let mapping = format!("{} {} {}\n", ns_uid, host_uid, count);
        write_file("/proc/self/uid_map", &mapping)
            .map_err(|e| format!("Failed to write uid_map: {}", e))?;
    }
    
    // 4. Configure GID mapping
    if let Some((host_gid, ns_gid, count)) = config.gid_map {
        let mapping = format!("{} {} {}\n", ns_gid, host_gid, count);
        write_file("/proc/self/gid_map", &mapping)
            .map_err(|e| format!("Failed to write gid_map: {}", e))?;
    }
    
    Ok(NsHandle {
        user: true,
        mount: false,
        pid: false,
        ipc: false,
        uts: false,
        net: false,
    })
}

pub fn enter_namespaces() -> Result<NsHandle, String> {
    // Create all namespaces at once
    let flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWNS     // mount
        | CloneFlags::CLONE_NEWPID    // pid
        | CloneFlags::CLONE_NEWIPC    // ipc
        | CloneFlags::CLONE_NEWUTS;   // uts/hostname
        // | CloneFlags::CLONE_NEWNET  // network (optional)
    
    unshare(flags)
        .map_err(|e| format!("Failed to unshare namespaces: {}", e))?;
    
    // Configure uid/gid mapping (user namespace)
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    
    write_file("/proc/self/setgroups", "deny")?;
    write_file("/proc/self/uid_map", &format!("0 {} 1\n", uid))?;
    write_file("/proc/self/gid_map", &format!("0 {} 1\n", gid))?;
    
    Ok(NsHandle {
        user: true,
        mount: true,
        pid: true,
        ipc: true,
        uts: true,
        net: false,
    })
}

pub fn mount_proc() -> Result<(), String> {
    use nix::mount::{mount, MsFlags};
    
    // Create /proc if it doesn't exist
    fs::create_dir_all("/proc")
        .map_err(|e| format!("Failed to create /proc: {}", e))?;
    
    // Mount procfs
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID,
        None::<&str>,
    )
    .map_err(|e| format!("Failed to mount /proc: {}", e))?;
    
    Ok(())
}

// Helper to write to procfs files
fn write_file(path: &str, content: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("Failed to open {}: {}", path, e))?;
    
    file.write_all(content.as_bytes())
        .map_err(|e| format!("Failed to write to {}: {}", path, e))?;
    
    Ok(())
}

