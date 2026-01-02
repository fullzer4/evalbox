//! Cgroups v2 resource limits

use crate::{LeewardError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::os::unix::io::{AsRawFd, RawFd};

/// Configuration for cgroups v2 resource limits
#[derive(Debug, Clone)]
pub struct CgroupsConfig {
    /// Memory limit in bytes (memory.max)
    pub memory_max: u64,
    /// CPU quota as percentage (cpu.max)
    pub cpu_percent: u32,
    /// Maximum number of processes (pids.max)
    pub pids_max: u32,
    /// Enable memory swap (memory.swap.max)
    pub allow_swap: bool,
}

impl Default for CgroupsConfig {
    fn default() -> Self {
        Self {
            memory_max: 256 * 1024 * 1024, // 256MB
            cpu_percent: 100,
            pids_max: 32,
            allow_swap: false,
        }
    }
}

impl CgroupsConfig {
    /// Create a new cgroup for a sandbox
    pub fn create_cgroup(&self, name: &str) -> Result<CgroupHandle> {
        tracing::debug!(
            name,
            memory = self.memory_max,
            cpu = self.cpu_percent,
            pids = self.pids_max,
            "creating cgroup"
        );

        let cgroup_root = PathBuf::from("/sys/fs/cgroup");
        let leeward_cgroup = cgroup_root.join("leeward");
        let cgroup_path = leeward_cgroup.join(name);

        // Ensure leeward parent cgroup exists
        if !leeward_cgroup.exists() {
            fs::create_dir_all(&leeward_cgroup)
                .map_err(|e| LeewardError::Cgroups(format!("failed to create leeward cgroup: {e}")))?;

            // Enable controllers in leeward cgroup
            enable_controllers(&cgroup_root, "leeward")?;
        }

        // Create the specific cgroup
        if !cgroup_path.exists() {
            fs::create_dir_all(&cgroup_path)
                .map_err(|e| LeewardError::Cgroups(format!("failed to create cgroup {}: {e}", name)))?;
        }

        // Set memory limit
        let memory_max_path = cgroup_path.join("memory.max");
        fs::write(&memory_max_path, self.memory_max.to_string())
            .map_err(|e| LeewardError::Cgroups(format!("failed to set memory.max: {e}")))?;

        // Set memory swap limit (0 = no swap)
        if !self.allow_swap {
            let swap_max_path = cgroup_path.join("memory.swap.max");
            fs::write(&swap_max_path, "0")
                .map_err(|e| LeewardError::Cgroups(format!("failed to set memory.swap.max: {e}")))?;
        }

        // Set CPU limit (percentage as quota/period)
        // cpu.max format: "$quota $period" or "max $period"
        let cpu_max_path = cgroup_path.join("cpu.max");
        let period = 100000; // 100ms in microseconds
        let quota = if self.cpu_percent >= 100 {
            "max".to_string()
        } else {
            ((self.cpu_percent as u64 * period) / 100).to_string()
        };
        fs::write(&cpu_max_path, format!("{} {}", quota, period))
            .map_err(|e| LeewardError::Cgroups(format!("failed to set cpu.max: {e}")))?;

        // Set PIDs limit
        let pids_max_path = cgroup_path.join("pids.max");
        fs::write(&pids_max_path, self.pids_max.to_string())
            .map_err(|e| LeewardError::Cgroups(format!("failed to set pids.max: {e}")))?;

        // Get FD for CLONE_INTO_CGROUP
        let cgroup_fd = fs::File::open(&cgroup_path)
            .map_err(|e| LeewardError::Cgroups(format!("failed to open cgroup: {e}")))?
            .as_raw_fd();

        Ok(CgroupHandle {
            name: name.to_string(),
            path: cgroup_path,
            fd: Some(cgroup_fd),
        })
    }
}

/// Enable controllers in a cgroup
fn enable_controllers(parent: &Path, child_name: &str) -> Result<()> {
    let subtree_control = parent.join("cgroup.subtree_control");

    // Read current controllers
    let current = fs::read_to_string(&subtree_control).unwrap_or_default();

    // Enable memory, cpu, and pids controllers if not already enabled
    let mut controllers = vec![];
    if !current.contains("memory") {
        controllers.push("+memory");
    }
    if !current.contains("cpu") {
        controllers.push("+cpu");
    }
    if !current.contains("pids") {
        controllers.push("+pids");
    }

    if !controllers.is_empty() {
        let control_str = controllers.join(" ");
        fs::write(&subtree_control, control_str)
            .map_err(|e| LeewardError::Cgroups(format!(
                "failed to enable controllers for {}: {e}",
                child_name
            )))?;
    }

    Ok(())
}

/// Handle to a cgroup
#[derive(Debug)]
pub struct CgroupHandle {
    name: String,
    path: PathBuf,
    fd: Option<RawFd>,
}

impl CgroupHandle {
    /// Get the file descriptor for CLONE_INTO_CGROUP
    pub fn as_raw_fd(&self) -> Option<RawFd> {
        self.fd
    }

    /// Add a process to this cgroup
    pub fn add_process(&self, pid: u32) -> Result<()> {
        tracing::debug!(cgroup = %self.name, pid, "adding process to cgroup");

        let procs_path = self.path.join("cgroup.procs");
        fs::write(&procs_path, pid.to_string())
            .map_err(|e| LeewardError::Cgroups(format!("failed to add process to cgroup: {e}")))?;

        Ok(())
    }

    /// Get current memory usage
    pub fn memory_current(&self) -> Result<u64> {
        let memory_current_path = self.path.join("memory.current");
        let content = fs::read_to_string(&memory_current_path)
            .map_err(|e| LeewardError::Cgroups(format!("failed to read memory.current: {e}")))?;

        content
            .trim()
            .parse()
            .map_err(|e| LeewardError::Cgroups(format!("failed to parse memory.current: {e}")))
    }

    /// Get peak memory usage
    pub fn memory_peak(&self) -> Result<u64> {
        let memory_peak_path = self.path.join("memory.peak");
        let content = fs::read_to_string(&memory_peak_path)
            .map_err(|e| LeewardError::Cgroups(format!("failed to read memory.peak: {e}")))?;

        content
            .trim()
            .parse()
            .map_err(|e| LeewardError::Cgroups(format!("failed to parse memory.peak: {e}")))
    }

    /// Check if OOM killed
    pub fn was_oom_killed(&self) -> Result<bool> {
        let events_path = self.path.join("memory.events");
        let content = fs::read_to_string(&events_path)
            .map_err(|e| LeewardError::Cgroups(format!("failed to read memory.events: {e}")))?;

        // Parse events file for oom_kill count
        for line in content.lines() {
            if let Some(oom_line) = line.strip_prefix("oom_kill ") {
                let count: u64 = oom_line
                    .parse()
                    .map_err(|e| LeewardError::Cgroups(format!("failed to parse oom_kill count: {e}")))?;
                return Ok(count > 0);
            }
        }

        Ok(false)
    }

    /// Get CPU usage statistics
    pub fn cpu_stat(&self) -> Result<(u64, u64)> {
        let cpu_stat_path = self.path.join("cpu.stat");
        let content = fs::read_to_string(&cpu_stat_path)
            .map_err(|e| LeewardError::Cgroups(format!("failed to read cpu.stat: {e}")))?;

        let mut usage_usec = 0u64;
        let mut user_usec = 0u64;

        for line in content.lines() {
            if let Some(usage) = line.strip_prefix("usage_usec ") {
                usage_usec = usage.parse()
                    .map_err(|e| LeewardError::Cgroups(format!("failed to parse usage_usec: {e}")))?;
            } else if let Some(user) = line.strip_prefix("user_usec ") {
                user_usec = user.parse()
                    .map_err(|e| LeewardError::Cgroups(format!("failed to parse user_usec: {e}")))?;
            }
        }

        Ok((usage_usec, user_usec))
    }

    /// Destroy the cgroup
    pub fn destroy(self) -> Result<()> {
        tracing::debug!(cgroup = %self.name, "destroying cgroup");

        // Close the file descriptor first if we have one
        if let Some(fd) = self.fd {
            // SAFETY: closing a file descriptor we own
            unsafe { libc::close(fd); }
        }

        // Remove the cgroup directory
        fs::remove_dir(&self.path)
            .map_err(|e| LeewardError::Cgroups(format!("failed to remove cgroup: {e}")))?;

        Ok(())
    }
}
