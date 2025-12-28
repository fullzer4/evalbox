//! Cgroups v2 resource limits

use crate::{LeewardError, Result};

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
        // TODO: Create cgroup under /sys/fs/cgroup/leeward/{name}
        tracing::debug!(
            name,
            memory = self.memory_max,
            cpu = self.cpu_percent,
            pids = self.pids_max,
            "creating cgroup"
        );
        Ok(CgroupHandle {
            name: name.to_string(),
            path: format!("/sys/fs/cgroup/leeward/{name}"),
        })
    }
}

/// Handle to a cgroup
#[derive(Debug)]
pub struct CgroupHandle {
    name: String,
    path: String,
}

impl CgroupHandle {
    /// Add a process to this cgroup
    pub fn add_process(&self, pid: u32) -> Result<()> {
        // TODO: Write pid to cgroup.procs
        tracing::debug!(cgroup = %self.name, pid, "adding process to cgroup");
        Ok(())
    }

    /// Get current memory usage
    pub fn memory_current(&self) -> Result<u64> {
        // TODO: Read memory.current
        Ok(0)
    }

    /// Get peak memory usage
    pub fn memory_peak(&self) -> Result<u64> {
        // TODO: Read memory.peak
        Ok(0)
    }

    /// Check if OOM killed
    pub fn was_oom_killed(&self) -> Result<bool> {
        // TODO: Read memory.events for oom_kill
        Ok(false)
    }

    /// Destroy the cgroup
    pub fn destroy(self) -> Result<()> {
        // TODO: rmdir the cgroup
        tracing::debug!(cgroup = %self.name, "destroying cgroup");
        Ok(())
    }
}
