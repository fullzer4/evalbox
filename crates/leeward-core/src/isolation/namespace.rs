//! Linux namespace isolation

use crate::{LeewardError, Result};
use nix::sched::CloneFlags;

/// Configuration for namespace isolation
#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    /// Create new user namespace
    pub user: bool,
    /// Create new PID namespace
    pub pid: bool,
    /// Create new mount namespace
    pub mount: bool,
    /// Create new network namespace
    pub net: bool,
    /// Create new IPC namespace
    pub ipc: bool,
    /// Create new UTS namespace
    pub uts: bool,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            user: true,
            pid: true,
            mount: true,
            net: true,
            ipc: true,
            uts: true,
        }
    }
}

impl NamespaceConfig {
    /// Convert to nix CloneFlags
    #[must_use]
    pub fn to_clone_flags(&self) -> CloneFlags {
        let mut flags = CloneFlags::empty();

        if self.user {
            flags |= CloneFlags::CLONE_NEWUSER;
        }
        if self.pid {
            flags |= CloneFlags::CLONE_NEWPID;
        }
        if self.mount {
            flags |= CloneFlags::CLONE_NEWNS;
        }
        if self.net {
            flags |= CloneFlags::CLONE_NEWNET;
        }
        if self.ipc {
            flags |= CloneFlags::CLONE_NEWIPC;
        }
        if self.uts {
            flags |= CloneFlags::CLONE_NEWUTS;
        }

        flags
    }

    /// Enter new namespaces using unshare
    pub fn enter(&self) -> Result<()> {
        let flags = self.to_clone_flags();
        nix::sched::unshare(flags).map_err(|e| {
            LeewardError::Namespace(format!("failed to unshare namespaces: {e}"))
        })?;
        Ok(())
    }
}
