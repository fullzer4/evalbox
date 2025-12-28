//! Filesystem mounting and pivot_root

use crate::{LeewardError, Result};
use std::path::PathBuf;

/// Configuration for filesystem mounts
#[derive(Debug, Clone, Default)]
pub struct MountConfig {
    /// New root path for pivot_root
    pub new_root: PathBuf,
    /// Read-only bind mounts
    pub ro_binds: Vec<(PathBuf, PathBuf)>,
    /// Read-write bind mounts
    pub rw_binds: Vec<(PathBuf, PathBuf)>,
    /// tmpfs mounts with size limits
    pub tmpfs: Vec<(PathBuf, u64)>,
}

impl MountConfig {
    /// Add a read-only bind mount
    #[must_use]
    pub fn ro_bind(mut self, src: impl Into<PathBuf>, dst: impl Into<PathBuf>) -> Self {
        self.ro_binds.push((src.into(), dst.into()));
        self
    }

    /// Add a read-write bind mount
    #[must_use]
    pub fn rw_bind(mut self, src: impl Into<PathBuf>, dst: impl Into<PathBuf>) -> Self {
        self.rw_binds.push((src.into(), dst.into()));
        self
    }

    /// Add a tmpfs mount with size limit in bytes
    #[must_use]
    pub fn tmpfs(mut self, path: impl Into<PathBuf>, size_bytes: u64) -> Self {
        self.tmpfs.push((path.into(), size_bytes));
        self
    }

    /// Setup all mounts and perform pivot_root
    pub fn apply(&self) -> Result<()> {
        self.setup_root()?;
        self.setup_binds()?;
        self.setup_tmpfs()?;
        self.do_pivot_root()?;
        Ok(())
    }

    fn setup_root(&self) -> Result<()> {
        // TODO: Create new root directory structure
        tracing::debug!(root = ?self.new_root, "setting up root");
        Ok(())
    }

    fn setup_binds(&self) -> Result<()> {
        for (src, dst) in &self.ro_binds {
            tracing::debug!(?src, ?dst, "ro bind mount");
            // TODO: mount --bind, then remount ro
        }
        for (src, dst) in &self.rw_binds {
            tracing::debug!(?src, ?dst, "rw bind mount");
            // TODO: mount --bind
        }
        Ok(())
    }

    fn setup_tmpfs(&self) -> Result<()> {
        for (path, size) in &self.tmpfs {
            tracing::debug!(?path, size, "tmpfs mount");
            // TODO: mount -t tmpfs -o size={size}
        }
        Ok(())
    }

    fn do_pivot_root(&self) -> Result<()> {
        // TODO: pivot_root(new_root, put_old)
        // Then unmount and remove put_old
        tracing::debug!(root = ?self.new_root, "pivot_root");
        Ok(())
    }
}
