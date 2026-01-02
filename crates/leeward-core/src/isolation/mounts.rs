//! Filesystem mounting and pivot_root

use crate::{LeewardError, Result};
use std::path::PathBuf;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

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
        tracing::debug!(root = ?self.new_root, "setting up root");

        // Create new root if it doesn't exist
        if self.new_root != PathBuf::new() {
            std::fs::create_dir_all(&self.new_root)
                .map_err(|e| LeewardError::Mount(format!("failed to create new root: {e}")))?;

            // Create essential directories
            for dir in &["proc", "sys", "dev", "tmp", "home", "home/sandbox"] {
                let path = self.new_root.join(dir);
                std::fs::create_dir_all(&path)
                    .map_err(|e| LeewardError::Mount(format!("failed to create {}: {e}", dir)))?;
            }
        }

        Ok(())
    }

    fn setup_binds(&self) -> Result<()> {
        for (src, dst) in &self.ro_binds {
            tracing::debug!(?src, ?dst, "ro bind mount");

            if src.exists() {
                // Ensure destination exists
                if let Some(parent) = dst.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| LeewardError::Mount(format!("failed to create mount point: {e}")))?;
                }

                // Bind mount
                mount_bind(src, dst)?;
                // Remount read-only
                mount_remount_ro(dst)?;
            }
        }

        for (src, dst) in &self.rw_binds {
            tracing::debug!(?src, ?dst, "rw bind mount");

            if src.exists() {
                // Ensure destination exists
                if let Some(parent) = dst.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| LeewardError::Mount(format!("failed to create mount point: {e}")))?;
                }

                // Bind mount
                mount_bind(src, dst)?;
            }
        }
        Ok(())
    }

    fn setup_tmpfs(&self) -> Result<()> {
        for (path, size) in &self.tmpfs {
            tracing::debug!(?path, size, "tmpfs mount");

            // Ensure mount point exists
            std::fs::create_dir_all(path)
                .map_err(|e| LeewardError::Mount(format!("failed to create tmpfs mount point: {e}")))?;

            mount_tmpfs(path, *size)?;
        }
        Ok(())
    }

    fn do_pivot_root(&self) -> Result<()> {
        tracing::debug!(root = ?self.new_root, "pivot_root");

        if self.new_root == PathBuf::new() {
            return Ok(()); // Skip pivot_root if no new root specified
        }

        let put_old = self.new_root.join("put_old");
        std::fs::create_dir_all(&put_old)
            .map_err(|e| LeewardError::Mount(format!("failed to create put_old: {e}")))?;

        pivot_root(&self.new_root, &put_old)?;

        // Change to new root
        std::env::set_current_dir("/")
            .map_err(|e| LeewardError::Mount(format!("failed to chdir to /: {e}")))?;

        // Unmount old root
        umount2(&PathBuf::from("/put_old"), libc::MNT_DETACH)?;

        // Remove put_old directory
        std::fs::remove_dir("/put_old")
            .map_err(|e| LeewardError::Mount(format!("failed to remove put_old: {e}")))?;

        Ok(())
    }
}

// Helper functions for mount operations

fn path_to_cstring(path: &std::path::Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|e| LeewardError::Mount(format!("invalid path {}: {}", path.display(), e)))
}

fn mount_bind(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    let src_c = path_to_cstring(src)?;
    let dst_c = path_to_cstring(dst)?;

    // SAFETY: mount syscall with bind flag
    let ret = unsafe {
        libc::mount(
            src_c.as_ptr(),
            dst_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    };

    if ret != 0 {
        return Err(LeewardError::Mount(format!(
            "failed to bind mount {} to {}: {}",
            src.display(),
            dst.display(),
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

fn mount_remount_ro(path: &std::path::Path) -> Result<()> {
    let path_c = path_to_cstring(path)?;

    // SAFETY: mount syscall to remount read-only
    let ret = unsafe {
        libc::mount(
            std::ptr::null(),
            path_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
            std::ptr::null(),
        )
    };

    if ret != 0 {
        return Err(LeewardError::Mount(format!(
            "failed to remount {} read-only: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

fn mount_tmpfs(path: &std::path::Path, size: u64) -> Result<()> {
    let path_c = path_to_cstring(path)?;
    let fstype = CString::new("tmpfs")
        .map_err(|e| LeewardError::Mount(format!("invalid fstype: {e}")))?;

    let size_mb = size / (1024 * 1024);
    let options = CString::new(format!("size={}M", size_mb))
        .map_err(|e| LeewardError::Mount(format!("invalid options: {e}")))?;

    // SAFETY: mount syscall with tmpfs
    let ret = unsafe {
        libc::mount(
            fstype.as_ptr(),
            path_c.as_ptr(),
            fstype.as_ptr(),
            0,
            options.as_ptr() as *const libc::c_void,
        )
    };

    if ret != 0 {
        return Err(LeewardError::Mount(format!(
            "failed to mount tmpfs at {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

fn pivot_root(new_root: &std::path::Path, put_old: &std::path::Path) -> Result<()> {
    let new_root_c = path_to_cstring(new_root)?;
    let put_old_c = path_to_cstring(put_old)?;

    // SAFETY: pivot_root syscall
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pivot_root,
            new_root_c.as_ptr(),
            put_old_c.as_ptr(),
        )
    };

    if ret != 0 {
        return Err(LeewardError::Mount(format!(
            "pivot_root failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

fn umount2(path: &std::path::Path, flags: i32) -> Result<()> {
    let path_c = path_to_cstring(path)?;

    // SAFETY: umount2 syscall
    let ret = unsafe {
        libc::umount2(path_c.as_ptr(), flags)
    };

    if ret != 0 {
        return Err(LeewardError::Mount(format!(
            "umount2 failed for {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}
