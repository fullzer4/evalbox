//! Workspace and pipe management for sandboxed execution.
//!
//! The workspace is a temporary directory containing the sandbox's writable areas
//! and all the pipes for parent-child communication.
//!
//! ## Pipes
//!
//! - **stdin**: Parent writes → Child reads
//! - **stdout**: Child writes → Parent reads
//! - **stderr**: Child writes → Parent reads
//! - **sync**: Eventfd for parent-child synchronization
//!
//! ## Important: Pipe Hygiene
//!
//! After `fork()`, each side must close unused pipe ends:
//! - Parent closes: stdin.read, stdout.write, stderr.write
//! - Child closes: stdin.write, stdout.read, stderr.read
//!
//! This is required for `poll()` to work correctly - EOF is only signaled
//! when ALL write ends are closed.

use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use tempfile::TempDir;

/// Unidirectional pipe.
#[derive(Debug)]
pub struct Pipe {
    pub read: OwnedFd,
    pub write: OwnedFd,
}

impl Pipe {
    pub fn new() -> io::Result<Self> {
        let mut fds = [0i32; 2];
        // SAFETY: pipe2 writes to valid array.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: On success, fds are valid file descriptors.
        Ok(Self {
            read: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            write: unsafe { OwnedFd::from_raw_fd(fds[1]) },
        })
    }

    #[inline]
    pub fn read_fd(&self) -> RawFd {
        self.read.as_raw_fd()
    }

    #[inline]
    pub fn write_fd(&self) -> RawFd {
        self.write.as_raw_fd()
    }
}

/// Eventfd-based parent-child synchronization.
///
/// Used when `NotifyMode::Disabled` — the child signals readiness via eventfd
/// after completing setup, and the parent writes back to let it proceed to exec.
#[derive(Debug)]
pub struct SyncPair {
    pub child_ready: OwnedFd,
    pub parent_done: OwnedFd,
}

impl SyncPair {
    pub fn new() -> io::Result<Self> {
        let child_ready = unsafe { libc::eventfd(0, 0) };
        if child_ready < 0 {
            return Err(io::Error::last_os_error());
        }
        let parent_done = unsafe { libc::eventfd(0, 0) };
        if parent_done < 0 {
            unsafe { libc::close(child_ready) };
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            child_ready: unsafe { OwnedFd::from_raw_fd(child_ready) },
            parent_done: unsafe { OwnedFd::from_raw_fd(parent_done) },
        })
    }

    #[inline]
    pub fn child_ready_fd(&self) -> RawFd {
        self.child_ready.as_raw_fd()
    }

    #[inline]
    pub fn parent_done_fd(&self) -> RawFd {
        self.parent_done.as_raw_fd()
    }
}

/// All pipes for sandbox I/O.
#[derive(Debug)]
pub struct Pipes {
    pub stdin: Pipe,
    pub stdout: Pipe,
    pub stderr: Pipe,
    pub sync: SyncPair,
}

impl Pipes {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            stdin: Pipe::new()?,
            stdout: Pipe::new()?,
            stderr: Pipe::new()?,
            sync: SyncPair::new()?,
        })
    }
}

/// Temporary workspace for sandbox execution.
#[derive(Debug)]
pub struct Workspace {
    root: PathBuf,
    pub pipes: Pipes,
    _tempdir: TempDir,
}

impl Workspace {
    pub fn new() -> io::Result<Self> {
        Self::with_prefix("evalbox-")
    }

    pub fn with_prefix(prefix: &str) -> io::Result<Self> {
        let tempdir = TempDir::with_prefix(prefix)?;
        Ok(Self {
            root: tempdir.path().to_path_buf(),
            pipes: Pipes::new()?,
            _tempdir: tempdir,
        })
    }

    #[inline]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn write_file(&self, path: &str, content: &[u8], executable: bool) -> io::Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt;

        let full = self.root.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&full, content)?;

        if executable {
            fs::set_permissions(&full, fs::Permissions::from_mode(0o755))?;
        }

        Ok(full)
    }

    pub fn create_dir(&self, path: &str) -> io::Result<PathBuf> {
        let full = self.root.join(path);
        fs::create_dir_all(&full)?;
        Ok(full)
    }

    /// Create standard sandbox directories.
    ///
    /// Only creates the writable workspace directories (work, tmp, home).
    /// No rootfs directories (proc, dev, etc.) needed since we don't use `pivot_root`.
    pub fn setup_sandbox_dirs(&self) -> io::Result<()> {
        for dir in ["work", "tmp", "home"] {
            self.create_dir(dir)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_creation() {
        let pipe = Pipe::new().unwrap();
        assert!(pipe.read_fd() >= 0);
        assert_ne!(pipe.read_fd(), pipe.write_fd());
    }

    #[test]
    fn workspace_creation() {
        let ws = Workspace::new().unwrap();
        assert!(ws.root().exists());
    }

    #[test]
    fn workspace_write_file() {
        let ws = Workspace::new().unwrap();
        let path = ws.write_file("test.txt", b"hello", false).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn workspace_write_executable() {
        use std::os::unix::fs::PermissionsExt;

        let ws = Workspace::new().unwrap();
        let path = ws.write_file("binary", b"\x7fELF", true).unwrap();
        assert!(path.exists());
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o755);
    }

    #[test]
    fn workspace_sandbox_dirs() {
        let ws = Workspace::new().unwrap();
        ws.setup_sandbox_dirs().unwrap();
        assert!(ws.root().join("work").exists());
        assert!(ws.root().join("tmp").exists());
        assert!(ws.root().join("home").exists());
    }
}
