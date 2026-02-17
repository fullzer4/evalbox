//! Workspace and pipe management for sandboxed execution.
//!
//! The workspace is a temporary directory that becomes the sandbox root after `pivot_root`.
//! It contains all the pipes for parent-child communication.
//!
//! ## Pipes
//!
//! - **stdin**: Parent writes → Child reads
//! - **stdout**: Child writes → Parent reads
//! - **stderr**: Child writes → Parent reads
//! - **sync**: Eventfd pair for parent-child synchronization (UID map setup)
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
            // Set executable permission (rwxr-xr-x)
            fs::set_permissions(&full, fs::Permissions::from_mode(0o755))?;
        }

        Ok(full)
    }

    pub fn create_dir(&self, path: &str) -> io::Result<PathBuf> {
        let full = self.root.join(path);
        fs::create_dir_all(&full)?;
        Ok(full)
    }

    pub fn setup_sandbox_dirs(&self) -> io::Result<()> {
        for dir in [
            "proc", "dev", "tmp", "home", "work", "usr", "bin", "lib", "lib64", "etc",
        ] {
            self.create_dir(dir)?;
        }
        self.setup_minimal_etc()?;
        Ok(())
    }

    /// Create minimal /etc files to prevent information leakage.
    ///
    /// Instead of mounting the host's /etc (which contains sensitive info like
    /// /etc/passwd, /etc/shadow), we create a minimal /etc with only essential files.
    pub fn setup_minimal_etc(&self) -> io::Result<()> {
        let etc = self.root.join("etc");

        // Minimal /etc/passwd - just nobody user
        fs::write(
            etc.join("passwd"),
            "nobody:x:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin\n",
        )?;

        // Minimal /etc/group - just nobody group
        fs::write(etc.join("group"), "nogroup:x:65534:\n")?;

        // Minimal /etc/hosts - localhost only
        fs::write(etc.join("hosts"), "127.0.0.1 localhost\n::1 localhost\n")?;

        // Minimal /etc/nsswitch.conf - required for name resolution
        fs::write(
            etc.join("nsswitch.conf"),
            "passwd: files\ngroup: files\nhosts: files dns\n",
        )?;

        // Copy /etc/ld.so.cache from host if it exists (needed for dynamic linking)
        let host_ldcache = Path::new("/etc/ld.so.cache");
        if host_ldcache.exists() {
            if let Ok(content) = fs::read(host_ldcache) {
                fs::write(etc.join("ld.so.cache"), content)?;
            }
        }

        // Create /etc/ssl directory for certificates
        let ssl_dir = etc.join("ssl");
        fs::create_dir_all(&ssl_dir)?;

        // Minimal /etc/resolv.conf - empty (network is blocked by default)
        // When network is enabled, Landlock will allow DNS
        fs::write(etc.join("resolv.conf"), "# DNS disabled in sandbox\n")?;

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
}
