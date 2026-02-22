//! Seccomp notification supervisor.
//!
//! Runs in the parent process, handling intercepted syscalls from the sandboxed child.
//! The supervisor receives notifications via the seccomp listener fd and decides
//! how to respond based on the configured [`NotifyMode`].
//!
//! ## Modes
//!
//! - **Monitor**: Log syscall and return `SECCOMP_USER_NOTIF_FLAG_CONTINUE`
//! - **Virtualize**: Translate filesystem paths via [`VirtualFs`], inject fds via `ADDFD`

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use evalbox_sys::seccomp_notify::{
    SECCOMP_ADDFD_FLAG_SEND, SECCOMP_USER_NOTIF_FLAG_CONTINUE, SeccompNotif, SeccompNotifAddfd,
    SeccompNotifResp, notif_addfd, notif_id_valid, notif_recv, notif_send,
};

use super::virtual_fs::VirtualFs;
use crate::plan::NotifyMode;

/// Events emitted by the supervisor for future user-facing notifications.
#[derive(Debug)]
pub enum NotifyEvent {
    /// A syscall was intercepted and handled.
    SyscallHandled {
        /// PID of the process that made the syscall.
        pid: u32,
        /// Syscall number.
        syscall_nr: i32,
        /// Whether the syscall was allowed.
        allowed: bool,
    },
}

/// Seccomp notification supervisor.
pub struct Supervisor {
    listener_fd: OwnedFd,
    mode: NotifyMode,
    vfs: VirtualFs,
}

impl Supervisor {
    /// Create a new supervisor.
    pub fn new(listener_fd: OwnedFd, mode: NotifyMode, vfs: VirtualFs) -> Self {
        Self {
            listener_fd,
            mode,
            vfs,
        }
    }

    /// Get the raw fd for registering with poll/mio.
    pub fn fd(&self) -> RawFd {
        self.listener_fd.as_raw_fd()
    }

    /// Handle a notification event. Call when the listener fd is readable.
    ///
    /// Returns `Some(NotifyEvent)` on success, `None` if the notification was
    /// stale (child died or already handled).
    pub fn handle_event(&self) -> io::Result<Option<NotifyEvent>> {
        let mut notif = SeccompNotif::default();

        if let Err(e) = notif_recv(self.listener_fd.as_raw_fd(), &mut notif) {
            // ENOENT means the target process died before we could receive
            if e == rustix::io::Errno::NOENT {
                return Ok(None);
            }
            return Err(io::Error::from_raw_os_error(e.raw_os_error()));
        }

        match self.mode {
            NotifyMode::Disabled => {
                debug_assert!(
                    false,
                    "supervisor received notification with NotifyMode::Disabled"
                );
                self.respond_continue(&notif)?;
                Ok(None)
            }
            NotifyMode::Monitor => self.handle_monitor(&notif),
            NotifyMode::Virtualize => self.handle_virtualize(&notif),
        }
    }

    fn handle_monitor(&self, notif: &SeccompNotif) -> io::Result<Option<NotifyEvent>> {
        let syscall_name = syscall_name(notif.data.nr);
        eprintln!(
            "[notify] pid={} syscall={}({}) args=[{:#x}, {:#x}, {:#x}]",
            notif.pid,
            syscall_name,
            notif.data.nr,
            notif.data.args[0],
            notif.data.args[1],
            notif.data.args[2],
        );

        self.respond_continue(notif)?;

        Ok(Some(NotifyEvent::SyscallHandled {
            pid: notif.pid,
            syscall_nr: notif.data.nr,
            allowed: true,
        }))
    }

    fn handle_virtualize(&self, notif: &SeccompNotif) -> io::Result<Option<NotifyEvent>> {
        let syscall_nr = notif.data.nr;

        // For openat-family syscalls, args[1] is the pathname pointer
        // For open/creat, args[0] is the pathname pointer
        let path_addr = if syscall_nr == libc::SYS_openat as i32
            || syscall_nr == libc::SYS_newfstatat as i32
            || syscall_nr == libc::SYS_faccessat as i32
            || syscall_nr == libc::SYS_faccessat2 as i32
            || syscall_nr == libc::SYS_readlinkat as i32
        {
            notif.data.args[1]
        } else {
            notif.data.args[0]
        };

        // Read path from child's memory
        let path = match self.read_child_string(notif.pid, path_addr) {
            Ok(p) => p,
            Err(_) => {
                // Can't read memory, let syscall proceed
                self.respond_continue(notif)?;
                return Ok(None);
            }
        };

        // TOCTOU check: verify notification is still valid after reading memory
        if notif_id_valid(self.listener_fd.as_raw_fd(), notif.id).is_err() {
            return Ok(None); // Notification is stale
        }

        // Try to translate path
        if let Some(real_path) = self.vfs.translate(&path) {
            // For openat: open the file ourselves and inject the fd
            if syscall_nr == libc::SYS_openat as i32
                || syscall_nr == libc::SYS_open as i32
                || syscall_nr == libc::SYS_creat as i32
            {
                let flags = if syscall_nr == libc::SYS_openat as i32 {
                    notif.data.args[2] as i32
                } else {
                    notif.data.args[1] as i32
                };

                match self.open_and_inject(notif, &real_path, flags) {
                    Ok(()) => {
                        return Ok(Some(NotifyEvent::SyscallHandled {
                            pid: notif.pid,
                            syscall_nr,
                            allowed: true,
                        }));
                    }
                    Err(_) => {
                        // Fall through to continue
                    }
                }
            }
        }

        // No translation or non-open syscall: let it proceed as-is
        self.respond_continue(notif)?;
        Ok(Some(NotifyEvent::SyscallHandled {
            pid: notif.pid,
            syscall_nr,
            allowed: true,
        }))
    }

    fn respond_continue(&self, notif: &SeccompNotif) -> io::Result<()> {
        let resp = SeccompNotifResp {
            id: notif.id,
            val: 0,
            error: 0,
            flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        };
        notif_send(self.listener_fd.as_raw_fd(), &resp)
            .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
    }

    fn open_and_inject(
        &self,
        notif: &SeccompNotif,
        real_path: &std::path::Path,
        flags: i32,
    ) -> io::Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let path_c = CString::new(real_path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid path"))?;

        // Open the file at the translated path
        let fd = unsafe { libc::open(path_c.as_ptr(), flags & !libc::O_CLOEXEC, 0o666) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Inject the fd into the child and atomically respond
        let addfd = SeccompNotifAddfd {
            id: notif.id,
            flags: SECCOMP_ADDFD_FLAG_SEND,
            srcfd: fd as u32,
            newfd: 0,
            newfd_flags: 0,
        };

        let result = notif_addfd(self.listener_fd.as_raw_fd(), &addfd)
            .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()));

        // Close our copy of the fd
        unsafe { libc::close(fd) };

        result.map(|_| ())
    }

    /// Read a null-terminated string from the child's memory via `/proc/pid/mem`.
    fn read_child_string(&self, pid: u32, addr: u64) -> io::Result<String> {
        let mem_path = format!("/proc/{pid}/mem");
        let mut file = File::open(&mem_path)?;
        file.seek(SeekFrom::Start(addr))?;

        let mut buf = vec![0u8; 4096];
        let n = file.read(&mut buf)?;
        buf.truncate(n);

        // Find null terminator
        if let Some(nul_pos) = buf.iter().position(|&b| b == 0) {
            buf.truncate(nul_pos);
        }

        String::from_utf8(buf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 in path"))
    }
}

/// Map syscall number to name for logging.
fn syscall_name(nr: i32) -> &'static str {
    match nr as i64 {
        libc::SYS_openat => "openat",
        libc::SYS_open => "open",
        libc::SYS_creat => "creat",
        libc::SYS_access => "access",
        libc::SYS_faccessat => "faccessat",
        libc::SYS_faccessat2 => "faccessat2",
        libc::SYS_stat => "stat",
        libc::SYS_lstat => "lstat",
        libc::SYS_newfstatat => "newfstatat",
        libc::SYS_statx => "statx",
        libc::SYS_readlink => "readlink",
        libc::SYS_readlinkat => "readlinkat",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_names() {
        assert_eq!(syscall_name(libc::SYS_openat as i32), "openat");
        assert_eq!(syscall_name(libc::SYS_stat as i32), "stat");
        assert_eq!(syscall_name(9999), "unknown");
    }
}
