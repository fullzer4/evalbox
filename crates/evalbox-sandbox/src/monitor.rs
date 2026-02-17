//! Process monitoring and output collection.
//!
//! Monitors the sandboxed child process using `pidfd` and collects stdout/stderr.
//! Uses `poll()` to multiplex between:
//!
//! - **pidfd** - Signals when child exits (no race conditions vs waitpid)
//! - **stdout pipe** - Data from child's stdout
//! - **stderr pipe** - Data from child's stderr
//! - **timeout** - Kills child if deadline exceeded
//!
//! ## Output Limits
//!
//! If stdout or stderr exceeds `max_output`, the child is killed with SIGKILL
//! and status is set to `OutputLimitExceeded`. This prevents memory exhaustion
//! from runaway output.
//!
//! ## Exit Detection
//!
//! Uses `waitid(P_PIDFD, ...)` to get detailed exit information:
//! - `CLD_EXITED` - Normal exit with exit code
//! - `CLD_KILLED` / `CLD_DUMPED` - Killed by signal

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use rustix::process::{Signal, pidfd_send_signal};

use crate::plan::Plan;
use crate::workspace::Workspace;

/// Output from a sandboxed execution.
#[derive(Debug, Clone)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: Status,
    pub duration: Duration,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

impl Output {
    #[inline]
    pub fn success(&self) -> bool {
        self.status == Status::Exited && self.exit_code == Some(0)
    }

    #[inline]
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    #[inline]
    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// Status of the sandboxed execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Exited,
    Signaled,
    Timeout,
    OutputLimitExceeded,
}

/// Monitor the child process and collect output.
pub fn monitor(pidfd: OwnedFd, workspace: &Workspace, plan: &Plan) -> io::Result<Output> {
    let start = Instant::now();
    let deadline = start + plan.timeout;

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();

    let stdout_fd = workspace.pipes.stdout.read.as_raw_fd();
    let stderr_fd = workspace.pipes.stderr.read.as_raw_fd();
    let pidfd_raw = pidfd.as_raw_fd();

    set_nonblocking(stdout_fd)?;
    set_nonblocking(stderr_fd)?;

    let mut status = Status::Exited;
    let mut exit_code = None;
    let mut signal = None;
    let mut buf = [0u8; 4096];

    loop {
        let timeout_remaining = deadline.saturating_duration_since(Instant::now());
        if timeout_remaining.is_zero() {
            pidfd_send_signal(&pidfd, Signal::KILL).ok();
            status = Status::Timeout;
            wait_for_exit(pidfd_raw)?;
            break;
        }

        // Cap at 100ms to allow periodic timeout checks. Cast is safe since min(100) fits in i32.
        let poll_timeout = timeout_remaining.as_millis().min(100) as i32;
        let mut fds = [
            libc::pollfd {
                fd: stdout_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stderr_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: pidfd_raw,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 3, poll_timeout) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }

        if fds[0].revents & libc::POLLIN != 0 {
            if let Ok(n) = read_nonblocking(stdout_fd, &mut buf) {
                if n > 0 {
                    if stdout_buf.len() + n > plan.max_output as usize {
                        status = Status::OutputLimitExceeded;
                        pidfd_send_signal(&pidfd, Signal::KILL).ok();
                        wait_for_exit(pidfd_raw)?;
                        break;
                    }
                    stdout_buf.extend_from_slice(&buf[..n]);
                }
            }
        }

        if fds[1].revents & libc::POLLIN != 0 {
            if let Ok(n) = read_nonblocking(stderr_fd, &mut buf) {
                if n > 0 {
                    if stderr_buf.len() + n > plan.max_output as usize {
                        status = Status::OutputLimitExceeded;
                        pidfd_send_signal(&pidfd, Signal::KILL).ok();
                        wait_for_exit(pidfd_raw)?;
                        break;
                    }
                    stderr_buf.extend_from_slice(&buf[..n]);
                }
            }
        }

        if fds[2].revents & libc::POLLIN != 0 {
            let (ec, sig) = wait_for_exit(pidfd_raw)?;
            exit_code = ec;
            signal = sig;
            if sig.is_some() {
                status = Status::Signaled;
            }
            break;
        }

        if (fds[0].revents & libc::POLLHUP != 0) && (fds[1].revents & libc::POLLHUP != 0) {
            let (ec, sig) = wait_for_exit(pidfd_raw)?;
            exit_code = ec;
            signal = sig;
            if sig.is_some() {
                status = Status::Signaled;
            }
            break;
        }
    }

    drain_remaining(stdout_fd, &mut stdout_buf, &mut buf, plan.max_output);
    drain_remaining(stderr_fd, &mut stderr_buf, &mut buf, plan.max_output);

    Ok(Output {
        stdout: stdout_buf,
        stderr: stderr_buf,
        status,
        duration: start.elapsed(),
        exit_code,
        signal,
    })
}

/// Write stdin data to the child process.
pub fn write_stdin(workspace: &Workspace, data: &[u8]) -> io::Result<()> {
    let fd = workspace.pipes.stdin.write.as_raw_fd();
    let mut written = 0;
    while written < data.len() {
        let ret = unsafe {
            libc::write(
                fd,
                data[written..].as_ptr().cast::<libc::c_void>(),
                data.len() - written,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        written += ret as usize;
    }
    Ok(())
}

#[inline]
pub(crate) fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[inline]
fn read_nonblocking(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let ret = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

fn drain_remaining(fd: RawFd, output: &mut Vec<u8>, buf: &mut [u8], max_output: u64) {
    let max = max_output as usize;
    loop {
        if output.len() >= max {
            // Already at limit, stop reading
            break;
        }
        match read_nonblocking(fd, buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                // Only append up to the limit
                let remaining = max.saturating_sub(output.len());
                let to_add = n.min(remaining);
                output.extend_from_slice(&buf[..to_add]);
            }
        }
    }
}

pub(crate) fn wait_for_exit(pidfd: RawFd) -> io::Result<(Option<i32>, Option<i32>)> {
    let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            pidfd as libc::id_t,
            &mut siginfo,
            libc::WEXITED,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let code = siginfo.si_code;
    let status = unsafe { siginfo.si_status() };

    match code {
        libc::CLD_EXITED => Ok((Some(status), None)),
        libc::CLD_KILLED | libc::CLD_DUMPED => Ok((None, Some(status))),
        _ => Ok((None, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_success() {
        let output = Output {
            stdout: vec![],
            stderr: vec![],
            status: Status::Exited,
            duration: Duration::from_millis(100),
            exit_code: Some(0),
            signal: None,
        };
        assert!(output.success());
    }

    #[test]
    fn output_failure() {
        let output = Output {
            stdout: vec![],
            stderr: vec![],
            status: Status::Exited,
            duration: Duration::from_millis(100),
            exit_code: Some(1),
            signal: None,
        };
        assert!(!output.success());
    }
}
