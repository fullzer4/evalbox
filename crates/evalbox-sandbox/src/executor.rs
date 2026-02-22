//! Sandbox executor for both blocking and concurrent execution.
//!
//! This module provides the unified API for sandbox execution:
//!
//! - `Executor::run()` - Blocking execution (single sandbox)
//! - `Executor::spawn()` + `poll()` - Concurrent execution (multiple sandboxes)
//!
//! ## Blocking Example
//!
//! ```ignore
//! use evalbox_sandbox::{Executor, Plan};
//!
//! let output = Executor::run(Plan::new(["echo", "hello"]))?;
//! assert_eq!(output.stdout, b"hello\n");
//! ```
//!
//! ## Concurrent Example
//!
//! ```ignore
//! use evalbox_sandbox::{Executor, Plan, Event};
//!
//! let mut executor = Executor::new()?;
//! let id = executor.spawn(Plan::new(["echo", "hello"]))?;
//!
//! let mut events = Vec::new();
//! while executor.active_count() > 0 {
//!     executor.poll(&mut events, None)?;
//!     for event in events.drain(..) {
//!         match event {
//!             Event::Completed { id, output } => println!("Done: {:?}", output),
//!             Event::Stdout { id, data } => print!("{}", String::from_utf8_lossy(&data)),
//!             _ => {}
//!         }
//!     }
//! }
//! ```

use std::collections::HashMap;
use std::ffi::CString;
use std::io::{self, Write as _};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use mio::unix::SourceFd;
use mio::{Events as MioEvents, Interest, Poll, Token};
use rustix::io::Errno;
use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
use thiserror::Error;

use evalbox_sys::seccomp::{
    DEFAULT_WHITELIST, NOTIFY_FS_SYSCALLS, SockFprog, build_notify_filter, build_whitelist_filter,
};
use evalbox_sys::seccomp_notify::seccomp_set_mode_filter_listener;
use evalbox_sys::{check, last_errno, seccomp::seccomp_set_mode_filter};

use crate::isolation::{LockdownError, close_extra_fds, lockdown};
use crate::monitor::{Output, Status, monitor, set_nonblocking, wait_for_exit, write_stdin};
use crate::notify::scm_rights;
use crate::plan::{Mount, NotifyMode, Plan};
use crate::resolve::{ResolvedBinary, resolve_binary};
use crate::validate::validate_cmd;
use crate::workspace::Workspace;

/// Error during sandbox execution.
#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("system check: {0}")]
    SystemCheck(String),

    #[error("validation: {0}")]
    Validation(#[from] crate::validate::ValidationError),

    #[error("workspace: {0}")]
    Workspace(io::Error),

    #[error("fork: {0}")]
    Fork(Errno),

    #[error("lockdown: {0}")]
    Lockdown(#[from] LockdownError),

    #[error("exec: {0}")]
    Exec(Errno),

    #[error("monitor: {0}")]
    Monitor(io::Error),

    #[error("child setup: {0}")]
    ChildSetup(String),

    #[error("pidfd: {0}")]
    Pidfd(Errno),

    #[error("command not found: {0}")]
    CommandNotFound(String),

    #[error("seccomp notify: {0}")]
    SeccompNotify(String),

    #[error("io: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SandboxId(pub usize);

impl std::fmt::Display for SandboxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sandbox({})", self.0)
    }
}

/// Events emitted by the Executor.
#[derive(Debug)]
pub enum Event {
    /// Sandbox completed execution.
    Completed { id: SandboxId, output: Output },
    /// Sandbox timed out and was killed.
    Timeout { id: SandboxId, output: Output },
    /// Stdout data available (streaming mode).
    Stdout { id: SandboxId, data: Vec<u8> },
    /// Stderr data available (streaming mode).
    Stderr { id: SandboxId, data: Vec<u8> },
}

struct ExecutionInfo {
    binary_path: PathBuf,
    extra_mounts: Vec<Mount>,
}

impl ExecutionInfo {
    fn from_resolved(resolved: ResolvedBinary) -> Self {
        let extra_mounts = resolved
            .required_mounts
            .into_iter()
            .map(|m| Mount::bind(&m.source, &m.target))
            .collect();
        Self {
            binary_path: resolved.path,
            extra_mounts,
        }
    }

    fn from_plan(plan: &Plan) -> Option<Self> {
        plan.binary_path.as_ref().map(|path| Self {
            binary_path: path.clone(),
            extra_mounts: Vec::new(),
        })
    }
}

/// A spawned sandbox that hasn't been waited on yet.
///
/// Some fields are never read but kept alive for RAII (fd lifetime, temp dir cleanup).
#[allow(dead_code)]
struct SpawnedSandbox {
    pidfd: OwnedFd,
    stdin_fd: RawFd,
    stdout_fd: RawFd,
    stderr_fd: RawFd,
    /// Seccomp listener fd kept alive for RAII; future supervisor integration.
    notify_fd: Option<OwnedFd>,
    /// Workspace kept alive so temp directory isn't deleted while sandbox runs.
    workspace: std::mem::ManuallyDrop<Workspace>,
}

/// Internal state for a running sandbox.
struct SandboxState {
    spawned: SpawnedSandbox,
    deadline: Instant,
    start: Instant,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    max_output: u64,
    pidfd_ready: bool,
    stdout_closed: bool,
    stderr_closed: bool,
}

impl SandboxState {
    fn is_done(&self) -> bool {
        self.pidfd_ready && self.stdout_closed && self.stderr_closed
    }
}

// Token encoding: [sandbox_id: 20 bits][type: 2 bits]
const TOKEN_TYPE_BITS: usize = 2;
const TOKEN_TYPE_MASK: usize = 0b11;
const TOKEN_TYPE_PIDFD: usize = 0;
const TOKEN_TYPE_STDOUT: usize = 1;
const TOKEN_TYPE_STDERR: usize = 2;

fn encode_token(sandbox_id: usize, token_type: usize) -> Token {
    Token((sandbox_id << TOKEN_TYPE_BITS) | token_type)
}

fn decode_token(token: Token) -> (SandboxId, usize) {
    let raw = token.0;
    (SandboxId(raw >> TOKEN_TYPE_BITS), raw & TOKEN_TYPE_MASK)
}

pub struct Executor {
    poll: Poll,
    sandboxes: HashMap<SandboxId, SandboxState>,
    next_id: usize,
    mio_events: MioEvents,
}

impl Executor {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            poll: Poll::new()?,
            sandboxes: HashMap::new(),
            next_id: 0,
            mio_events: MioEvents::with_capacity(64),
        })
    }

    /// Execute a sandbox and wait for completion (blocking).
    pub fn run(plan: Plan) -> Result<Output, ExecutorError> {
        let cmd_refs: Vec<&str> = plan.cmd.iter().map(|s| s.as_str()).collect();
        validate_cmd(&cmd_refs).map_err(ExecutorError::Validation)?;

        if let Err(e) = check::check() {
            return Err(ExecutorError::SystemCheck(e.to_string()));
        }

        let exec_info = if let Some(info) = ExecutionInfo::from_plan(&plan) {
            info
        } else {
            let resolved = resolve_binary(&plan.cmd[0])
                .map_err(|e| ExecutorError::CommandNotFound(e.to_string()))?;
            ExecutionInfo::from_resolved(resolved)
        };

        let workspace = Workspace::with_prefix("evalbox-").map_err(ExecutorError::Workspace)?;

        workspace
            .setup_sandbox_dirs()
            .map_err(ExecutorError::Workspace)?;
        for file in &plan.user_files {
            let work_path = format!("work/{}", file.path);
            workspace
                .write_file(&work_path, &file.content, file.executable)
                .map_err(ExecutorError::Workspace)?;
        }

        // Create socketpair for notify fd transfer (if needed)
        let notify_sockets = if plan.notify_mode != NotifyMode::Disabled {
            Some(scm_rights::create_socketpair().map_err(ExecutorError::Workspace)?)
        } else {
            None
        };

        let child_pid = unsafe { libc::fork() };
        if child_pid < 0 {
            return Err(ExecutorError::Fork(last_errno()));
        }

        if child_pid == 0 {
            // In child: close parent's socket end
            let child_socket = notify_sockets.map(|(_, child)| child);
            match child_process(&workspace, &plan, &exec_info, child_socket.as_ref()) {
                Ok(()) => unsafe { libc::_exit(127) },
                Err(e) => {
                    writeln!(io::stderr(), "sandbox error: {e}").ok();
                    unsafe { libc::_exit(126) }
                }
            }
        }

        let pid = unsafe { Pid::from_raw_unchecked(child_pid) };
        let pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(ExecutorError::Pidfd)?;

        // Parent: receive notify fd if applicable
        let notify_fd = if let Some((parent_socket, _)) = notify_sockets {
            poll_or_kill(
                parent_socket.as_raw_fd(),
                child_pid,
                "timeout waiting for notify fd",
            )?;
            Some(
                scm_rights::recv_fd(parent_socket.as_raw_fd())
                    .map_err(|e| ExecutorError::SeccompNotify(e.to_string()))?,
            )
        } else {
            None
        };

        blocking_parent(child_pid, pidfd, notify_fd, workspace, plan)
    }

    /// Spawn a new sandbox. Returns immediately with a [`SandboxId`].
    pub fn spawn(&mut self, plan: Plan) -> Result<SandboxId, ExecutorError> {
        let id = SandboxId(self.next_id);
        self.next_id += 1;

        let timeout = plan.timeout;
        let max_output = plan.max_output;

        let spawned = spawn_sandbox(plan)?;

        // Register with mio
        let pidfd_token = encode_token(id.0, TOKEN_TYPE_PIDFD);
        let stdout_token = encode_token(id.0, TOKEN_TYPE_STDOUT);
        let stderr_token = encode_token(id.0, TOKEN_TYPE_STDERR);

        self.poll.registry().register(
            &mut SourceFd(&spawned.pidfd.as_raw_fd()),
            pidfd_token,
            Interest::READABLE,
        )?;
        self.poll.registry().register(
            &mut SourceFd(&spawned.stdout_fd),
            stdout_token,
            Interest::READABLE,
        )?;
        self.poll.registry().register(
            &mut SourceFd(&spawned.stderr_fd),
            stderr_token,
            Interest::READABLE,
        )?;

        let state = SandboxState {
            spawned,
            deadline: Instant::now() + timeout,
            start: Instant::now(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            max_output,
            pidfd_ready: false,
            stdout_closed: false,
            stderr_closed: false,
        };

        self.sandboxes.insert(id, state);
        Ok(id)
    }

    /// Poll for events. Blocks until events are available or timeout expires.
    pub fn poll(&mut self, events: &mut Vec<Event>, timeout: Option<Duration>) -> io::Result<()> {
        events.clear();

        if self.sandboxes.is_empty() {
            return Ok(());
        }

        let effective_timeout = self.calculate_timeout(timeout);
        self.poll.poll(&mut self.mio_events, effective_timeout)?;

        let mut pidfd_ready: Vec<SandboxId> = Vec::new();
        let mut read_stdout: Vec<SandboxId> = Vec::new();
        let mut read_stderr: Vec<SandboxId> = Vec::new();

        for mio_event in &self.mio_events {
            let (sandbox_id, token_type) = decode_token(mio_event.token());
            if self.sandboxes.contains_key(&sandbox_id) {
                match token_type {
                    TOKEN_TYPE_PIDFD => pidfd_ready.push(sandbox_id),
                    TOKEN_TYPE_STDOUT => read_stdout.push(sandbox_id),
                    TOKEN_TYPE_STDERR => read_stderr.push(sandbox_id),
                    _ => {}
                }
            }
        }

        for id in pidfd_ready {
            if let Some(state) = self.sandboxes.get_mut(&id) {
                state.pidfd_ready = true;
            }
        }

        for id in read_stdout {
            self.read_pipe(id, true, events);
        }

        for id in read_stderr {
            self.read_pipe(id, false, events);
        }

        self.check_completions(events)?;
        Ok(())
    }

    pub fn active_count(&self) -> usize {
        self.sandboxes.len()
    }

    pub fn kill(&mut self, id: SandboxId) -> io::Result<()> {
        if let Some(state) = self.sandboxes.get(&id) {
            pidfd_send_signal(&state.spawned.pidfd, Signal::KILL)?;
        }
        Ok(())
    }

    /// Write data to a sandbox's stdin.
    pub fn write_stdin(&mut self, id: SandboxId, data: &[u8]) -> io::Result<usize> {
        if let Some(state) = self.sandboxes.get(&id) {
            let fd = state.spawned.stdin_fd;
            if fd < 0 {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stdin closed"));
            }
            let ret = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
            if ret < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(ret as usize)
            }
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "sandbox not found"))
        }
    }

    /// Close a sandbox's stdin (signal EOF).
    pub fn close_stdin(&mut self, id: SandboxId) -> io::Result<()> {
        if let Some(state) = self.sandboxes.get_mut(&id) {
            if state.spawned.stdin_fd >= 0 {
                unsafe { libc::close(state.spawned.stdin_fd) };
                state.spawned.stdin_fd = -1;
            }
        }
        Ok(())
    }

    fn calculate_timeout(&self, user_timeout: Option<Duration>) -> Option<Duration> {
        let now = Instant::now();
        let nearest_deadline = self.sandboxes.values().map(|s| s.deadline).min();

        match (user_timeout, nearest_deadline) {
            (Some(user), Some(deadline)) => Some(user.min(deadline.saturating_duration_since(now))),
            (Some(user), None) => Some(user),
            (None, Some(deadline)) => Some(deadline.saturating_duration_since(now)),
            (None, None) => None,
        }
    }

    fn read_pipe(&mut self, sandbox_id: SandboxId, is_stdout: bool, events: &mut Vec<Event>) {
        let Some(state) = self.sandboxes.get_mut(&sandbox_id) else {
            return;
        };

        let fd = if is_stdout {
            state.spawned.stdout_fd
        } else {
            state.spawned.stderr_fd
        };

        let mut buf = [0u8; 4096];
        loop {
            let ret = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };

            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    break;
                }
                if is_stdout {
                    state.stdout_closed = true;
                } else {
                    state.stderr_closed = true;
                }
                break;
            } else if ret == 0 {
                if is_stdout {
                    state.stdout_closed = true;
                } else {
                    state.stderr_closed = true;
                }
                break;
            } else {
                let n = ret as usize;
                let data = buf[..n].to_vec();

                if is_stdout {
                    state.stdout.extend_from_slice(&data);
                    events.push(Event::Stdout {
                        id: sandbox_id,
                        data,
                    });
                } else {
                    state.stderr.extend_from_slice(&data);
                    events.push(Event::Stderr {
                        id: sandbox_id,
                        data,
                    });
                }

                let total = state.stdout.len() + state.stderr.len();
                if total > state.max_output as usize {
                    pidfd_send_signal(&state.spawned.pidfd, Signal::KILL).ok();
                    break;
                }
            }
        }
    }

    fn check_completions(&mut self, events: &mut Vec<Event>) -> io::Result<()> {
        let now = Instant::now();
        let mut to_remove = Vec::new();

        for (&id, state) in &mut self.sandboxes {
            if now >= state.deadline && !state.pidfd_ready {
                pidfd_send_signal(&state.spawned.pidfd, Signal::KILL).ok();
                state.pidfd_ready = true;
            }
            if state.is_done() {
                to_remove.push(id);
            }
        }

        for id in to_remove {
            if let Some(state) = self.sandboxes.remove(&id) {
                self.poll
                    .registry()
                    .deregister(&mut SourceFd(&state.spawned.pidfd.as_raw_fd()))
                    .ok();
                self.poll
                    .registry()
                    .deregister(&mut SourceFd(&state.spawned.stdout_fd))
                    .ok();
                self.poll
                    .registry()
                    .deregister(&mut SourceFd(&state.spawned.stderr_fd))
                    .ok();

                let (exit_code, signal) = wait_for_exit(state.spawned.pidfd.as_raw_fd())?;
                let duration = state.start.elapsed();
                let timed_out = Instant::now() >= state.deadline;

                let status = if timed_out {
                    Status::Timeout
                } else if signal.is_some() {
                    Status::Signaled
                } else if state.stdout.len() + state.stderr.len() > state.max_output as usize {
                    Status::OutputLimitExceeded
                } else {
                    Status::Exited
                };

                let output = Output {
                    stdout: state.stdout,
                    stderr: state.stderr,
                    status,
                    duration,
                    exit_code,
                    signal,
                };

                if timed_out {
                    events.push(Event::Timeout { id, output });
                } else {
                    events.push(Event::Completed { id, output });
                }
            }
        }

        Ok(())
    }
}

/// Close the parent-side pipe ends that the child uses (stdin read, stdout write, stderr write).
fn close_parent_pipe_ends(workspace: &Workspace) {
    unsafe {
        libc::close(workspace.pipes.stdin.read.as_raw_fd());
        libc::close(workspace.pipes.stdout.write.as_raw_fd());
        libc::close(workspace.pipes.stderr.write.as_raw_fd());
    }
}

/// Poll an fd with a 30-second timeout; kill the child on timeout or error.
fn poll_or_kill(fd: RawFd, child_pid: libc::pid_t, msg: &str) -> Result<(), ExecutorError> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut pfd, 1, 30000) } <= 0 {
        unsafe { libc::kill(child_pid, libc::SIGKILL) };
        return Err(ExecutorError::ChildSetup(msg.into()));
    }
    Ok(())
}

/// Wait for the child to signal readiness via eventfd, then signal back.
fn sync_with_child(workspace: &Workspace, child_pid: libc::pid_t) -> Result<(), ExecutorError> {
    let child_ready_fd = workspace.pipes.sync.child_ready_fd();
    poll_or_kill(child_ready_fd, child_pid, "timeout waiting for child")?;

    let mut value: u64 = 0;
    if unsafe { libc::read(child_ready_fd, (&mut value as *mut u64).cast(), 8) } != 8 {
        unsafe { libc::kill(child_pid, libc::SIGKILL) };
        return Err(ExecutorError::ChildSetup("eventfd read failed".into()));
    }

    let parent_done_fd = workspace.pipes.sync.parent_done_fd();
    let signal_value: u64 = 1;
    if unsafe { libc::write(parent_done_fd, (&signal_value as *const u64).cast(), 8) } != 8 {
        unsafe { libc::kill(child_pid, libc::SIGKILL) };
        return Err(ExecutorError::ChildSetup("eventfd write failed".into()));
    }

    Ok(())
}

fn spawn_sandbox(plan: Plan) -> Result<SpawnedSandbox, ExecutorError> {
    let cmd_refs: Vec<&str> = plan.cmd.iter().map(|s| s.as_str()).collect();
    validate_cmd(&cmd_refs).map_err(ExecutorError::Validation)?;

    if let Err(e) = check::check() {
        return Err(ExecutorError::SystemCheck(e.to_string()));
    }

    let exec_info = if let Some(info) = ExecutionInfo::from_plan(&plan) {
        info
    } else {
        let resolved = resolve_binary(&plan.cmd[0])
            .map_err(|e| ExecutorError::CommandNotFound(e.to_string()))?;
        ExecutionInfo::from_resolved(resolved)
    };

    let workspace = Workspace::with_prefix("evalbox-").map_err(ExecutorError::Workspace)?;

    workspace
        .setup_sandbox_dirs()
        .map_err(ExecutorError::Workspace)?;
    for file in &plan.user_files {
        let work_path = format!("work/{}", file.path);
        workspace
            .write_file(&work_path, &file.content, file.executable)
            .map_err(ExecutorError::Workspace)?;
    }

    // Create socketpair for notify fd transfer (if needed)
    let notify_sockets = if plan.notify_mode != NotifyMode::Disabled {
        Some(scm_rights::create_socketpair().map_err(ExecutorError::Workspace)?)
    } else {
        None
    };

    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(ExecutorError::Fork(last_errno()));
    }

    if child_pid == 0 {
        let child_socket = notify_sockets.map(|(_, child)| child);
        match child_process(&workspace, &plan, &exec_info, child_socket.as_ref()) {
            Ok(()) => unsafe { libc::_exit(127) },
            Err(e) => {
                writeln!(io::stderr(), "sandbox error: {e}").ok();
                unsafe { libc::_exit(126) }
            }
        }
    }

    let pid = unsafe { Pid::from_raw_unchecked(child_pid) };
    let pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(ExecutorError::Pidfd)?;

    let stdin_write_fd = workspace.pipes.stdin.write.as_raw_fd();
    let stdout_read_fd = workspace.pipes.stdout.read.as_raw_fd();
    let stderr_read_fd = workspace.pipes.stderr.read.as_raw_fd();

    close_parent_pipe_ends(&workspace);

    // Receive notify fd from child if applicable
    let notify_fd = if let Some((parent_socket, _)) = notify_sockets {
        poll_or_kill(
            parent_socket.as_raw_fd(),
            child_pid,
            "timeout waiting for notify fd",
        )?;
        Some(
            scm_rights::recv_fd(parent_socket.as_raw_fd())
                .map_err(|e| ExecutorError::SeccompNotify(e.to_string()))?,
        )
    } else {
        None
    };

    sync_with_child(&workspace, child_pid)?;

    // Write stdin if provided
    if let Some(ref stdin_data) = plan.stdin {
        write_stdin(&workspace, stdin_data).map_err(ExecutorError::Monitor)?;
        unsafe { libc::close(stdin_write_fd) };
    }

    // Set non-blocking for async reading
    set_nonblocking(stdout_read_fd).map_err(ExecutorError::Monitor)?;
    set_nonblocking(stderr_read_fd).map_err(ExecutorError::Monitor)?;

    // Close sync fds
    unsafe {
        libc::close(workspace.pipes.sync.child_ready_fd());
        libc::close(workspace.pipes.sync.parent_done_fd());
    }

    Ok(SpawnedSandbox {
        pidfd,
        stdin_fd: if plan.stdin.is_some() {
            -1
        } else {
            stdin_write_fd
        },
        stdout_fd: stdout_read_fd,
        stderr_fd: stderr_read_fd,
        notify_fd,
        workspace: std::mem::ManuallyDrop::new(workspace),
    })
}

fn blocking_parent(
    child_pid: libc::pid_t,
    pidfd: OwnedFd,
    _notify_fd: Option<OwnedFd>,
    workspace: Workspace,
    plan: Plan,
) -> Result<Output, ExecutorError> {
    let workspace = std::mem::ManuallyDrop::new(workspace);

    close_parent_pipe_ends(&workspace);

    sync_with_child(&workspace, child_pid)?;

    if let Some(ref stdin_data) = plan.stdin {
        write_stdin(&workspace, stdin_data).map_err(ExecutorError::Monitor)?;
    }
    unsafe { libc::close(workspace.pipes.stdin.write.as_raw_fd()) };

    let result = monitor(pidfd, &workspace, &plan).map_err(ExecutorError::Monitor);

    unsafe {
        libc::close(workspace.pipes.stdout.read.as_raw_fd());
        libc::close(workspace.pipes.stderr.read.as_raw_fd());
        libc::close(workspace.pipes.sync.child_ready_fd());
        libc::close(workspace.pipes.sync.parent_done_fd());
    }

    result
}

/// Child process flow (runs after fork in the child).
///
/// 1. Close parent pipe ends
/// 2. Setup stdio (dup2 stdin/stdout/stderr)
/// 3. chdir(workspace/work)
/// 4. Landlock v5 + rlimits + securebits + drop caps (lockdown)
/// 5. If `notify_mode` != Disabled: install notify filter, send listener fd
/// 6. Install kill seccomp filter (whitelist)
/// 7. Signal parent readiness
/// 8. Wait for parent signal
/// 9. `close_range(3, MAX, 0)`
/// 10. execve
fn child_process(
    workspace: &Workspace,
    plan: &Plan,
    exec_info: &ExecutionInfo,
    notify_socket: Option<&OwnedFd>,
) -> Result<(), ExecutorError> {
    // 1. Close parent pipe ends
    unsafe {
        libc::close(workspace.pipes.stdin.write.as_raw_fd());
        libc::close(workspace.pipes.stdout.read.as_raw_fd());
        libc::close(workspace.pipes.stderr.read.as_raw_fd());
    }

    // 2. Setup stdio
    setup_stdio(workspace)?;

    // 3. chdir to workspace/work
    let work_dir = workspace.root().join("work");
    let work_cstr =
        CString::new(work_dir.to_string_lossy().as_bytes()).map_err(|_| ExecutorError::Exec(Errno::INVAL))?;
    if unsafe { libc::chdir(work_cstr.as_ptr()) } != 0 {
        return Err(ExecutorError::Exec(last_errno()));
    }

    // 4. Apply lockdown (Landlock v5 + rlimits + securebits + drop caps)
    let extra_paths: Vec<&str> = exec_info
        .extra_mounts
        .iter()
        .filter_map(|m| m.source.to_str())
        .collect();
    lockdown(plan, workspace.root(), &extra_paths).map_err(ExecutorError::Lockdown)?;

    // 5. If notify mode != Disabled: install notify seccomp filter, send listener fd
    if plan.notify_mode != NotifyMode::Disabled {
        let notify_filter = build_notify_filter(NOTIFY_FS_SYSCALLS);
        let fprog = SockFprog {
            len: notify_filter.len() as u16,
            filter: notify_filter.as_ptr(),
        };
        let listener_fd = unsafe { seccomp_set_mode_filter_listener(&fprog) }.map_err(|e| {
            ExecutorError::SeccompNotify(format!("failed to install notify filter: {e}"))
        })?;

        // Send listener fd to parent via SCM_RIGHTS
        if let Some(sock) = notify_socket {
            scm_rights::send_fd(sock.as_raw_fd(), listener_fd.as_raw_fd()).map_err(|e| {
                ExecutorError::SeccompNotify(format!("failed to send listener fd: {e}"))
            })?;
        }
    }

    // 6. Install kill seccomp filter (whitelist)
    apply_seccomp(plan)?;

    // 7. Signal parent readiness
    let child_ready_fd = workspace.pipes.sync.child_ready_fd();
    let signal_value: u64 = 1;
    if unsafe { libc::write(child_ready_fd, (&signal_value as *const u64).cast(), 8) } != 8 {
        return Err(ExecutorError::ChildSetup("eventfd write failed".into()));
    }

    // 8. Wait for parent signal
    let parent_done_fd = workspace.pipes.sync.parent_done_fd();
    let mut value: u64 = 0;
    if unsafe { libc::read(parent_done_fd, (&mut value as *mut u64).cast(), 8) } != 8 {
        return Err(ExecutorError::ChildSetup("eventfd read failed".into()));
    }

    // 9. Close all fds except 0,1,2
    close_extra_fds();

    // 10. execve
    exec_command(plan, exec_info)
}

fn setup_stdio(workspace: &Workspace) -> Result<(), ExecutorError> {
    let stdin_fd = workspace.pipes.stdin.read.as_raw_fd();
    let stdout_fd = workspace.pipes.stdout.write.as_raw_fd();
    let stderr_fd = workspace.pipes.stderr.write.as_raw_fd();

    unsafe {
        libc::close(0);
        libc::close(1);
        libc::close(2);
        if libc::dup2(stdin_fd, 0) < 0 {
            return Err(ExecutorError::Exec(last_errno()));
        }
        if libc::dup2(stdout_fd, 1) < 0 {
            return Err(ExecutorError::Exec(last_errno()));
        }
        if libc::dup2(stderr_fd, 2) < 0 {
            return Err(ExecutorError::Exec(last_errno()));
        }
    }
    Ok(())
}

fn apply_seccomp(plan: &Plan) -> Result<(), ExecutorError> {
    let whitelist: Vec<i64> = if let Some(ref syscalls) = plan.syscalls {
        let mut wl: Vec<i64> = DEFAULT_WHITELIST
            .iter()
            .copied()
            .filter(|s| !syscalls.denied.contains(s))
            .collect();
        for s in &syscalls.allowed {
            if !wl.contains(s) {
                wl.push(*s);
            }
        }
        wl
    } else {
        DEFAULT_WHITELIST.to_vec()
    };

    let filter = build_whitelist_filter(&whitelist);
    let fprog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };
    unsafe { seccomp_set_mode_filter(&fprog) }
        .map_err(|e| ExecutorError::Lockdown(LockdownError::Seccomp(e)))?;
    Ok(())
}

fn exec_command(plan: &Plan, exec_info: &ExecutionInfo) -> Result<(), ExecutorError> {
    let cmd_path = CString::new(exec_info.binary_path.to_string_lossy().as_bytes())
        .map_err(|_| ExecutorError::Exec(Errno::INVAL))?;

    let mut argv: Vec<CString> = Vec::with_capacity(plan.cmd.len());
    argv.push(cmd_path.clone());
    for arg in plan.cmd.iter().skip(1) {
        argv.push(CString::new(arg.as_bytes()).map_err(|_| ExecutorError::Exec(Errno::INVAL))?);
    }

    let argv_ptrs: Vec<*const libc::c_char> = argv
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let envp: Vec<CString> = plan
        .env
        .iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ExecutorError::Exec(Errno::INVAL))?;

    let envp_ptrs: Vec<*const libc::c_char> = envp
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    unsafe { libc::execve(cmd_path.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr()) };

    Err(ExecutorError::Exec(last_errno()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_encoding() {
        let token = encode_token(42, TOKEN_TYPE_STDOUT);
        let (id, ty) = decode_token(token);
        assert_eq!(id.0, 42);
        assert_eq!(ty, TOKEN_TYPE_STDOUT);
    }

    #[test]
    fn sandbox_id_display() {
        let id = SandboxId(123);
        assert_eq!(format!("{id}"), "Sandbox(123)");
    }
}
