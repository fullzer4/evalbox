use crate::{pipe::ParentPipe, ExecutionResult, LeewardError, Result, SandboxConfig};
use std::os::unix::io::RawFd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    /// Ready to accept work
    Idle,
    /// Currently executing code
    Busy,
    /// Being recycled (killed and respawned)
    Recycling,
    /// Dead/failed
    Dead,
}

#[derive(Debug)]
pub struct Worker {
    pub id: u32,
    pub state: WorkerState,
    pub pid: Option<i32>,
    pub execution_count: u64,
    config: SandboxConfig,
    pipe: Option<ParentPipe>,
    /// Cgroup file descriptor (for CLONE_INTO_CGROUP)
    cgroup_fd: Option<RawFd>,
}

impl Worker {
    pub fn new(id: u32, config: SandboxConfig) -> Self {
        Self {
            id,
            state: WorkerState::Dead,
            pid: None,
            execution_count: 0,
            config,
            pipe: None,
            cgroup_fd: None,
        }
    }

    pub fn spawn(&mut self) -> Result<()> {
        use crate::isolation::{clone3, CgroupsConfig};
        use crate::pipe::WorkerPipe;

        tracing::info!(worker_id = self.id, "spawning pre-forked worker");

        // Try to create cgroup for this worker (optional - continue if it fails)
        let cgroup_fd = if self.config.memory_limit > 0 || self.config.cpu_limit < 100 {
            let cgroup_config = CgroupsConfig {
                memory_max: self.config.memory_limit,
                cpu_percent: self.config.cpu_limit,
                pids_max: self.config.max_pids,
                allow_swap: false,
            };

            match cgroup_config.create_cgroup(&format!("worker-{}", self.id)) {
                Ok(cgroup_handle) => {
                    let fd = cgroup_handle.as_raw_fd().unwrap_or(-1);
                    // Store cgroup handle (we'll leak it for now, proper cleanup later)
                    std::mem::forget(cgroup_handle);
                    tracing::info!("cgroups enabled for worker {}", self.id);
                    fd
                }
                Err(e) => {
                    tracing::warn!("cgroups not available (running without root?): {}", e);
                    -1
                }
            }
        } else {
            -1
        };

        self.cgroup_fd = Some(cgroup_fd);

        // Create pipes for communication
        let worker_pipe = WorkerPipe::new()?;
        let (parent_pipe, child_pipe) = worker_pipe.split();

        // Get namespace flags (but don't include them in clone3, we'll set them inside)
        let namespace_flags = 0; // We'll enter namespaces from inside the worker
        let config = self.config.clone();

        let pid = clone3::clone_worker(cgroup_fd, namespace_flags, move || {
            worker_main(child_pipe, &config)
        })?;

        self.pid = Some(pid);
        self.pipe = Some(parent_pipe);
        self.state = WorkerState::Idle;

        tracing::info!(
            worker_id = self.id,
            pid = pid,
            "worker spawned and ready with cgroup"
        );

        Ok(())
    }

    pub fn execute(&mut self, code: &str) -> Result<ExecutionResult> {
        if self.state != WorkerState::Idle {
            return Err(LeewardError::Execution(format!(
                "worker {} is not idle (state: {:?})",
                self.id, self.state
            )));
        }

        let pipe = self
            .pipe
            .as_mut()
            .ok_or_else(|| LeewardError::Execution("worker pipe not initialized".into()))?;

        self.state = WorkerState::Busy;
        tracing::debug!(worker_id = self.id, code_len = code.len(), "sending code to worker");

        pipe.send_code(code.as_bytes())?;
        let result_bytes = pipe.recv_result()?;

        // MessagePack deserialization
        let result: ExecutionResult = rmp_serde::from_slice(&result_bytes)
            .map_err(|e| LeewardError::Execution(format!("failed to deserialize result: {}", e)))?;

        self.execution_count += 1;
        self.state = WorkerState::Idle;

        tracing::debug!(
            worker_id = self.id,
            execution_count = self.execution_count,
            "execution completed"
        );

        Ok(result)
    }

    pub fn recycle(&mut self) -> Result<()> {
        tracing::info!(worker_id = self.id, "recycling worker");
        self.state = WorkerState::Recycling;

        if let Some(pid) = self.pid {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }

        self.pipe = None;
        self.pid = None;
        self.execution_count = 0;

        self.spawn()
    }

    #[must_use]
    pub fn should_recycle(&self, max_executions: u64) -> bool {
        self.execution_count >= max_executions
    }

    fn config_to_namespace_flags(&self) -> u64 {
        use nix::sched::CloneFlags;

        let mut flags = CloneFlags::CLONE_NEWUSER
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWIPC
            | CloneFlags::CLONE_NEWUTS;

        if !self.config.allow_network {
            flags |= CloneFlags::CLONE_NEWNET;
        }

        flags.bits() as u64
    }
}

fn worker_main(mut pipe: crate::pipe::ChildPipe, config: &SandboxConfig) -> Result<()> {
    use crate::isolation::{LandlockConfig, SeccompConfig, NamespaceConfig};

    tracing::debug!("worker process starting isolation setup");

    // Step 1: Setup namespaces (critical for security)
    let namespace_config = NamespaceConfig {
        user: false,  // User namespace needs UID mapping setup
        pid: true,    // Isolate process tree
        mount: true,  // Isolate filesystem
        net: !config.allow_network,  // Network isolation
        ipc: true,    // IPC isolation
        uts: true,    // Hostname isolation
    };

    namespace_config.enter()?;
    tracing::info!("namespaces configured");

    // Step 2: Apply Landlock filesystem restrictions (if available)
    // Landlock requires Linux 5.13+, but that's okay - we try it
    let mut landlock = LandlockConfig::default();

    // Add Python path and libraries as executable
    if let Some(python_dir) = config.python_path.parent() {
        landlock = landlock.exec(python_dir).ro(python_dir);
    }

    // Add read-only paths
    for path in &config.ro_binds {
        landlock = landlock.ro(path);
    }

    // Add read-write paths
    for path in &config.rw_binds {
        landlock = landlock.rw(path);
    }

    // Add /tmp as read-write
    landlock = landlock.rw("/tmp");

    match landlock.apply() {
        Ok(_) => tracing::info!("landlock restrictions applied"),
        Err(e) => {
            // Landlock is nice to have but not critical if we have seccomp + namespaces
            tracing::warn!("landlock not available (kernel < 5.13?): {}", e);
        }
    }

    // Step 3: Apply seccomp filter (critical for security)
    let seccomp = SeccompConfig::default();
    seccomp.apply()?;
    tracing::info!("seccomp filter applied");

    tracing::info!("worker fully isolated, entering main loop");

    // Main worker loop
    loop {
        let code = match pipe.recv_code() {
            Ok(code) => code,
            Err(e) => {
                tracing::error!("failed to receive code: {}", e);
                break;
            }
        };

        let exec_result = execute_python(&code, config);

        let result_bytes = match rmp_serde::to_vec(&exec_result) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!("failed to serialize result: {}", e);
                break;
            }
        };

        if let Err(e) = pipe.send_result(&result_bytes) {
            tracing::error!("failed to send result: {}", e);
            break;
        }
    }

    Ok(())
}

fn execute_python(code: &[u8], config: &SandboxConfig) -> ExecutionResult {
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let code_str = String::from_utf8_lossy(code);
    let start = Instant::now();

    let output = match Command::new(&config.python_path)
        .arg("-c")
        .arg(code_str.as_ref())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            return ExecutionResult {
                exit_code: -1,
                stdout: Vec::new(),
                stderr: format!("Failed to execute Python: {}", e).into_bytes(),
                duration: start.elapsed(),
                memory_peak: 0,
                cpu_time_us: 0,
                timed_out: false,
                oom_killed: false,
            };
        }
    };

    let duration = start.elapsed();

    ExecutionResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: output.stdout,
        stderr: output.stderr,
        duration,
        memory_peak: 0,  // TODO: Get from cgroup memory.peak
        cpu_time_us: 0,  // TODO: Get from /proc/[pid]/stat
        timed_out: false, // TODO: Implement timeout handling
        oom_killed: false, // TODO: Detect from cgroup events
    }
}
