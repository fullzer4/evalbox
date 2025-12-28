//! Sandbox worker process management

use crate::{ExecutionResult, LeewardError, Result, SandboxConfig};

/// State of a worker in the pool
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

/// A sandboxed worker process
#[derive(Debug)]
pub struct Worker {
    /// Unique worker ID
    pub id: u32,
    /// Current state
    pub state: WorkerState,
    /// Process ID (if running)
    pub pid: Option<u32>,
    /// Number of executions completed
    pub execution_count: u64,
    /// Configuration for this worker
    config: SandboxConfig,
}

impl Worker {
    /// Create a new worker with the given config
    pub fn new(id: u32, config: SandboxConfig) -> Self {
        Self {
            id,
            state: WorkerState::Dead,
            pid: None,
            execution_count: 0,
            config,
        }
    }

    /// Spawn the worker process
    pub fn spawn(&mut self) -> Result<()> {
        // TODO: Implement process spawning with isolation
        tracing::info!(worker_id = self.id, "spawning worker");
        self.state = WorkerState::Idle;
        Ok(())
    }

    /// Execute code in this worker
    pub fn execute(&mut self, code: &str) -> Result<ExecutionResult> {
        if self.state != WorkerState::Idle {
            return Err(LeewardError::Execution(format!(
                "worker {} is not idle (state: {:?})",
                self.id, self.state
            )));
        }

        self.state = WorkerState::Busy;
        tracing::debug!(worker_id = self.id, "executing code");

        // TODO: Implement actual execution
        let result = ExecutionResult::default();

        self.execution_count += 1;
        self.state = WorkerState::Idle;

        Ok(result)
    }

    /// Kill and recycle this worker
    pub fn recycle(&mut self) -> Result<()> {
        tracing::info!(worker_id = self.id, "recycling worker");
        self.state = WorkerState::Recycling;

        // TODO: Kill existing process if any

        self.pid = None;
        self.spawn()
    }

    /// Check if worker should be recycled based on execution count
    #[must_use]
    pub fn should_recycle(&self, max_executions: u64) -> bool {
        self.execution_count >= max_executions
    }
}
