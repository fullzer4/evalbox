//! Worker pool management

use leeward_core::{ExecutionResult, LeewardError, Result, SandboxConfig, worker::{Worker, WorkerState}};
use parking_lot::Mutex;
use std::sync::Arc;

/// Pool of sandbox workers
pub struct WorkerPool {
    workers: Vec<Arc<Mutex<Worker>>>,
    config: SandboxConfig,
}

impl WorkerPool {
    /// Create a new worker pool
    pub fn new(num_workers: usize, config: SandboxConfig) -> Result<Self> {
        let mut workers = Vec::with_capacity(num_workers);

        for id in 0..num_workers {
            let mut worker = Worker::new(id as u32, config.clone());
            worker.spawn()?;
            workers.push(Arc::new(Mutex::new(worker)));
        }

        Ok(Self { workers, config })
    }

    /// Get an idle worker from the pool
    pub fn get_idle(&self) -> Option<Arc<Mutex<Worker>>> {
        for worker in &self.workers {
            let guard = worker.lock();
            if guard.state == WorkerState::Idle {
                drop(guard);
                return Some(Arc::clone(worker));
            }
        }
        None
    }

    /// Execute code using an available worker
    pub async fn execute(&self, code: &str) -> Result<ExecutionResult> {
        // Get idle worker
        let worker = self.get_idle().ok_or_else(|| {
            LeewardError::Execution("no idle workers available".into())
        })?;

        // Execute
        let result = {
            let mut guard = worker.lock();
            guard.execute(code)?
        };

        // Check if worker needs recycling
        {
            let mut guard = worker.lock();
            if guard.should_recycle(100) {
                guard.recycle()?;
            }
        }

        Ok(result)
    }

    /// Get pool status
    pub fn status(&self) -> PoolStatus {
        let mut idle = 0;
        let mut busy = 0;
        let mut recycling = 0;
        let mut dead = 0;

        for worker in &self.workers {
            match worker.lock().state {
                WorkerState::Idle => idle += 1,
                WorkerState::Busy => busy += 1,
                WorkerState::Recycling => recycling += 1,
                WorkerState::Dead => dead += 1,
            }
        }

        PoolStatus {
            total: self.workers.len(),
            idle,
            busy,
            recycling,
            dead,
        }
    }
}

/// Status of the worker pool
#[derive(Debug, Clone)]
pub struct PoolStatus {
    pub total: usize,
    pub idle: usize,
    pub busy: usize,
    pub recycling: usize,
    pub dead: usize,
}
