//! High-level concurrent execution session.
//!
//! `Session` provides a user-friendly API for concurrent sandbox execution,
//! wrapping the low-level `Executor` from evalbox-sandbox.
//!
//! ## Example
//!
//! ```ignore
//! use evalbox::Session;
//!
//! let mut session = Session::new()?;
//!
//! // Spawn multiple tasks
//! let id1 = session.spawn_cmd(["echo", "hello"])?;
//! let id2 = session.spawn_cmd(["echo", "world"])?;
//!
//! // Poll for events
//! loop {
//!     for event in session.poll()? {
//!         match event {
//!             Event::Completed { id, output } => {
//!                 println!("{}: exit {:?}", id, output.exit_code);
//!             }
//!             Event::Timeout { id, .. } => {
//!                 println!("{}: timeout", id);
//!             }
//!             _ => {}
//!         }
//!     }
//!     if session.is_empty() { break; }
//! }
//! ```

use std::io;
use std::time::Duration;

use evalbox_sandbox::{Executor, Plan, SandboxId};

pub use evalbox_sandbox::Event;

use crate::error::Result;

/// A session for concurrent sandbox execution.
///
/// Session wraps the low-level Executor with a more ergonomic API.
pub struct Session {
    executor: Executor,
}

impl Session {
    /// Create a new session.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            executor: Executor::new()?,
        })
    }

    /// Spawn a sandbox from a Plan.
    pub fn spawn(&mut self, plan: Plan) -> Result<SandboxId> {
        let id = self.executor.spawn(plan)?;
        Ok(id)
    }

    /// Spawn a simple command.
    pub fn spawn_cmd<I, S>(&mut self, cmd: I) -> Result<SandboxId>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let plan = Plan::new(cmd);
        self.spawn(plan)
    }

    /// Poll for events, returning immediately if none are available.
    pub fn poll(&mut self) -> io::Result<Vec<Event>> {
        let mut events = Vec::new();
        self.executor.poll(&mut events, Some(Duration::ZERO))?;
        Ok(events)
    }

    /// Poll for events, blocking until at least one is available or timeout expires.
    pub fn poll_blocking(&mut self, timeout: Option<Duration>) -> io::Result<Vec<Event>> {
        let mut events = Vec::new();
        self.executor.poll(&mut events, timeout)?;
        Ok(events)
    }

    /// Get the number of active (running) sandboxes.
    pub fn active_count(&self) -> usize {
        self.executor.active_count()
    }

    /// Check if the session has no active sandboxes.
    pub fn is_empty(&self) -> bool {
        self.active_count() == 0
    }

    /// Kill a running sandbox.
    pub fn kill(&mut self, id: SandboxId) -> io::Result<()> {
        self.executor.kill(id)
    }

    /// Write data to a sandbox's stdin.
    pub fn write_stdin(&mut self, id: SandboxId, data: &[u8]) -> io::Result<usize> {
        self.executor.write_stdin(id, data)
    }

    /// Close a sandbox's stdin (signal EOF).
    pub fn close_stdin(&mut self, id: SandboxId) -> io::Result<()> {
        self.executor.close_stdin(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_new() {
        let session = Session::new();
        assert!(session.is_ok());
    }

    #[test]
    fn test_session_empty_initially() {
        let session = Session::new().unwrap();
        assert!(session.is_empty());
        assert_eq!(session.active_count(), 0);
    }
}
