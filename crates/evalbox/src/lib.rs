//! evalbox: Unprivileged sandbox for arbitrary code execution.
//!
//! Execute untrusted code safely on Linux without containers, VMs, or root privileges.
//!
//! ## Features
//!
//! - **Unprivileged**: Uses user namespaces, no root required
//! - **Secure**: Multiple isolation layers (namespaces, Landlock, seccomp, rlimits)
//! - **Fast**: No VM or container startup overhead
//! - **Simple**: Single function call to run sandboxed code
//!
//! ## Quick Start
//!
//! ```ignore
//! use evalbox::{python, go, shell};
//! use std::time::Duration;
//!
//! // Python execution
//! let output = python::run("print('hello')")?;
//!
//! // Go execution (auto-wraps into main())
//! let output = go::run(r#"fmt.Println("hello")"#)?;
//!
//! // Shell execution
//! let output = shell::run("echo hello && pwd")?;
//!
//! // With options
//! let output = python::run("import requests")
//!     .timeout(Duration::from_secs(30))
//!     .network(true)?;
//! ```
//!
//! ## Concurrent Execution
//!
//! ```ignore
//! use evalbox::{python, Session, Event};
//!
//! let mut session = Session::new()?;
//! let id1 = session.spawn(python::run("code1"))?;
//! let id2 = session.spawn(python::run("code2"))?;
//!
//! loop {
//!     for event in session.poll()? {
//!         match event {
//!             Event::Completed { id, output } => println!("{}: done", id),
//!             Event::Timeout { id } => println!("{}: timeout", id),
//!             _ => {}
//!         }
//!     }
//!     if session.is_empty() { break; }
//! }
//! ```
//!
//! ## API Tiers
//!
//! | Tier | API | Use Case |
//! |------|-----|----------|
//! | 1 | `python::run()`, `go::run()`, `shell::run()` | Simple one-shot execution |
//! | 2 | `.timeout()`, `.network()`, `.with()` | Execution with options |
//! | 3 | `Session`, `Event` | Concurrent execution |
//! | 4 | `evalbox_sandbox::Plan` | Full control (power users) |
//!
//! ## Requirements
//!
//! - Linux kernel 5.13+ (for Landlock)
//! - User namespaces enabled
//! - Seccomp enabled

// Internal modules
mod detect;
mod error;
mod output;
mod probe;
mod session;

#[cfg(any(feature = "python", feature = "go"))]
mod probe_cache;

// Runtime implementations
#[cfg(feature = "python")]
pub mod python;

#[cfg(feature = "go")]
pub mod go;

#[cfg(feature = "shell")]
pub mod shell;

// Public API - Core types
pub use error::{Error, ProbeError, Result};
pub use output::{Output, Status};
pub use session::Session;

// Re-export from evalbox-sandbox for convenience
pub use evalbox_sandbox::{
    Event, Executor, ExecutorError, Mount, Plan, SandboxId,
};

// Also re-export advanced types for power users
pub use evalbox_sandbox::{Landlock, Syscalls, UserFile};

// Probe infrastructure (for internal use and extension)
pub use probe::{Probe, RuntimeInfo};

#[cfg(any(feature = "python", feature = "go"))]
pub use probe_cache::ProbeCache;

#[cfg(feature = "go")]
pub use go::wrap::{wrap_go_code, AUTO_IMPORTS};

#[cfg(feature = "go")]
pub use go::GoProbe;

#[cfg(feature = "python")]
pub use python::PythonProbe;
