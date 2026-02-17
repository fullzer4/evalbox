//! Security isolation tests for evalbox-sandbox.
//!
//! These tests verify that the sandbox correctly isolates processes and
//! blocks dangerous operations. Most tests require user namespace permissions.
//!
//! ## Running Tests
//!
//! ```bash
//! # Build first (compiles C payloads)
//! cargo build -p evalbox-sandbox
//!
//! # Run unit tests (no special permissions)
//! cargo test -p evalbox-sandbox
//!
//! # Run security tests (require user namespaces)
//! cargo test -p evalbox-sandbox --test security_tests --ignored
//!
//! # Run specific test with output
//! cargo test -p evalbox-sandbox --test security_tests test_ptrace_blocked --ignored -- --nocapture
//! ```
//!
//! ## Test Categories
//!
//! - **seccomp**: Verify dangerous syscalls are blocked (ptrace, mount, reboot)
//! - **filesystem**: Verify filesystem isolation (/etc/shadow, /root not accessible)
//! - **network**: Verify network is blocked by default
//! - **resources**: Verify limits work (timeout, memory, pids, output)
//! - **cve**: Verify real-world CVE attack vectors are blocked

mod common;

#[path = "security/seccomp.rs"]
mod seccomp;

#[path = "security/filesystem.rs"]
mod filesystem;

#[path = "security/network.rs"]
mod network;

#[path = "security/resources.rs"]
mod resources;

#[path = "security/cve.rs"]
mod cve;
