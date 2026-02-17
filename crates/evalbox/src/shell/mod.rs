//! Shell execution in sandbox.
//!
//! Execute shell scripts with simple, fluent API.
//!
//! ## Example
//!
//! ```ignore
//! use evalbox::shell;
//!
//! // Simple execution
//! let output = shell::run("echo hello")?;
//! assert_eq!(output.stdout_str().trim(), "hello");
//!
//! // With options
//! let output = shell::run("cat /data/file")
//!     .with("/host/data", "/data")
//!     .timeout(Duration::from_secs(10))?;
//!
//! // With network access
//! let output = shell::run("curl https://example.com")
//!     .network(true)?;
//! ```

mod builder;

pub use builder::ShellBuilder;

use crate::error::Result;
use crate::output::Output;

/// Run a shell script with default settings.
///
/// Returns a `ShellBuilder` that can be customized with `.timeout()`, `.network()`, etc.
/// The builder implements `Try` so using `?` will execute and return the result.
///
/// # Example
///
/// ```ignore
/// // Simple execution
/// let output = shell::run("echo hello")?;
///
/// // With options
/// let output = shell::run("echo hello")
///     .timeout(Duration::from_secs(5))
///     .network(true)?;
/// ```
pub fn run(script: &str) -> ShellBuilder {
    ShellBuilder::new(script)
}

/// Run a shell script and wait for completion (blocking).
///
/// This is a convenience function that immediately executes the script.
pub fn exec(script: &str) -> Result<Output> {
    run(script).exec()
}
