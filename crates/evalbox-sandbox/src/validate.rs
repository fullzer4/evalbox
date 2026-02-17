//! Input validation for sandbox execution.
//!
//! Validates user input before sandbox execution to prevent:
//!
//! - **Empty commands** - Would cause exec to fail
//! - **Null bytes** - Could cause string truncation attacks
//! - **Path traversal** - `../` could escape workspace
//! - **Absolute paths** - Could reference host filesystem
//!
//! ## Example
//!
//! ```ignore
//! use evalbox_sandbox::validate::{validate_cmd, validate_path};
//!
//! // Valid inputs
//! assert!(validate_cmd(&["echo", "hello"]).is_ok());
//! assert!(validate_path("main.py").is_ok());
//!
//! // Invalid inputs
//! assert!(validate_cmd(&[]).is_err());           // Empty command
//! assert!(validate_path("../etc/passwd").is_err()); // Path traversal
//! assert!(validate_path("/etc/passwd").is_err());   // Absolute path
//! ```

use std::path::Path;

use thiserror::Error;

/// Validation error for sandbox inputs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("command cannot be empty")]
    EmptyCommand,

    #[error("argument {0} is empty")]
    EmptyArgument(usize),

    #[error("null byte in input")]
    NullByte,

    #[error("path traversal not allowed")]
    PathTraversal,

    #[error("absolute path not allowed")]
    AbsolutePath,

    #[error("path cannot be empty")]
    EmptyPath,
}

/// Validate command and arguments.
pub fn validate_cmd(cmd: &[&str]) -> Result<(), ValidationError> {
    if cmd.is_empty() {
        return Err(ValidationError::EmptyCommand);
    }
    for (i, arg) in cmd.iter().enumerate() {
        if arg.is_empty() {
            return Err(ValidationError::EmptyArgument(i));
        }
        if arg.contains('\0') {
            return Err(ValidationError::NullByte);
        }
    }
    Ok(())
}

/// Validate a relative path (no `..`, no absolute).
pub fn validate_path(path: &str) -> Result<(), ValidationError> {
    if path.is_empty() {
        return Err(ValidationError::EmptyPath);
    }
    if path.contains('\0') {
        return Err(ValidationError::NullByte);
    }
    if path.starts_with('/') {
        return Err(ValidationError::AbsolutePath);
    }
    if has_traversal(path) {
        return Err(ValidationError::PathTraversal);
    }
    Ok(())
}

fn has_traversal(path: &str) -> bool {
    Path::new(path)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_valid() {
        assert!(validate_cmd(&["echo", "hello"]).is_ok());
    }

    #[test]
    fn cmd_empty() {
        assert_eq!(validate_cmd(&[]), Err(ValidationError::EmptyCommand));
    }

    #[test]
    fn path_traversal() {
        assert_eq!(
            validate_path("../etc/passwd"),
            Err(ValidationError::PathTraversal)
        );
    }

    #[test]
    fn path_absolute() {
        assert_eq!(
            validate_path("/etc/passwd"),
            Err(ValidationError::AbsolutePath)
        );
    }
}
