//! Mapeamento de erros Rust para exceções Python.

use pyo3::{PyErr, exceptions::*};
use pyenclave_sandbox::Error;

/// Converte Error da sandbox para PyErr
pub fn into_pyerr(err: Error) -> PyErr {
    match err {
        Error::InvalidSpec(msg) => {
            PyValueError::new_err(format!("Invalid specification: {}", msg))
        }
        Error::Preflight(msg) => {
            PyRuntimeError::new_err(format!("Preflight check failed: {}", msg))
        }
        Error::Namespace(e) => {
            PyRuntimeError::new_err(format!("Namespace error: {:#}", e))
        }
        Error::Filesystem(e) => {
            PyRuntimeError::new_err(format!("Filesystem error: {:#}", e))
        }
        Error::Security(e) => {
            PyRuntimeError::new_err(format!("Security policy error: {:#}", e))
        }
        Error::Execution(e) => {
            PyRuntimeError::new_err(format!("Execution error: {:#}", e))
        }
        Error::Io(e) => {
            PyIOError::new_err(format!("I/O error: {}", e))
        }
        Error::Nix(e) => {
            PyOSError::new_err(format!("System call error: {}", e))
        }
    }
}
