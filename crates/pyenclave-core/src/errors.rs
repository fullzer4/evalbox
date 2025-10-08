//! Erros tipados e mapeamento para PyErr (skeleton).

#[derive(thiserror::Error, Debug)]
pub enum EnclaveError {
    #[error("preflight failed: {0}")]
    Preflight(String),
    #[error("namespace error: {0}")]
    Namespace(String),
    #[error("mount error: {0}")]
    Mount(String),
    #[error("policy error: {0}")]
    Policy(String),
    #[error("limits error: {0}")]
    Limits(String),
    #[error("exec error: {0}")]
    Exec(String),
}

impl From<EnclaveError> for pyo3::PyErr {
    fn from(e: EnclaveError) -> Self {
        pyo3::exceptions::PyRuntimeError::new_err(e.to_string())
    }
}
