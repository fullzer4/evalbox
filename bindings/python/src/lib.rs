//! PyO3 bindings for pyenclave-sandbox.
//!
//! Este módulo expõe a funcionalidade de pyenclave-sandbox para Python.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyenclave_sandbox::{RunSpec, Runtime, probe_host};

mod convert;
mod error;

#[pymodule]
fn _core(_py: Python, m: &PyModule) -> PyResult<()> {
    /// Execute Python code in isolated sandbox.
    /// 
    /// Args:
    ///     spec_dict (dict): Execution specification
    /// 
    /// Returns:
    ///     dict: Execution result with exit_code, stdout, stderr, etc.
    #[pyfn(m)]
    fn run(py: Python, spec_dict: &PyAny) -> PyResult<PyObject> {
        // Convert Python dict → RunSpec
        let spec = convert::py_to_runspec(py, spec_dict)?;
        
        // Execute via sandbox runtime
        let result = Runtime::new(spec)
            .and_then(|rt| rt.execute())
            .map_err(error::into_pyerr)?;
        
        // Convert ExecutionResult → Python dict
        convert::result_to_py(py, result)
    }

    /// Probe host capabilities.
    /// 
    /// Returns:
    ///     dict: Host report with userns, seccomp, landlock, etc.
    #[pyfn(m)]
    fn probe(py: Python) -> PyResult<PyObject> {
        let report = probe_host();
        convert::report_to_py(py, report)
    }

    Ok(())
}
