//! Conversão entre tipos Python e Rust.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyBytes};
use pyenclave_sandbox::{RunSpec, ExecutionResult, probe::HostReport};
use std::collections::HashMap;

/// Converte dict Python para RunSpec Rust
pub fn py_to_runspec(py: Python, spec_dict: &PyAny) -> PyResult<RunSpec> {
    let dict = spec_dict.downcast::<PyDict>()?;
    
    let mut spec = RunSpec::default();
    
    // interpreter
    if let Ok(Some(interp)) = dict.get_item("interpreter") {
        if !interp.is_none() {
            let interp_dict = interp.downcast::<PyDict>()?;
            if let Ok(Some(path)) = interp_dict.get_item("path") {
                spec.interpreter.path = Some(path.extract::<String>()?);
            }
            if let Ok(Some(label)) = interp_dict.get_item("label") {
                spec.interpreter.label = Some(label.extract::<String>()?);
            }
        }
    }
    
    // argv
    if let Ok(Some(argv)) = dict.get_item("argv") {
        let argv_list = argv.downcast::<PyList>()?;
        spec.argv = argv_list.iter()
            .filter_map(|item| item.extract::<String>().ok())
            .collect();
    }
    
    // env
    if let Ok(Some(env)) = dict.get_item("env") {
        let env_dict = env.downcast::<PyDict>()?;
        spec.env = env_dict.iter()
            .filter_map(|(k, v)| {
                let key = k.extract::<String>().ok()?;
                let val = v.extract::<String>().ok()?;
                Some((key, val))
            })
            .collect();
    }
    
    // TODO: mounts, policy, limits, cwd, umask
    
    Ok(spec)
}

/// Converte ExecutionResult para dict Python
pub fn result_to_py(py: Python, result: ExecutionResult) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    
    if let Some(code) = result.exit_code {
        dict.set_item("exit_code", code)?;
    } else {
        dict.set_item("exit_code", py.None())?;
    }
    
    dict.set_item("stdout", PyBytes::new(py, &result.stdout))?;
    dict.set_item("stderr", PyBytes::new(py, &result.stderr))?;
    
    if let Some(sig) = result.signal {
        dict.set_item("signal", sig)?;
    } else {
        dict.set_item("signal", py.None())?;
    }
    
    Ok(dict.into())
}

/// Converte HostReport para dict Python
pub fn report_to_py(py: Python, report: HostReport) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    
    dict.set_item("userns", report.userns)?;
    dict.set_item("seccomp", report.seccomp)?;
    dict.set_item("landlock", report.landlock)?;
    
    if let Some(abi) = report.landlock_abi {
        dict.set_item("landlock_abi", abi)?;
    } else {
        dict.set_item("landlock_abi", py.None())?;
    }
    
    dict.set_item("cgroups_v2", report.cgroups_v2)?;
    
    if let Some(arch) = report.arch {
        dict.set_item("arch", arch)?;
    } else {
        dict.set_item("arch", py.None())?;
    }
    
    if let Some(kernel) = report.kernel {
        dict.set_item("kernel", kernel)?;
    } else {
        dict.set_item("kernel", py.None())?;
    }
    
    Ok(dict.into())
}
