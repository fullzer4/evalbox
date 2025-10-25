//! PyO3 bindings: Exposes functions to Python and handles type marshaling.
//!
//! Planned execution pipeline (strict order) for `run`:
//! 1. `unshare` for user, mount, pid, ipc, uts and optionally net namespaces.
//! 2. Setup `uid_map`/`gid_map` with `setgroups` denied.
//! 3. Mount root `tmpfs`, apply RO/RW binds from `MountPlan` and execute `pivot_root`.
//! 4. Mount new `/proc` inside the PID namespace.
//! 5. Apply `PR_SET_NO_NEW_PRIVS = 1` (prerequisite for unprivileged seccomp).
//! 6. Apply `rlimits` and/or attach cgroup v2 according to `LimitSpec`.
//! 7. Apply Landlock rules (filesystem only; network is handled by net namespace
//!    or syscall blocking via seccomp).
//! 8. Load appropriate seccomp filter (fails with `EACCES` if `no_new_privs` is not active).
//! 9. Configure `PR_SET_PDEATHSIG` to kill the tree if supervisor terminates.
//! 10. `execve` target Python with `-I` and sanitized environment (pycache prefix
//!     inside enclave, local caches, etc.).

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::HashMap;

pub mod spec;
pub mod preflight;
pub mod ns;
pub mod fs;
pub mod limits;
pub mod exec;
pub mod telemetry;
pub mod errors;
pub mod policy;

use spec::{RunSpec, InterpreterSpec, MountPlan, PolicySpec, LimitSpec};
use exec::{CommandSpec, execute_command};

fn py_to_runspec(py: Python, spec_dict: &PyAny) -> PyResult<RunSpec> {
    let dict = spec_dict.downcast::<PyDict>()?;
    
    let mut spec = RunSpec::default();
    
    if let Ok(Some(interp)) = dict.get_item("interpreter") {
        if !interp.is_none() {
            let interp_dict = interp.downcast::<PyDict>()?;
            spec.interpreter = InterpreterSpec {
                label: interp_dict.get_item("label")?
                    .filter(|v| !v.is_none())
                    .and_then(|v| v.extract::<String>().ok()),
                path: interp_dict.get_item("path")?
                    .filter(|v| !v.is_none())
                    .and_then(|v| v.extract::<String>().ok()),
            };
        }
    }
    
    if let Ok(Some(argv)) = dict.get_item("argv") {
        let argv_list = argv.downcast::<PyList>()?;
        spec.argv = argv_list.iter()
            .filter_map(|item| item.extract::<String>().ok())
            .collect();
    }
    
    if let Ok(Some(mounts)) = dict.get_item("mounts") {
        let mounts_dict = mounts.downcast::<PyDict>()?;
        
        if let Ok(Some(ro)) = mounts_dict.get_item("ro") {
            let ro_list = ro.downcast::<PyList>()?;
            spec.mounts.ro = ro_list.iter()
                .filter_map(|item| {
                    let tuple = item.downcast::<PyList>().ok()?;
                    if tuple.len() == 2 {
                        let src = tuple.get_item(0).ok()?.extract::<String>().ok()?;
                        let dst = tuple.get_item(1).ok()?.extract::<String>().ok()?;
                        Some((src, dst))
                    } else {
                        None
                    }
                })
                .collect();
        }
        
        if let Ok(Some(rw)) = mounts_dict.get_item("rw") {
            let rw_list = rw.downcast::<PyList>()?;
            spec.mounts.rw = rw_list.iter()
                .filter_map(|item| {
                    let tuple = item.downcast::<PyList>().ok()?;
                    if tuple.len() == 2 {
                        let src = tuple.get_item(0).ok()?.extract::<String>().ok()?;
                        let dst = tuple.get_item(1).ok()?.extract::<String>().ok()?;
                        Some((src, dst))
                    } else {
                        None
                    }
                })
                .collect();
        }
        
        if let Ok(Some(eph_tmp)) = mounts_dict.get_item("ephemeral_tmp") {
            spec.mounts.ephemeral_tmp = eph_tmp.extract::<bool>().unwrap_or(false);
        }
    }
    
    if let Ok(Some(policy)) = dict.get_item("policy") {
        if !policy.is_none() {
            let policy_dict = policy.downcast::<PyDict>()?;
            spec.policy = PolicySpec {
                seccomp_profile: policy_dict.get_item("seccomp_profile")?
                    .filter(|v| !v.is_none())
                    .and_then(|v| v.extract::<String>().ok()),
                landlock: policy_dict.get_item("landlock")?
                    .filter(|v| !v.is_none())
                    .and_then(|v| v.extract::<bool>().ok())
                    .unwrap_or(false),
                network: policy_dict.get_item("network")?
                    .filter(|v| !v.is_none())
                    .and_then(|v| v.extract::<bool>().ok())
                    .unwrap_or(false),
            };
        }
    }
    
    if let Ok(Some(limits)) = dict.get_item("limits") {
        if !limits.is_none() {
            let limits_dict = limits.downcast::<PyDict>()?;
            spec.limits = LimitSpec {
                time_limit_s: limits_dict.get_item("time_limit_s")?
                    .filter(|v| !v.is_none())
                    .and_then(|v| v.extract::<u64>().ok()),
                memory_limit_mb: limits_dict.get_item("memory_limit_mb")?
                    .filter(|v| !v.is_none())
                    .and_then(|v| v.extract::<u64>().ok()),
                max_procs: limits_dict.get_item("max_procs")?
                    .filter(|v| !v.is_none())
                    .and_then(|v| v.extract::<u64>().ok()),
                fsize_mb: limits_dict.get_item("fsize_mb")?
                    .filter(|v| !v.is_none())
                    .and_then(|v| v.extract::<u64>().ok()),
            };
        }
    }
    
    if let Ok(Some(cwd)) = dict.get_item("cwd") {
        if !cwd.is_none() {
            spec.cwd = Some(cwd.extract::<String>()?);
        }
    }
    
    if let Ok(Some(umask)) = dict.get_item("umask") {
        if !umask.is_none() {
            spec.umask = Some(umask.extract::<u32>()?);
        }
    }
    
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
    
    Ok(spec)
}

fn exec_result_to_py(py: Python, result: exec::ExecutionResult) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    
    if let Some(code) = result.exit_code {
        dict.set_item("exit_code", code)?;
    } else {
        dict.set_item("exit_code", py.None())?;
    }
    
    dict.set_item("stdout", pyo3::types::PyBytes::new(py, &result.stdout))?;
    dict.set_item("stderr", pyo3::types::PyBytes::new(py, &result.stderr))?;
    
    if let Some(sig) = result.signal {
        dict.set_item("signal", sig)?;
    } else {
        dict.set_item("signal", py.None())?;
    }
    
    Ok(dict.into())
}

fn host_report_to_py(py: Python, report: preflight::HostReport) -> PyResult<PyObject> {
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

fn run_simple_command(py: Python, spec: &RunSpec) -> PyResult<PyObject> {
    let executable = spec.interpreter.path.as_ref()
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("interpreter.path is required"))?;
    
    let mut env = HashMap::new();
    for (k, v) in &spec.env {
        env.insert(k.clone(), v.clone());
    }
    
    let cmd_spec = CommandSpec {
        executable: executable.clone(),
        args: spec.argv.clone(),
        env,
        cwd: spec.cwd.clone(),
    };
    
    let result = execute_command(&cmd_spec)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    
    exec_result_to_py(py, result)
}

#[pymodule]
fn _core(_py: Python, m: &PyModule) -> PyResult<()> {
    /// Executes a Python job in an enclave.
    /// 
    /// Args:
    ///     spec (dict): Execution specification with fields:
    ///         - interpreter: dict with 'label' and 'path'
    ///         - argv: list of arguments
    ///         - mounts: dict with 'ro', 'rw', 'ephemeral_tmp'
    ///         - policy: dict with 'seccomp_profile', 'landlock', 'network'
    ///         - limits: dict with 'time_limit_s', 'memory_limit_mb', etc.
    ///         - cwd: working directory (optional)
    ///         - umask: umask (optional)
    ///         - env: dict of environment variables
    /// 
    /// Returns:
    ///     dict: Result with 'exit_code', 'stdout', 'stderr', 'signal'
    #[pyfn(m)]
    fn run(py: Python, spec_dict: &PyAny) -> PyResult<PyObject> {
        let spec = py_to_runspec(py, spec_dict)?;
        
        // For now, execute simple command
        // TODO: Implement full pipeline with namespaces, seccomp, landlock, etc.
        run_simple_command(py, &spec)
    }

    /// Probes host capabilities (userns, seccomp, landlock, cgroups).
    /// 
    /// Returns:
    ///     dict: Report with fields:
    ///         - userns: bool
    ///         - seccomp: bool
    ///         - landlock: bool
    ///         - landlock_abi: int or None
    ///         - cgroups_v2: bool
    ///         - arch: str
    ///         - kernel: str
    #[pyfn(m)]
    fn probe(py: Python) -> PyResult<PyObject> {
        let report = preflight::probe_host();
        host_report_to_py(py, report)
    }

    Ok(())
}
