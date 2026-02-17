//! Python runtime probe and execution.
//!
//! ## Example
//!
//! ```ignore
//! use evalbox::python;
//!
//! // Simple execution
//! let output = python::run("print('hello')").exec()?;
//!
//! // With options
//! let output = python::run("import requests")
//!     .timeout(Duration::from_secs(30))
//!     .network(true)
//!     .exec()?;
//!
//! // With virtualenv
//! let output = python::run("import numpy")
//!     .venv("/path/to/.venv")
//!     .exec()?;
//! ```

mod builder;
mod elf;
mod ldcache;

pub use builder::PythonBuilder;

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::detect::{prefix_dir, resolve_binary, resolve_from_env};
use crate::error::ProbeError;
use crate::probe::{Mount, Probe, RuntimeInfo};

use elf::resolve_shared_libs;

/// Run Python code with default settings.
///
/// Returns a `PythonBuilder` that can be customized with `.timeout()`, `.network()`, etc.
/// Call `.exec()` to execute.
///
/// # Example
///
/// ```ignore
/// // Simple execution
/// let output = python::run("print('hello')").exec()?;
///
/// // With options
/// let output = python::run("print('hello')")
///     .timeout(Duration::from_secs(5))
///     .network(true)
///     .exec()?;
/// ```
pub fn run(code: &str) -> PythonBuilder {
    PythonBuilder::new(code)
}

pub struct PythonProbe {
    /// Preferred Python version (e.g., "3.11", "3.12").
    pub version: Option<String>,
}

impl PythonProbe {
    pub fn new() -> Self {
        Self { version: None }
    }

    pub fn with_version(version: impl Into<String>) -> Self {
        Self {
            version: Some(version.into()),
        }
    }
}

impl Default for PythonProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl Probe for PythonProbe {
    fn name(&self) -> &str {
        "python"
    }

    fn detect(&self) -> Option<PathBuf> {
        if let Some(path) = resolve_from_env("VIRTUAL_ENV", "python3") {
            return Some(path);
        }

        if let Some(path) = resolve_from_env("CONDA_PREFIX", "python3") {
            return Some(path);
        }

        let names: Vec<String> = if let Some(ref ver) = self.version {
            vec![format!("python{ver}"), "python3".to_string()]
        } else {
            vec!["python3".to_string(), "python".to_string()]
        };

        for name in &names {
            if let Some(path) = resolve_binary(name, &[]) {
                return Some(path);
            }
        }

        let fallbacks = [
            "/usr/bin/python3",
            "/usr/local/bin/python3",
            "/opt/python/bin/python3",
        ];

        for fallback in &fallbacks {
            let path = Path::new(fallback);
            if path.exists() {
                return Some(path.to_path_buf());
            }
        }

        None
    }

    fn probe(&self, binary: &Path) -> Result<RuntimeInfo, ProbeError> {
        let probe_script = r#"
import sys
import json
import sysconfig

result = {
    "executable": sys.executable,
    "prefix": sys.prefix,
    "base_prefix": sys.base_prefix,
    "exec_prefix": sys.exec_prefix,
    "stdlib": sysconfig.get_path("stdlib"),
    "platstdlib": sysconfig.get_path("platstdlib"),
    "purelib": sysconfig.get_path("purelib"),
    "platlib": sysconfig.get_path("platlib"),
    "include": sysconfig.get_path("include"),
    "scripts": sysconfig.get_path("scripts"),
    "data": sysconfig.get_path("data"),
    "version_info": list(sys.version_info[:3]),
}

try:
    import site
    result["site_packages"] = site.getsitepackages()
except:
    result["site_packages"] = []

result["in_virtualenv"] = sys.prefix != sys.base_prefix

print(json.dumps(result))
"#;

        let output = Command::new(binary)
            .arg("-c")
            .arg(probe_script)
            .output()
            .map_err(|e| ProbeError::ProbeScriptFailed(format!("failed to run Python: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ProbeError::ProbeScriptFailed(format!(
                "Python probe script failed: {stderr}"
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let info: PythonInfo = serde_json::from_str(&stdout).map_err(|e| {
            ProbeError::ParseError(format!(
                "failed to parse Python probe output: {e}\n{stdout}"
            ))
        })?;

        let mut runtime = RuntimeInfo::new(binary.to_path_buf());

        runtime.env.insert(
            "PYTHONHOME".to_string(),
            info.prefix.to_string_lossy().into_owned(),
        );

        let mut mount_paths = std::collections::HashSet::new();

        if let Some(prefix) = prefix_dir(binary) {
            mount_paths.insert(prefix);
        }

        if let Some(ref stdlib) = info.stdlib {
            mount_paths.insert(stdlib.clone());
        }
        if let Some(ref platstdlib) = info.platstdlib {
            mount_paths.insert(platstdlib.clone());
        }

        for sp in &info.site_packages {
            mount_paths.insert(sp.clone());
        }
        if let Some(ref purelib) = info.purelib {
            mount_paths.insert(purelib.clone());
        }
        if let Some(ref platlib) = info.platlib {
            mount_paths.insert(platlib.clone());
        }

        if info.in_virtualenv {
            mount_paths.insert(info.base_prefix.clone());
        }

        mount_paths.insert(info.prefix.clone());
        mount_paths.insert(info.exec_prefix.clone());

        let mounts: Vec<Mount> = mount_paths
            .into_iter()
            .filter(|p| p.exists())
            .map(Mount::ro)
            .collect();

        runtime.mounts = mounts;

        match resolve_shared_libs(binary) {
            Ok(libs) => {
                runtime.shared_libs = libs;
            }
            Err(e) => {
                eprintln!("Warning: failed to resolve shared libs for Python: {e}");
            }
        }

        Ok(runtime)
    }
}

#[derive(Debug, Deserialize)]
struct PythonInfo {
    #[allow(dead_code)]
    executable: PathBuf,
    prefix: PathBuf,
    base_prefix: PathBuf,
    exec_prefix: PathBuf,
    stdlib: Option<PathBuf>,
    platstdlib: Option<PathBuf>,
    purelib: Option<PathBuf>,
    platlib: Option<PathBuf>,
    #[allow(dead_code)]
    include: Option<PathBuf>,
    #[allow(dead_code)]
    scripts: Option<PathBuf>,
    #[allow(dead_code)]
    data: Option<PathBuf>,
    #[allow(dead_code)]
    version_info: Vec<u32>,
    site_packages: Vec<PathBuf>,
    in_virtualenv: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_name() {
        let probe = PythonProbe::new();
        assert_eq!(probe.name(), "python");
    }

    #[test]
    fn test_probe_with_version() {
        let probe = PythonProbe::with_version("3.11");
        assert_eq!(probe.version, Some("3.11".to_string()));
    }

    #[test]
    fn test_probe_default() {
        let probe = PythonProbe::default();
        assert!(probe.version.is_none());
    }

    #[test]
    fn test_detect_python() {
        let probe = PythonProbe::new();
        let path = probe.detect();

        if let Some(p) = path {
            assert!(p.exists(), "Detected Python should exist");
            assert!(
                p.to_string_lossy().contains("python"),
                "Path should contain 'python': {}",
                p.display()
            );
        }
    }

    #[test]
    fn test_probe_nonexistent() {
        let probe = PythonProbe::new();
        let result = probe.probe(Path::new("/nonexistent/python"));
        assert!(result.is_err(), "Should fail for nonexistent binary");
    }
}
