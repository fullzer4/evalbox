//! Go runtime probe and execution.
//!
//! ## Example
//!
//! ```ignore
//! use evalbox::go;
//!
//! // Simple execution (auto-wraps into main())
//! let output = go::run(r#"fmt.Println("hello")"#).exec()?;
//!
//! // With options
//! let output = go::run(r#"fmt.Println("hello")"#)
//!     .timeout(Duration::from_secs(10))
//!     .auto_wrap(false)
//!     .exec()?;
//!
//! // Full program works unchanged
//! let output = go::run(r#"
//! package main
//! import "fmt"
//! func main() { fmt.Println("hello") }
//! "#).exec()?;
//! ```

mod builder;
pub mod wrap;

pub use builder::GoBuilder;

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::detect::{resolve_binary, resolve_from_env};
use crate::error::ProbeError;
use crate::probe::{Mount, Probe, RuntimeInfo};

pub use wrap::{wrap_go_code, AUTO_IMPORTS};

/// Run Go code with default settings.
///
/// Returns a `GoBuilder` that can be customized with `.timeout()`, `.auto_wrap()`, etc.
/// Call `.exec()` to execute.
///
/// # Example
///
/// ```ignore
/// // Simple execution (auto-wraps into main())
/// let output = go::run(r#"fmt.Println("hello")"#).exec()?;
///
/// // With options
/// let output = go::run(r#"fmt.Println("hello")"#)
///     .timeout(Duration::from_secs(5))
///     .exec()?;
/// ```
pub fn run(code: &str) -> GoBuilder {
    GoBuilder::new(code)
}

pub struct GoProbe {
    pub cgo_enabled: bool,
}

impl GoProbe {
    pub fn new() -> Self {
        Self { cgo_enabled: false }
    }

    pub fn with_cgo() -> Self {
        Self { cgo_enabled: true }
    }
}

impl Default for GoProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl Probe for GoProbe {
    fn name(&self) -> &str {
        "go"
    }

    fn detect(&self) -> Option<PathBuf> {
        if let Some(path) = resolve_from_env("GOROOT", "go") {
            return Some(path);
        }

        if let Some(path) = resolve_binary("go", &[]) {
            return Some(path);
        }

        let fallbacks = ["/usr/local/go/bin/go", "/usr/lib/go/bin/go", "/opt/go/bin/go"];

        for fallback in &fallbacks {
            let path = Path::new(fallback);
            if path.exists() {
                return Some(path.to_path_buf());
            }
        }

        None
    }

    fn probe(&self, binary: &Path) -> Result<RuntimeInfo, ProbeError> {
        let output = Command::new(binary)
            .arg("env")
            .arg("-json")
            .output()
            .map_err(|e| ProbeError::ProbeScriptFailed(format!("failed to run go env: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ProbeError::ProbeScriptFailed(format!("go env failed: {stderr}")));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let env: GoEnv = serde_json::from_str(&stdout).map_err(|e| {
            ProbeError::ParseError(format!("failed to parse go env output: {e}\n{stdout}"))
        })?;

        let mut runtime = RuntimeInfo::new(binary.to_path_buf());

        runtime.env.insert("GOROOT".to_string(), env.goroot.to_string_lossy().into_owned());
        runtime.env.insert("GOCACHE".to_string(), env.gocache.to_string_lossy().into_owned());

        if let Some(ref gomodcache) = env.gomodcache {
            runtime.env.insert("GOMODCACHE".to_string(), gomodcache.to_string_lossy().into_owned());
        }

        runtime.env.insert(
            "CGO_ENABLED".to_string(),
            if self.cgo_enabled { "1" } else { "0" }.to_string(),
        );

        runtime.mounts.push(Mount::ro(&env.goroot));

        if let Some(ref gomodcache) = env.gomodcache {
            if gomodcache.exists() {
                runtime.mounts.push(Mount::ro(gomodcache));
            }
        }

        if let Some(store_path) = detect_nix_store_path(&env.goroot) {
            runtime.mounts.push(Mount::ro(store_path));
        }

        Ok(runtime)
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
struct GoEnv {
    goroot: PathBuf,
    gocache: PathBuf,
    gomodcache: Option<PathBuf>,
    #[allow(dead_code)]
    gopath: Option<PathBuf>,
    #[allow(dead_code)]
    goos: String,
    #[allow(dead_code)]
    goarch: String,
}

fn detect_nix_store_path(path: &Path) -> Option<PathBuf> {
    let path_str = path.to_string_lossy();
    if !path_str.starts_with("/nix/store/") {
        return None;
    }

    let store_path: PathBuf = path.components().take(4).collect();
    (store_path.components().count() == 4).then_some(store_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_name() {
        let probe = GoProbe::new();
        assert_eq!(probe.name(), "go");
    }

    #[test]
    fn test_probe_with_cgo() {
        let probe = GoProbe::with_cgo();
        assert!(probe.cgo_enabled);
    }

    #[test]
    fn test_probe_default() {
        let probe = GoProbe::default();
        assert!(!probe.cgo_enabled);
    }

    #[test]
    fn test_detect_go() {
        let probe = GoProbe::new();
        let path = probe.detect();

        if let Some(p) = path {
            assert!(p.exists(), "Detected Go should exist");
            assert!(p.to_string_lossy().contains("go"), "Path should contain 'go': {}", p.display());
        }
    }

    #[test]
    fn test_probe_nonexistent() {
        let probe = GoProbe::new();
        let result = probe.probe(Path::new("/nonexistent/go"));
        assert!(result.is_err(), "Should fail for nonexistent binary");
    }

    #[test]
    fn test_detect_nix_store_path() {
        let nix_path = Path::new("/nix/store/abc123-go/bin/go");
        let store_path = detect_nix_store_path(nix_path);
        assert!(store_path.is_some());
        assert!(store_path.unwrap().to_string_lossy().starts_with("/nix/store/"));
    }

    #[test]
    fn test_detect_nix_store_path_non_nix() {
        let normal_path = Path::new("/usr/bin/go");
        assert!(detect_nix_store_path(normal_path).is_none());
    }
}
