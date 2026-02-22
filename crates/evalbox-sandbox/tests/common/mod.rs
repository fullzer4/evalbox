//! Common utilities for security tests.

use std::path::PathBuf;

/// Load a pre-compiled C payload binary.
///
/// Payloads are compiled by build.rs and stored in `OUT_DIR/payloads`/.
pub fn payload(name: &str) -> Vec<u8> {
    if let Some(path) = find_payload(name) {
        return std::fs::read(&path)
            .unwrap_or_else(|e| panic!("Failed to read payload {}: {}", path.display(), e));
    }

    panic!("Payload '{name}' not found. Run `cargo build -p evalbox-sandbox` first.");
}

/// Find payload in cargo's build directory structure.
fn find_payload(name: &str) -> Option<PathBuf> {
    // 1. Next to the test executable (Nix builds)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let path = exe_dir.join("payloads").join(name);
            if path.exists() {
                return Some(path);
            }
        }
    }

    // 2. Cargo build directory (development)
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));

    let workspace_root = manifest_dir.parent()?.parent()?;

    let target_dirs: Vec<PathBuf> = std::iter::once(workspace_root.join("target"))
        .chain(std::env::var("CARGO_TARGET_DIR").ok().map(PathBuf::from))
        .collect();

    for target_dir in target_dirs {
        for profile in ["debug", "release"] {
            let build_dir = target_dir.join(profile).join("build");
            if let Ok(entries) = std::fs::read_dir(&build_dir) {
                for entry in entries.flatten() {
                    if entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("evalbox-sandbox-")
                    {
                        let path = entry.path().join("out").join("payloads").join(name);
                        if path.exists() {
                            return Some(path);
                        }
                    }
                }
            }
        }
    }

    None
}

/// SIGSYS signal number (seccomp violation).
pub const SIGSYS: i32 = 31;

/// SIGKILL signal number.
#[allow(dead_code)]
pub const SIGKILL: i32 = 9;
