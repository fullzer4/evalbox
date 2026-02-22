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
    // Get the workspace root by looking for Cargo.toml
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));

    // The workspace root is two levels up from crates/evalbox-sandbox
    let workspace_root = manifest_dir.parent()?.parent()?;
    let target_dir = workspace_root.join("target");

    // Look in both debug and release builds
    for profile in ["debug", "release"] {
        let build_dir = target_dir.join(profile).join("build");
        if let Ok(entries) = std::fs::read_dir(&build_dir) {
            for entry in entries.flatten() {
                let dir_name = entry.file_name();
                if dir_name.to_string_lossy().starts_with("evalbox-sandbox-") {
                    let payload_path = entry.path().join("out").join("payloads").join(name);
                    if payload_path.exists() {
                        return Some(payload_path);
                    }
                }
            }
        }
    }

    // Also try CARGO_TARGET_DIR if set
    if let Ok(target) = std::env::var("CARGO_TARGET_DIR") {
        let target_dir = PathBuf::from(target);
        for profile in ["debug", "release"] {
            let build_dir = target_dir.join(profile).join("build");
            if let Ok(entries) = std::fs::read_dir(&build_dir) {
                for entry in entries.flatten() {
                    let dir_name = entry.file_name();
                    if dir_name.to_string_lossy().starts_with("evalbox-sandbox-") {
                        let payload_path = entry.path().join("out").join("payloads").join(name);
                        if payload_path.exists() {
                            return Some(payload_path);
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
