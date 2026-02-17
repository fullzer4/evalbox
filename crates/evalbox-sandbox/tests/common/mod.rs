//! Common utilities for security tests.

use std::path::PathBuf;

/// Load a pre-compiled C payload binary.
///
/// Payloads are compiled by build.rs and stored in OUT_DIR/payloads/.
pub fn payload(name: &str) -> Vec<u8> {
    if let Some(path) = find_payload(name) {
        return std::fs::read(&path)
            .unwrap_or_else(|e| panic!("Failed to read payload {}: {}", path.display(), e));
    }

    panic!(
        "Payload '{}' not found. Run `cargo build -p evalbox-sandbox` first.",
        name
    );
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

/// Check if we have permission to create user namespaces.
pub fn can_create_namespaces() -> bool {
    // Check kernel parameter
    if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        if content.trim() == "0" {
            return false;
        }
    }

    // Try to actually create a namespace
    let result = std::process::Command::new("unshare")
        .args(["--user", "--map-root-user", "true"])
        .output();

    result.map(|o| o.status.success()).unwrap_or(false)
}

/// Skip test if namespaces aren't available. Call at start of test.
pub fn skip_if_no_namespaces() -> bool {
    if !can_create_namespaces() {
        eprintln!("Skipping: Cannot create user namespaces");
        true
    } else {
        false
    }
}

/// SIGSYS signal number (seccomp violation).
pub const SIGSYS: i32 = 31;

/// SIGKILL signal number.
pub const SIGKILL: i32 = 9;
