//! Build script for evalbox-sandbox.
//!
//! Compiles C security test payloads into static binaries.
//! These payloads are used in integration tests to verify sandbox isolation.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=tests/payloads");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let payload_dir = out_dir.join("payloads");
    fs::create_dir_all(&payload_dir).unwrap();

    let payloads_src = PathBuf::from("tests/payloads");
    if !payloads_src.exists() {
        // No payloads directory - skip compilation
        return;
    }

    // Find all .c files in tests/payloads/
    let entries = match fs::read_dir(&payloads_src) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e == "c").unwrap_or(false) {
            let stem = path.file_stem().unwrap().to_string_lossy();
            let output = payload_dir.join(stem.as_ref());

            compile_payload(&path, &output);
        }
    }
}

fn compile_payload(source: &PathBuf, output: &PathBuf) {
    let name = source.file_stem().unwrap().to_string_lossy();

    // Try to compile with musl for static binary, fall back to glibc
    let compilers = ["musl-gcc", "gcc", "cc"];

    for compiler in compilers {
        let status = Command::new(compiler)
            .args(["-static", "-O2", "-Wall", "-Wextra", "-o"])
            .arg(output)
            .arg(source)
            .status();

        match status {
            Ok(s) if s.success() => {
                println!("cargo:warning=Compiled payload: {name}");
                return;
            }
            _ => continue,
        }
    }

    // If static compilation fails, try without -static
    let status = Command::new("gcc")
        .args(["-O2", "-Wall", "-Wextra", "-o"])
        .arg(output)
        .arg(source)
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("cargo:warning=Compiled payload (dynamic): {name}");
        }
        _ => {
            println!("cargo:warning=Failed to compile payload: {name}");
        }
    }
}
