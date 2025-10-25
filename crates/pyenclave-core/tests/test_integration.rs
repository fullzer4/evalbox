/// Integration tests for the complete pyenclave pipeline
use pyenclave_core::{exec, limits, policy, preflight, telemetry};
use std::collections::HashMap;
use tempfile::TempDir;

fn find_python3() -> Option<String> {
    for path in ["/usr/bin/python3", "/usr/bin/python3.11", "/usr/bin/python"] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

fn make_command(
    executable: &str,
    args: &[&str],
    env_vars: &[(String, String)],
    cwd: Option<&str>,
) -> exec::CommandSpec {
    let mut env = HashMap::new();
    for (k, v) in env_vars {
        env.insert(k.clone(), v.clone());
    }
    exec::CommandSpec {
        executable: executable.to_string(),
        args: args.iter().map(|s| s.to_string()).collect(),
        env,
        cwd: cwd.map(|s| s.to_string()),
    }
}

#[test]
fn test_simple_python() {
    let python = match find_python3() {
        Some(p) => p,
        None => {
            println!("⚠️  Python not found");
            return;
        }
    };

    limits::apply_no_new_privs().expect("no_new_privs failed");
    let cmd = make_command(&python, &["-c", "print('Hello!')"], &[], None);
    let result = exec::execute_command(&cmd);
    assert!(result.is_ok());
}

#[test]
fn test_seccomp_blocks_socket() {
    let python = match find_python3() {
        Some(p) => p,
        None => {
            println!("⚠️  Python not found");
            return;
        }
    };

    limits::apply_no_new_privs().expect("no_new_privs failed");
    let profile = policy::seccomp::SeccompProfile::Default;
    policy::seccomp::apply_seccomp_filter(&profile).expect("seccomp failed");

    let cmd = make_command(&python, &["-c", "import socket; socket.socket()"], &[], None);
    let result = exec::execute_command(&cmd);
    match result {
        Ok(r) => assert_ne!(r.exit_code, Some(0)),
        Err(e) => println!("✅ Blocked: {}", e),
    }
}

#[test]
fn test_preflight() {
    let report = preflight::probe_host();
    println!("Arch: {:?}", report.arch);
    println!("Kernel: {:?}", report.kernel);
    println!("Userns: {}", report.userns);
    println!("Seccomp: {}", report.seccomp);
    println!("Landlock: {}", report.landlock);
    assert!(report.arch.is_some());
}
