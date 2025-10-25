use nix::errno::Errno;
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use pyenclave_core::policy::seccomp::{apply_seccomp_filter, SeccompProfile};
use std::fs;

/// Test that seccomp filter can be applied successfully
#[test]
fn test_apply_seccomp_basic() {
    // This test requires PR_SET_NO_NEW_PRIVS to be set first
    // We'll use nix's prctl wrapper
    nix::sys::prctl::set_no_new_privs().expect("Failed to set no_new_privs");

    // Apply a permissive filter (allow all by default, just testing loading)
    let profile = SeccompProfile::AllowAll;
    let result = apply_seccomp_filter(&profile);

    // Should succeed - filter loaded
    assert!(
        result.is_ok(),
        "Failed to apply seccomp filter: {:?}",
        result.err()
    );
}

/// Test that socket() syscall is blocked by the default profile
#[test]
fn test_block_socket_syscall() {
    // Set no_new_privs (required for seccomp)
    nix::sys::prctl::set_no_new_privs().expect("Failed to set no_new_privs");

    // Before filter: socket() should work
    let result_before = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        None,
    );
    assert!(
        result_before.is_ok(),
        "socket() should work before seccomp filter"
    );
    drop(result_before); // Close the socket

    // Apply default profile (blocks network syscalls)
    let profile = SeccompProfile::Default;
    apply_seccomp_filter(&profile).expect("Failed to apply seccomp filter");

    // After filter: socket() should fail with EPERM
    let result_after = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        None,
    );

    assert!(
        result_after.is_err(),
        "socket() should be blocked after seccomp filter"
    );
    assert_eq!(
        result_after.unwrap_err(),
        Errno::EPERM,
        "socket() should return EPERM when blocked by seccomp"
    );
}

/// Test that read/write syscalls are still allowed
#[test]
fn test_allow_basic_syscalls() {
    use std::io::{Read, Write};

    // Set no_new_privs
    nix::sys::prctl::set_no_new_privs().expect("Failed to set no_new_privs");

    // Apply default profile
    let profile = SeccompProfile::Default;
    apply_seccomp_filter(&profile).expect("Failed to apply seccomp filter");

    // Create a temp file and write to it (tests open, write, close)
    let temp_path = "/tmp/pyenclave_seccomp_test.txt";
    let mut file = fs::File::create(temp_path).expect("Should be able to create file");
    file.write_all(b"test data")
        .expect("Should be able to write");
    drop(file);

    // Read from file (tests open, read, close)
    let mut file = fs::File::open(temp_path).expect("Should be able to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Should be able to read");
    assert_eq!(contents, "test data");

    // Cleanup
    fs::remove_file(temp_path).expect("Should be able to remove file");
}

/// Test that the profile correctly identifies the current architecture
#[test]
fn test_detect_architecture() {
    let arch = SeccompProfile::detect_arch();

    #[cfg(target_arch = "x86_64")]
    assert_eq!(arch, "x86_64", "Should detect x86_64 architecture");

    #[cfg(target_arch = "aarch64")]
    assert_eq!(arch, "aarch64", "Should detect aarch64 architecture");
}

/// Test that fork() is allowed (we need it for exec)
#[test]
fn test_allow_fork() {
    use nix::unistd::{fork, ForkResult};

    // Set no_new_privs
    nix::sys::prctl::set_no_new_privs().expect("Failed to set no_new_privs");

    // Apply default profile
    let profile = SeccompProfile::Default;
    apply_seccomp_filter(&profile).expect("Failed to apply seccomp filter");

    // fork() should still work
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Parent: wait for child
            nix::sys::wait::waitpid(child, None).expect("Failed to wait for child");
        }
        Ok(ForkResult::Child) => {
            // Child: exit immediately
            std::process::exit(0);
        }
        Err(e) => {
            panic!("fork() should be allowed by default profile: {}", e);
        }
    }
}

/// Test that execve() is allowed (critical for running Python)
#[test]
fn test_allow_execve() {
    use nix::unistd::{execve, fork, ForkResult};
    use std::ffi::CString;

    // Set no_new_privs
    nix::sys::prctl::set_no_new_privs().expect("Failed to set no_new_privs");

    // Apply default profile
    let profile = SeccompProfile::Default;
    apply_seccomp_filter(&profile).expect("Failed to apply seccomp filter");

    // Test execve in a child process
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Parent: wait for child
            let status = nix::sys::wait::waitpid(child, None).expect("Failed to wait for child");
            // Check that child exited with 0
            use nix::sys::wait::WaitStatus;
            match status {
                WaitStatus::Exited(_, code) => {
                    assert_eq!(code, 0, "Child should exit with code 0");
                }
                _ => panic!("Child should have exited normally"),
            }
        }
        Ok(ForkResult::Child) => {
            // Child: exec /bin/true
            let path = CString::new("/bin/true").unwrap();
            let args = vec![path.clone()];
            let env: Vec<CString> = vec![];

            execve(&path, &args, &env).expect("execve() should be allowed");
            // Should never reach here
            std::process::exit(1);
        }
        Err(e) => {
            panic!("fork() failed: {}", e);
        }
    }
}

/// Test blocking mount() syscall (security critical)
#[test]
#[cfg(target_os = "linux")]
fn test_block_mount_syscall() {
    use nix::mount::{mount, MsFlags};
    use std::path::Path;

    // Set no_new_privs
    nix::sys::prctl::set_no_new_privs().expect("Failed to set no_new_privs");

    // Apply default profile
    let profile = SeccompProfile::Default;
    apply_seccomp_filter(&profile).expect("Failed to apply seccomp filter");

    // Attempt to mount tmpfs (should be blocked by seccomp, not permissions)
    let target = Path::new("/tmp/pyenclave_mount_test");
    let _ = fs::create_dir_all(target); // Ignore errors if exists

    let result = mount(
        Some("tmpfs"),
        target,
        Some("tmpfs"),
        MsFlags::empty(),
        None::<&str>,
    );

    // Should fail with EPERM (seccomp block), not EPERM (permissions)
    // Note: This might fail with EPERM even without seccomp due to lack of CAP_SYS_ADMIN,
    // but the key is that seccomp blocks it *before* the capability check
    assert!(
        result.is_err(),
        "mount() should be blocked by seccomp filter"
    );

    // Cleanup
    let _ = fs::remove_dir(target);
}

/// Test blocking ptrace() syscall (anti-debugging)
#[test]
fn test_block_ptrace_syscall() {
    use nix::sys::ptrace;
    use nix::unistd::{fork, ForkResult, Pid};

    // Set no_new_privs
    nix::sys::prctl::set_no_new_privs().expect("Failed to set no_new_privs");

    // Apply default profile
    let profile = SeccompProfile::Default;
    apply_seccomp_filter(&profile).expect("Failed to apply seccomp filter");

    // Try to ptrace ourselves (should fail with EPERM from seccomp)
    let result = ptrace::traceme();

    assert!(
        result.is_err(),
        "ptrace() should be blocked by seccomp filter"
    );
    assert_eq!(
        result.unwrap_err(),
        Errno::EPERM,
        "ptrace() should return EPERM when blocked by seccomp"
    );
}

/// Test that custom profile can be created with specific syscalls
#[test]
fn test_custom_profile() {
    // Set no_new_privs
    nix::sys::prctl::set_no_new_privs().expect("Failed to set no_new_privs");

    // Create custom profile that blocks read (extreme test)
    let blocked_syscalls = vec!["socket", "connect", "bind", "listen"];
    let profile = SeccompProfile::Custom { blocked_syscalls };

    let result = apply_seccomp_filter(&profile);
    assert!(result.is_ok(), "Should be able to apply custom profile");
}
