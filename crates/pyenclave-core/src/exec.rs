//! Environment preparation and process execution.

use crate::spec::RunSpec;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, execve, ForkResult, Pid};
use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::io::Read;

/// Command specification to execute
#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub executable: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub cwd: Option<String>,
}

/// Execution result
#[derive(Debug, Clone, Default)]
pub struct ExecutionResult {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub signal: Option<i32>,
}

/// Dangerous environment variables that should be removed
const DANGEROUS_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
];

pub fn prepare_env(spec: &RunSpec) -> Result<(), String> {
    // Prepare safe environment variables for Python
    // TODO: define safe env (PYTHONPYCACHEPREFIX to redirect .pyc to
    // enclave, XDG_CACHE_HOME, thread control)
    
    // For now, just validate that there are no dangerous variables
    for (key, _value) in &spec.env {
        if DANGEROUS_ENV_VARS.contains(&key.as_str()) {
            return Err(format!("Dangerous environment variable: {}", key));
        }
    }
    
    Ok(())
}

pub fn set_pdeathsig() -> Result<(), String> {
    // PR_SET_PDEATHSIG: send SIGKILL if parent dies
    unsafe {
        prctl::set_death_signal(Signal::SIGKILL as isize)
            .map_err(|e| format!("Failed to set pdeathsig: {}", e))?;
    }
    
    Ok(())
}

pub fn exec_interpreter(_spec: &RunSpec) -> Result<(), String> {
    // TODO: execve() the target Python with -I and argv from spec
    // For now, return placeholder error
    Err("exec_interpreter: not implemented yet".to_string())
}

/// Sanitizes environment variables by removing dangerous ones
pub fn sanitize_env(env: &HashMap<String, String>) -> HashMap<String, String> {
    env.iter()
        .filter(|(key, _)| !DANGEROUS_ENV_VARS.contains(&key.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Executes a command and captures stdout/stderr
pub fn execute_command(spec: &CommandSpec) -> Result<ExecutionResult, String> {
    // Create pipes for stdout and stderr
    let (stdout_reader, stdout_writer) = create_pipe()?;
    let (stderr_reader, stderr_writer) = create_pipe()?;
    
    // Fork
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Parent process: close write ends and read output
            drop(stdout_writer);
            drop(stderr_writer);
            
            let stdout = read_from_pipe(stdout_reader)?;
            let stderr = read_from_pipe(stderr_reader)?;
            
            // Wait for child to terminate
            let wait_result = waitpid(child, None)
                .map_err(|e| format!("Failed to wait for child: {}", e))?;
            
            let (exit_code, signal) = match wait_result {
                WaitStatus::Exited(_pid, code) => (Some(code), None),
                WaitStatus::Signaled(_pid, sig, _) => (None, Some(sig as i32)),
                _ => (None, None),
            };
            
            Ok(ExecutionResult {
                exit_code,
                stdout,
                stderr,
                signal,
            })
        }
        Ok(ForkResult::Child) => {
            // Child process: redirect stdout/stderr and exec
            
            // Close read ends
            drop(stdout_reader);
            drop(stderr_reader);
            
            // Redirect stdout
            nix::unistd::dup2(stdout_writer.as_raw_fd(), 1)
                .expect("Failed to dup2 stdout");
            
            // Redirect stderr
            nix::unistd::dup2(stderr_writer.as_raw_fd(), 2)
                .expect("Failed to dup2 stderr");
            
            // Change working directory if specified
            if let Some(ref cwd) = spec.cwd {
                std::env::set_current_dir(cwd)
                    .expect("Failed to set working directory");
            }
            
            // Prepare arguments
            let exe_cstring = CString::new(spec.executable.as_str())
                .expect("Failed to create CString for executable");
            
            let mut args_cstrings: Vec<CString> = vec![exe_cstring.clone()];
            for arg in &spec.args {
                args_cstrings.push(CString::new(arg.as_str())
                    .expect("Failed to create CString for arg"));
            }
            
            // Prepare environment
            let env_cstrings: Vec<CString> = spec.env.iter()
                .map(|(k, v)| CString::new(format!("{}={}", k, v))
                    .expect("Failed to create CString for env"))
                .collect();
            
            // Execve
            execve(&exe_cstring, &args_cstrings, &env_cstrings)
                .expect("Failed to execve");
            
            unreachable!("execve should not return");
        }
        Err(e) => Err(format!("Failed to fork: {}", e)),
    }
}

// Helper: create pipe
fn create_pipe() -> Result<(std::fs::File, std::fs::File), String> {
    let (reader_fd, writer_fd) = nix::unistd::pipe()
        .map_err(|e| format!("Failed to create pipe: {}", e))?;
    
    // Convert OwnedFd to RawFd
    use std::os::fd::IntoRawFd;
    let reader_raw = reader_fd.into_raw_fd();
    let writer_raw = writer_fd.into_raw_fd();
    
    let reader = unsafe { std::fs::File::from_raw_fd(reader_raw) };
    let writer = unsafe { std::fs::File::from_raw_fd(writer_raw) };
    
    Ok((reader, writer))
}

// Helper: read from pipe until EOF
fn read_from_pipe(mut pipe: std::fs::File) -> Result<Vec<u8>, String> {
    let mut buffer = Vec::new();
    pipe.read_to_end(&mut buffer)
        .map_err(|e| format!("Failed to read from pipe: {}", e))?;
    Ok(buffer)
}

