//! C FFI bindings for leeward
//!
//! This crate provides a C-compatible API for the leeward sandbox.
//!
//! # Example (C)
//! ```c
//! #include <leeward.h>
//!
//! LeewardHandle* handle = leeward_connect("/var/run/leeward.sock");
//! LeewardResult* result = leeward_execute(handle, "print('hello')", NULL);
//! printf("%s", result->stdout_data);
//! leeward_result_free(result);
//! leeward_disconnect(handle);
//! ```

#![allow(clippy::missing_safety_doc)]

use libc::{c_char, c_int, size_t};
use once_cell::sync::Lazy;
use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::ptr;

/// Opaque handle to a leeward connection
pub struct LeewardHandle {
    // TODO: actual connection state
    _socket_path: String,
}

/// Result of an execution
#[repr(C)]
pub struct LeewardResult {
    /// Exit code
    pub exit_code: c_int,
    /// Stdout data (null-terminated)
    pub stdout_data: *mut c_char,
    /// Stdout length
    pub stdout_len: size_t,
    /// Stderr data (null-terminated)
    pub stderr_data: *mut c_char,
    /// Stderr length
    pub stderr_len: size_t,
    /// Duration in microseconds
    pub duration_us: u64,
    /// Peak memory in bytes
    pub memory_peak: u64,
    /// Whether timed out
    pub timed_out: c_int,
    /// Whether OOM killed
    pub oom_killed: c_int,
}

/// Execution options
#[repr(C)]
pub struct LeewardOptions {
    /// Timeout in seconds (0 = default)
    pub timeout_secs: u64,
    /// Memory limit in bytes (0 = default)
    pub memory_limit: u64,
}

/// Error codes
#[repr(C)]
pub enum LeewardError {
    /// Success
    Ok = 0,
    /// Null pointer argument
    NullPointer = 1,
    /// Invalid UTF-8
    InvalidUtf8 = 2,
    /// Connection failed
    ConnectionFailed = 3,
    /// Execution failed
    ExecutionFailed = 4,
    /// Timeout
    Timeout = 5,
    /// Out of memory
    OutOfMemory = 6,
    /// Unknown error
    Unknown = 99,
}

// Thread-local error message
thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn set_last_error(msg: String) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(msg);
    });
}

/// Get the last error message
///
/// Returns NULL if no error. The returned string is valid until the next
/// leeward call on this thread.
#[no_mangle]
pub extern "C" fn leeward_last_error() -> *const c_char {
    thread_local! {
        static ERROR_BUF: RefCell<Option<CString>> = const { RefCell::new(None) };
    }

    LAST_ERROR.with(|e| {
        let err = e.borrow();
        match &*err {
            Some(msg) => {
                ERROR_BUF.with(|buf| {
                    let cstr = CString::new(msg.as_str()).unwrap_or_default();
                    let ptr = cstr.as_ptr();
                    *buf.borrow_mut() = Some(cstr);
                    ptr
                })
            }
            None => ptr::null(),
        }
    })
}

/// Connect to the leeward daemon
///
/// Returns NULL on failure. Call `leeward_last_error()` for details.
#[no_mangle]
pub unsafe extern "C" fn leeward_connect(socket_path: *const c_char) -> *mut LeewardHandle {
    if socket_path.is_null() {
        set_last_error("socket_path is null".into());
        return ptr::null_mut();
    }

    let path = match CStr::from_ptr(socket_path).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_last_error("invalid UTF-8 in socket_path".into());
            return ptr::null_mut();
        }
    };

    // TODO: Actually connect to socket

    Box::into_raw(Box::new(LeewardHandle { _socket_path: path }))
}

/// Disconnect from the daemon
#[no_mangle]
pub unsafe extern "C" fn leeward_disconnect(handle: *mut LeewardHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Execute Python code
///
/// Returns NULL on failure. Call `leeward_last_error()` for details.
/// The caller must free the result with `leeward_result_free()`.
#[no_mangle]
pub unsafe extern "C" fn leeward_execute(
    handle: *mut LeewardHandle,
    code: *const c_char,
    options: *const LeewardOptions,
) -> *mut LeewardResult {
    if handle.is_null() {
        set_last_error("handle is null".into());
        return ptr::null_mut();
    }

    if code.is_null() {
        set_last_error("code is null".into());
        return ptr::null_mut();
    }

    let _code = match CStr::from_ptr(code).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("invalid UTF-8 in code".into());
            return ptr::null_mut();
        }
    };

    let _opts = if options.is_null() {
        None
    } else {
        Some(&*options)
    };

    // TODO: Actually execute via socket

    // Return dummy result for now
    let stdout = CString::new("").unwrap();
    let stderr = CString::new("").unwrap();

    Box::into_raw(Box::new(LeewardResult {
        exit_code: 0,
        stdout_data: stdout.into_raw(),
        stdout_len: 0,
        stderr_data: stderr.into_raw(),
        stderr_len: 0,
        duration_us: 0,
        memory_peak: 0,
        timed_out: 0,
        oom_killed: 0,
    }))
}

/// Free an execution result
#[no_mangle]
pub unsafe extern "C" fn leeward_result_free(result: *mut LeewardResult) {
    if !result.is_null() {
        let r = Box::from_raw(result);
        if !r.stdout_data.is_null() {
            drop(CString::from_raw(r.stdout_data));
        }
        if !r.stderr_data.is_null() {
            drop(CString::from_raw(r.stderr_data));
        }
    }
}

/// Get library version
#[no_mangle]
pub extern "C" fn leeward_version() -> *const c_char {
    static VERSION: Lazy<CString> =
        Lazy::new(|| CString::new(env!("CARGO_PKG_VERSION")).unwrap());
    VERSION.as_ptr()
}
