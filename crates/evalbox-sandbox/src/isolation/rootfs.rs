//! Rootfs setup and resource limits for sandboxed processes.
//!
//! This module handles:
//! - Bind mounts for the sandbox filesystem
//! - Pivot root to isolate the filesystem
//! - Resource limits (rlimits)
//!
//! ## Filesystem Layout (after `pivot_root`)
//!
//! ```text
//! /
//! ├── bin/      → bind mount from /bin (read-only)
//! ├── dev/      → bind mounts: null, zero, urandom, random + symlinks
//! ├── etc/      → bind mount from /etc (read-only)
//! ├── home/     → empty, writable
//! ├── lib/      → bind mount from /lib (read-only)
//! ├── lib64/    → bind mount from /lib64 if exists (read-only)
//! ├── nix/      → bind mount from /nix/store on NixOS (read-only)
//! ├── proc/     → bind mount from /proc (read-only)
//! ├── tmp/      → empty, writable
//! ├── usr/      → bind mount from /usr (read-only)
//! └── work/     → user code directory, writable
//! ```

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use evalbox_sys::last_errno;
use rustix::io::Errno;
use rustix::process::pivot_root;

use crate::plan::Plan;

/// Make all mounts private recursively.
pub fn make_rprivate() -> Result<(), Errno> {
    let ret = unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if ret != 0 { Err(last_errno()) } else { Ok(()) }
}

/// Mount proc filesystem (bind-mounted read-only from host).
pub fn mount_proc(target: &Path) -> Result<(), Errno> {
    let target_c = path_to_cstring(target)?;

    let ret = unsafe {
        libc::mount(
            c"/proc".as_ptr(),
            target_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(last_errno());
    }

    let ret = unsafe {
        libc::mount(
            std::ptr::null(),
            target_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND
                | libc::MS_REMOUNT
                | libc::MS_RDONLY
                | libc::MS_NOSUID
                | libc::MS_NODEV
                | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    };
    if ret != 0 { Err(last_errno()) } else { Ok(()) }
}

/// Create minimal /dev with null, zero, urandom (bind-mounted from host).
pub fn mount_minimal_dev(target: &Path) -> Result<(), Errno> {
    for dev in ["null", "zero", "urandom", "random"] {
        bind_mount_dev(target, dev)?;
    }

    let fd_path = target.join("fd");
    let fd_c = path_to_cstring(&fd_path)?;
    if unsafe { libc::symlink(c"/proc/self/fd".as_ptr(), fd_c.as_ptr()) } != 0 {
        return Err(last_errno());
    }

    for (name, num) in [("stdin", 0), ("stdout", 1), ("stderr", 2)] {
        let link_path = target.join(name);
        let link_c = path_to_cstring(&link_path)?;
        let target_str = CString::new(format!("/proc/self/fd/{num}")).map_err(|_| Errno::INVAL)?;
        if unsafe { libc::symlink(target_str.as_ptr(), link_c.as_ptr()) } != 0 {
            return Err(last_errno());
        }
    }

    Ok(())
}

fn bind_mount_dev(target_dev: &Path, name: &str) -> Result<(), Errno> {
    let source = Path::new("/dev").join(name);
    let target = target_dev.join(name);
    let target_c = path_to_cstring(&target)?;
    let source_c = path_to_cstring(&source)?;

    let fd = unsafe { libc::open(target_c.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644) };
    if fd < 0 {
        return Err(last_errno());
    }
    unsafe { libc::close(fd) };

    let ret = unsafe {
        libc::mount(
            source_c.as_ptr(),
            target_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if ret != 0 { Err(last_errno()) } else { Ok(()) }
}

/// Bind mount a path.
pub fn bind_mount(source: &Path, target: &Path, readonly: bool) -> Result<(), Errno> {
    let source_c = path_to_cstring(source)?;
    let target_c = path_to_cstring(target)?;

    let ret = unsafe {
        libc::mount(
            source_c.as_ptr(),
            target_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(last_errno());
    }

    if readonly {
        let ret = unsafe {
            libc::mount(
                std::ptr::null(),
                target_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            return Err(last_errno());
        }
    }

    Ok(())
}

/// Perform `pivot_root` and clean up the old root.
pub fn pivot_root_and_cleanup(new_root: &Path) -> Result<(), Errno> {
    let new_root_c = path_to_cstring(new_root)?;

    let ret = unsafe {
        libc::mount(
            new_root_c.as_ptr(),
            new_root_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(last_errno());
    }

    let old_root = new_root.join(".old_root");
    let old_root_c = path_to_cstring(&old_root)?;
    unsafe { libc::mkdir(old_root_c.as_ptr(), 0o700) };

    let new_root_cstr = CString::new(new_root_c.as_bytes()).map_err(|_| Errno::INVAL)?;
    let old_root_cstr = CString::new(old_root_c.as_bytes()).map_err(|_| Errno::INVAL)?;
    pivot_root(new_root_cstr.as_c_str(), old_root_cstr.as_c_str())?;

    unsafe {
        libc::chdir(c"/".as_ptr());
        libc::umount2(c"/.old_root".as_ptr(), libc::MNT_DETACH);
        libc::rmdir(c"/.old_root".as_ptr());
    }

    Ok(())
}

/// Set the hostname.
pub fn set_hostname(name: &str) -> Result<(), Errno> {
    let ret = unsafe { libc::sethostname(name.as_ptr().cast::<libc::c_char>(), name.len()) };
    if ret != 0 { Err(last_errno()) } else { Ok(()) }
}

#[inline]
fn path_to_cstring(path: &Path) -> Result<CString, Errno> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| Errno::INVAL)
}

/// Apply resource limits based on the sandbox plan.
pub fn apply_rlimits(plan: &Plan) -> Result<(), Errno> {
    let cpu_secs = plan.timeout.as_secs().saturating_mul(2).saturating_add(60);

    // Note: We intentionally do NOT set RLIMIT_AS (address space).
    // RLIMIT_AS limits virtual memory, which can be much larger than actual usage.
    // Modern runtimes like Go, Java, and V8 pre-allocate large virtual address ranges
    // but only commit (use) small portions. RLIMIT_AS would break these runtimes.
    // RLIMIT_DATA limits the data segment and is more appropriate for real memory control.
    set_rlimit(libc::RLIMIT_DATA, plan.memory_limit)?;
    set_rlimit(libc::RLIMIT_CPU, cpu_secs)?;
    set_rlimit(libc::RLIMIT_FSIZE, plan.max_output)?;
    set_rlimit(libc::RLIMIT_NOFILE, 256)?;
    set_rlimit(libc::RLIMIT_NPROC, u64::from(plan.max_pids))?;
    set_rlimit(libc::RLIMIT_CORE, 0)?;
    set_rlimit(libc::RLIMIT_STACK, 8 * 1024 * 1024)?;
    Ok(())
}

#[inline]
fn set_rlimit(resource: libc::__rlimit_resource_t, limit: u64) -> Result<(), Errno> {
    let rlim = libc::rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    };
    // SAFETY: rlim is valid, resource is a valid constant.
    if unsafe { libc::setrlimit(resource, &rlim) } != 0 {
        Err(last_errno())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_to_cstring_valid() {
        let cstr = path_to_cstring(Path::new("/tmp/test")).unwrap();
        assert_eq!(cstr.as_bytes(), b"/tmp/test");
    }

    #[test]
    fn get_current_nofile() {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) },
            0
        );
        assert!(rlim.rlim_cur > 0);
    }
}
