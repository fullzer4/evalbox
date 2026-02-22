//! Resource limits for sandboxed processes.
//!
//! Sets kernel-enforced resource limits to prevent denial-of-service.
//!
//! ## Limits Applied
//!
//! | Limit | Purpose | Default |
//! |-------|---------|---------|
//! | `RLIMIT_DATA` | Memory usage | 256 MiB |
//! | `RLIMIT_CPU` | CPU time | timeout * 2 + 60s |
//! | `RLIMIT_FSIZE` | Output file size | 16 MiB |
//! | `RLIMIT_NOFILE` | Open file descriptors | 256 |
//! | `RLIMIT_NPROC` | Max processes | 64 |
//! | `RLIMIT_CORE` | Core dump size | 0 (disabled) |
//! | `RLIMIT_STACK` | Stack size | 8 MiB |
//!
//! ## Note on `RLIMIT_AS`
//!
//! We intentionally do NOT set `RLIMIT_AS` (virtual address space).
//! Modern runtimes like Go, Java, and V8 pre-allocate large virtual address
//! ranges but only commit small portions. `RLIMIT_AS` would break these
//! runtimes. `RLIMIT_DATA` limits actual memory and is more appropriate.

use evalbox_sys::last_errno;
use rustix::io::Errno;

use crate::plan::Plan;

/// Apply resource limits based on the sandbox plan.
pub fn apply_rlimits(plan: &Plan) -> Result<(), Errno> {
    let cpu_secs = plan.timeout.as_secs().saturating_mul(2).saturating_add(60);

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
