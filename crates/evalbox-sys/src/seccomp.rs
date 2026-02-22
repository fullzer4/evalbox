//! Seccomp-BPF syscall filtering.
//!
//! Seccomp-BPF allows filtering syscalls using Berkeley Packet Filter (BPF) programs.
//! This provides a second layer of defense after Landlock - even if a path is accessible,
//! dangerous syscalls are blocked.
//!
//! ## Filter Structure
//!
//! The BPF filter runs on every syscall:
//!
//! 1. Verify architecture is `x86_64` (kill otherwise)
//! 2. Load syscall number from `seccomp_data`
//! 3. Block `clone3` entirely (cannot inspect flags in struct)
//! 4. For `clone`, inspect flags and block namespace creation
//! 5. For `socket`, inspect domain and block dangerous types (`AF_NETLINK`, `SOCK_RAW`)
//! 6. Compare other syscalls against whitelist
//! 7. Allow if match found, kill process otherwise
//!
//! ## Clone Flag Filtering
//!
//! The `clone` syscall is allowed but with restricted flags:
//!
//! - `CLONE_NEWUSER` - User namespace (kernel attack surface)
//! - `CLONE_NEWNET` - Network namespace (`nf_tables` access)
//! - `CLONE_NEWNS` - Mount namespace
//! - `CLONE_NEWPID` - PID namespace
//! - `CLONE_NEWIPC` - IPC namespace
//! - `CLONE_NEWUTS` - UTS namespace
//! - `CLONE_NEWCGROUP` - Cgroup namespace
//!
//! The `clone3` syscall is blocked entirely because its flags are passed via
//! a userspace struct pointer that BPF cannot dereference.
//!
//! ## Socket Filtering
//!
//! The `socket` syscall is filtered to block:
//!
//! - `AF_NETLINK` (16) - Access to kernel netlink interfaces (`nf_tables`, CVE-2024-1086)
//! - `SOCK_RAW` (3) - Raw packet access (can craft arbitrary packets)
//!
//! Allowed socket types:
//! - `AF_UNIX` (1) - Local IPC (Python multiprocessing, etc.)
//! - `AF_INET`/`AF_INET6` (2, 10) - Network (Landlock controls actual access)
//!
//! ## Removed Dangerous Syscalls
//!
//! - `memfd_create` + `execveat` - Enables fileless execution (bypass Landlock)
//! - `setresuid`/`setresgid` - No reason to change UID in sandbox
//! - `setsid`/`setpgid` - Session manipulation, unnecessary
//! - `ioctl` - Allowed with argument filtering (TIOCSTI, TIOCSETD, TIOCLINUX blocked)
//!
//! ## Security Notes
//!
//! - Filter is permanent - cannot be removed once applied
//! - Requires `PR_SET_NO_NEW_PRIVS` first
//! - Blocked syscall = immediate process termination (SIGSYS)
//! - `kill`/`tgkill` are safe due to Landlock v5 `SCOPE_SIGNAL` isolation
//! - `prctl` allowed but `PR_SET_SECCOMP` has no effect (filter already applied)

use rustix::io::Errno;

use crate::last_errno;

// Seccomp constants
const SECCOMP_SET_MODE_FILTER: u32 = 1;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc00000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
// Return ENOSYS (38) to allow graceful fallback
const SECCOMP_RET_ERRNO_ENOSYS: u32 = 0x00050000 | 38;

// BPF instruction classes
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;

// BPF ld/ldx fields
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;

// BPF alu/jmp fields
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;

const AUDIT_ARCH_X86_64: u32 = 0xc000003e;

// seccomp_data offsets (x86_64)
const OFFSET_SYSCALL_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;
const OFFSET_ARGS_0: u32 = 16; // args[0], lower 32 bits
const OFFSET_ARGS_1: u32 = 24; // args[1], lower 32 bits

// Clone flags that create new namespaces - blocked to prevent sandbox escape
const CLONE_NEWNS: u32 = 0x00020000;
const CLONE_NEWCGROUP: u32 = 0x02000000;
const CLONE_NEWUTS: u32 = 0x04000000;
const CLONE_NEWIPC: u32 = 0x08000000;
const CLONE_NEWUSER: u32 = 0x10000000;
const CLONE_NEWPID: u32 = 0x20000000;
const CLONE_NEWNET: u32 = 0x40000000;

/// Combined mask of all blocked clone flags.
const BLOCKED_CLONE_FLAGS: u32 = CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET;

// Socket constants
const AF_NETLINK: u32 = 16; // Kernel netlink (nf_tables, etc.) - BLOCKED
const SOCK_RAW: u32 = 3; // Raw sockets - BLOCKED

// Dangerous ioctl commands - BLOCKED
// See: https://madaidans-insecurities.github.io/guides/linux-hardening.html
// TIOCSTI: Inject terminal input - sandbox escape vector
const TIOCSTI: u32 = 0x5412;
// TIOCSETD: Load TTY line disciplines - multiple exploits (CVE-2017-2636, etc.)
const TIOCSETD: u32 = 0x5423;
// TIOCLINUX: Linux-specific terminal ops - can inject input on virtual consoles
const TIOCLINUX: u32 = 0x541C;

/// Maximum whitelist size (BPF jump offsets are u8)
const MAX_WHITELIST_SIZE: usize = 200;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl SockFilter {
    #[inline]
    pub const fn stmt(code: u16, k: u32) -> Self {
        Self {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    #[inline]
    pub const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Self {
        Self { code, jt, jf, k }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

/// Syscalls allowed in the sandbox.
///
/// ## Special handling (not in this list):
/// - `clone` - Allowed with flag filtering (blocks `CLONE_NEW`*)
/// - `clone3` - Returns ENOSYS (glibc falls back to `clone`)
/// - `socket` - Allowed with domain/type filtering (blocks `AF_NETLINK`, `SOCK_RAW`)
/// - `ioctl` - Allowed with command filtering (blocks `TIOCSTI`, `TIOCSETD`, `TIOCLINUX`)
///
/// ## Removed for security:
/// - `memfd_create` - With execveat enables fileless execution
/// - `execveat` - Removed to prevent fileless execution
/// - `setresuid`/`setresgid` - No need to change UID in sandbox
/// - `setsid`/`setpgid` - Session manipulation unnecessary
///
/// ## Notes:
/// - `kill`/`tgkill` safe due to Landlock v5 `SCOPE_SIGNAL` isolation
/// - `prctl` kept for runtime needs (`PR_SET_NAME`, etc.)
pub const DEFAULT_WHITELIST: &[i64] = &[
    // === Basic I/O ===
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_close,
    libc::SYS_close_range, // Modern fd range closing
    libc::SYS_fstat,
    libc::SYS_lseek,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_preadv,
    libc::SYS_pwritev,
    libc::SYS_preadv2,
    libc::SYS_pwritev2,
    libc::SYS_dup,
    libc::SYS_dup2,
    libc::SYS_dup3,
    libc::SYS_fcntl,
    libc::SYS_flock,
    libc::SYS_fsync,
    libc::SYS_fdatasync,
    libc::SYS_ftruncate,
    libc::SYS_fadvise64,
    libc::SYS_access,
    libc::SYS_pipe,
    libc::SYS_pipe2,
    libc::SYS_select,
    libc::SYS_poll,
    libc::SYS_ppoll,
    libc::SYS_pselect6,
    // Efficient file operations (Python/Node use these)
    libc::SYS_sendfile,
    libc::SYS_copy_file_range,
    libc::SYS_splice,
    libc::SYS_tee,
    // === Memory ===
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_brk,
    libc::SYS_mremap,
    libc::SYS_msync,
    libc::SYS_mincore,
    libc::SYS_madvise,
    // memfd_create REMOVED - enables fileless execution with execveat
    libc::SYS_membarrier,
    libc::SYS_mlock,
    libc::SYS_mlock2,
    libc::SYS_munlock,
    libc::SYS_mlockall,
    libc::SYS_munlockall,
    // === Process info (read-only) ===
    libc::SYS_getpid,
    libc::SYS_getppid,
    libc::SYS_gettid, // Thread ID (used by Python, Go, etc.)
    libc::SYS_getuid,
    libc::SYS_getgid,
    libc::SYS_geteuid,
    libc::SYS_getegid,
    libc::SYS_getresuid,
    libc::SYS_getresgid,
    // setresuid/setresgid REMOVED - no need to change UID in sandbox
    libc::SYS_getpgrp,
    // setpgid/setsid REMOVED - session manipulation unnecessary
    libc::SYS_getgroups,
    libc::SYS_getsid,
    libc::SYS_uname,
    libc::SYS_getrusage,
    libc::SYS_times,
    libc::SYS_sysinfo,
    // === Time ===
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_clock_nanosleep,
    libc::SYS_gettimeofday,
    libc::SYS_nanosleep,
    // === Filesystem (Landlock restricts actual access) ===
    libc::SYS_openat,
    libc::SYS_open,
    libc::SYS_creat,
    libc::SYS_unlink,
    libc::SYS_unlinkat,
    libc::SYS_rename,
    libc::SYS_renameat,
    libc::SYS_renameat2,
    libc::SYS_mkdir,
    libc::SYS_mkdirat,
    libc::SYS_rmdir,
    libc::SYS_symlink,
    libc::SYS_symlinkat,
    libc::SYS_link,
    libc::SYS_linkat,
    libc::SYS_chmod,
    libc::SYS_fchmod,
    libc::SYS_fchmodat,
    libc::SYS_chown,
    libc::SYS_fchown,
    libc::SYS_fchownat,
    libc::SYS_lchown,
    libc::SYS_utimensat,
    libc::SYS_faccessat,
    libc::SYS_faccessat2,
    libc::SYS_stat,
    libc::SYS_lstat,
    libc::SYS_newfstatat,
    libc::SYS_statfs,
    libc::SYS_fstatfs,
    libc::SYS_statx,
    libc::SYS_getdents,
    libc::SYS_getdents64,
    libc::SYS_getcwd,
    libc::SYS_chdir,
    libc::SYS_fchdir,
    libc::SYS_readlink,
    libc::SYS_readlinkat,
    // === Signals (safe due to Landlock SCOPE_SIGNAL) ===
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_rt_sigsuspend,
    libc::SYS_rt_sigpending,
    libc::SYS_rt_sigtimedwait,
    libc::SYS_sigaltstack,
    libc::SYS_kill,   // Safe: Landlock SCOPE_SIGNAL isolates
    libc::SYS_tgkill, // Safe: Landlock SCOPE_SIGNAL isolates
    libc::SYS_tkill,  // Safe: Landlock SCOPE_SIGNAL isolates
    // === Process control ===
    libc::SYS_execve,
    // execveat REMOVED - with memfd_create enables fileless execution
    libc::SYS_fork,  // Safe: no flags
    libc::SYS_vfork, // Safe: no flags
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_wait4,
    libc::SYS_waitid,
    libc::SYS_set_tid_address,
    libc::SYS_futex,
    libc::SYS_get_robust_list,
    libc::SYS_set_robust_list,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity, // Go runtime needs
    libc::SYS_sched_setaffinity, // Go runtime needs
    libc::SYS_sched_getparam,
    libc::SYS_sched_setparam,
    libc::SYS_sched_getscheduler,
    libc::SYS_sched_get_priority_max,
    libc::SYS_sched_get_priority_min,
    libc::SYS_arch_prctl,
    libc::SYS_prctl, // Kept for PR_SET_NAME, etc. PR_SET_SECCOMP is no-op
    libc::SYS_getrandom,
    libc::SYS_prlimit64,
    libc::SYS_rseq,
    libc::SYS_ioprio_get,
    // === Terminal/Device I/O ===
    // ioctl is handled specially below - blocks TIOCSTI, TIOCSETD, TIOCLINUX
    // (not in whitelist, filtered like socket)
    // === Event mechanisms ===
    libc::SYS_eventfd,
    libc::SYS_eventfd2,
    libc::SYS_epoll_create,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_wait,
    libc::SYS_epoll_pwait,
    libc::SYS_epoll_pwait2,
    libc::SYS_timerfd_create,
    libc::SYS_timerfd_settime,
    libc::SYS_timerfd_gettime,
    libc::SYS_signalfd,
    libc::SYS_signalfd4,
    // === Sockets (filtered separately for domain/type) ===
    // SYS_socket handled specially - blocks AF_NETLINK, SOCK_RAW
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_setsockopt,
    libc::SYS_getsockopt,
    libc::SYS_shutdown,
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_sendmmsg,
    libc::SYS_recvmmsg,
];

/// Builds a BPF filter with clone and socket argument filtering.
///
/// ## Filter Layout
///
/// ```text
/// [0-2]   Architecture check (x86_64)
/// [3]     Load syscall number
/// [4]     clone3 -> KILL
/// [5]     clone -> clone_handler
/// [6]     socket -> socket_handler
/// [7..N]  Whitelist checks -> ALLOW
/// [N+1]   RET KILL (default deny)
/// [N+2]   RET ALLOW
/// [N+3-6] Clone handler (load flags, JSET, ALLOW/KILL)
/// [N+7-12] Socket handler (check AF_NETLINK, check SOCK_RAW)
/// ```
///
/// # Panics
///
/// Panics if `syscalls.len()` > 200 (BPF jump offsets are u8)
pub fn build_whitelist_filter(syscalls: &[i64]) -> Vec<SockFilter> {
    assert!(
        syscalls.len() <= MAX_WHITELIST_SIZE,
        "whitelist too large: {} > {} (BPF jump offset overflow)",
        syscalls.len(),
        MAX_WHITELIST_SIZE
    );

    let n = syscalls.len();
    let mut filter = Vec::with_capacity(n + 20);

    // === Architecture check ===
    filter.push(SockFilter::stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH));
    filter.push(SockFilter::jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH_X86_64,
        1,
        0,
    ));
    filter.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // === Load syscall number ===
    filter.push(SockFilter::stmt(
        BPF_LD | BPF_W | BPF_ABS,
        OFFSET_SYSCALL_NR,
    ));

    // === clone3 -> ERRNO(ENOSYS) ===
    // Return ENOSYS to allow glibc to fall back to clone() syscall.
    // We can't inspect clone3 args (struct pointer), so we block it but gracefully.
    // Jump to ERRNO: skip clone + socket + ioctl checks + whitelist + KILL + ALLOW
    let clone3_errno_offset = (3 + n + 2) as u8;
    filter.push(SockFilter::jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_clone3 as u32,
        clone3_errno_offset,
        0,
    ));

    // === clone -> clone_handler ===
    // Jump to clone handler: skip socket + ioctl checks + whitelist + KILL + ALLOW + ERRNO
    let clone_handler_offset = (2 + n + 3) as u8;
    filter.push(SockFilter::jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_clone as u32,
        clone_handler_offset,
        0,
    ));

    // === socket -> socket_handler ===
    // Jump to socket handler: skip ioctl check + whitelist + KILL + ALLOW + ERRNO + clone_handler(4)
    let socket_handler_offset = (1 + n + 3 + 4) as u8;
    filter.push(SockFilter::jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_socket as u32,
        socket_handler_offset,
        0,
    ));

    // === ioctl -> ioctl_handler ===
    // Jump to ioctl handler: skip whitelist + KILL + ALLOW + ERRNO + clone_handler(4) + socket_handler(6)
    let ioctl_handler_offset = (n + 3 + 4 + 6) as u8;
    filter.push(SockFilter::jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_ioctl as u32,
        ioctl_handler_offset,
        0,
    ));

    // === Whitelist check ===
    for (i, &nr) in syscalls.iter().enumerate() {
        let allow_offset = (n - i) as u8;
        filter.push(SockFilter::jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            nr as u32,
            allow_offset,
            0,
        ));
    }

    // === Default deny ===
    filter.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // === ALLOW ===
    filter.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // === ERRNO(ENOSYS) for clone3 ===
    // This allows glibc to gracefully fall back to clone()
    filter.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO_ENOSYS));

    // === Clone handler (4 instructions) ===
    // Load clone flags (args[0])
    filter.push(SockFilter::stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS_0));
    // Check blocked flags
    filter.push(SockFilter::jump(
        BPF_JMP | BPF_JSET | BPF_K,
        BLOCKED_CLONE_FLAGS,
        1,
        0,
    ));
    // No blocked flags -> ALLOW
    filter.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    // Blocked flags -> KILL
    filter.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // === Socket handler (6 instructions) ===
    // Load socket domain (args[0])
    filter.push(SockFilter::stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS_0));
    // Block AF_NETLINK (domain 16) - access to nf_tables, etc.
    filter.push(SockFilter::jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        AF_NETLINK,
        3,
        0,
    )); // -> KILL

    // Load socket type (args[1])
    filter.push(SockFilter::stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS_1));
    // Block SOCK_RAW (type 3) - but need to mask out flags (SOCK_NONBLOCK, etc.)
    // SOCK_RAW = 3, SOCK_NONBLOCK = 0x800, SOCK_CLOEXEC = 0x80000
    // We check if (type & 0xF) == SOCK_RAW
    filter.push(SockFilter::jump(BPF_JMP | BPF_JEQ | BPF_K, SOCK_RAW, 1, 0)); // -> KILL

    // Socket OK -> ALLOW
    filter.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    // Socket blocked -> KILL
    filter.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // === Ioctl handler (6 instructions) ===
    // Block dangerous ioctls that can escape sandbox:
    // - TIOCSTI: inject terminal input (sandbox escape)
    // - TIOCSETD: load TTY line disciplines (multiple CVEs)
    // - TIOCLINUX: Linux terminal ops (input injection)
    // Load ioctl command (args[1])
    filter.push(SockFilter::stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS_1));
    // Block TIOCSTI (0x5412) - jt=3 lands on KILL
    filter.push(SockFilter::jump(BPF_JMP | BPF_JEQ | BPF_K, TIOCSTI, 3, 0));
    // Block TIOCSETD (0x5423) - jt=2 lands on KILL
    filter.push(SockFilter::jump(BPF_JMP | BPF_JEQ | BPF_K, TIOCSETD, 2, 0));
    // Block TIOCLINUX (0x541C) - jt=1 lands on KILL
    filter.push(SockFilter::jump(BPF_JMP | BPF_JEQ | BPF_K, TIOCLINUX, 1, 0));
    // Ioctl OK -> ALLOW
    filter.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    // Ioctl blocked -> KILL
    filter.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    filter
}

/// Applies a seccomp-BPF filter to the current thread.
///
/// # Safety
///
/// This permanently restricts syscalls for this thread. The filter must be valid.
///
/// # Errors
///
/// Returns `Errno` if the filter cannot be applied.
pub unsafe fn seccomp_set_mode_filter(fprog: &SockFprog) -> Result<(), Errno> {
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(last_errno());
    }

    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0u32,
            fprog as *const _,
        )
    };
    if ret != 0 { Err(last_errno()) } else { Ok(()) }
}

/// Returns true if seccomp is available.
pub fn seccomp_available() -> bool {
    unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) >= 0 }
}

/// Builds a BPF filter that returns `SECCOMP_RET_USER_NOTIF` for the listed
/// syscalls and `SECCOMP_RET_ALLOW` for everything else.
///
/// This filter is installed *before* the kill filter. The kernel evaluates all
/// stacked filters and returns the strictest verdict, so:
/// - Syscall in both ALLOW lists → ALLOW
/// - Syscall in NOTIFY + ALLOW → NOTIFY (supervisor decides)
/// - Syscall not in kill filter whitelist → KILL (regardless of notify filter)
///
/// # Panics
///
/// Panics if `syscalls.len()` > 200 (BPF jump offsets are u8).
pub fn build_notify_filter(syscalls: &[i64]) -> Vec<SockFilter> {
    assert!(
        syscalls.len() <= MAX_WHITELIST_SIZE,
        "notify syscall list too large: {} > {}",
        syscalls.len(),
        MAX_WHITELIST_SIZE
    );

    let n = syscalls.len();
    let mut filter = Vec::with_capacity(n + 8);

    // Architecture check
    filter.push(SockFilter::stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH));
    filter.push(SockFilter::jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH_X86_64,
        1,
        0,
    ));
    filter.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // Load syscall number
    filter.push(SockFilter::stmt(
        BPF_LD | BPF_W | BPF_ABS,
        OFFSET_SYSCALL_NR,
    ));

    // Check each syscall → jump to NOTIFY
    for (i, &nr) in syscalls.iter().enumerate() {
        let notify_offset = (n - i) as u8; // jump to NOTIFY instruction
        filter.push(SockFilter::jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            nr as u32,
            notify_offset,
            0,
        ));
    }

    // Default: ALLOW
    filter.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // NOTIFY
    filter.push(SockFilter::stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF));

    filter
}

/// Syscalls that are intercepted by the notify filter for filesystem virtualization.
pub const NOTIFY_FS_SYSCALLS: &[i64] = &[
    libc::SYS_openat,
    libc::SYS_open,
    libc::SYS_creat,
    libc::SYS_access,
    libc::SYS_faccessat,
    libc::SYS_faccessat2,
    libc::SYS_stat,
    libc::SYS_lstat,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_readlink,
    libc::SYS_readlinkat,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_structure() {
        let syscalls = &[libc::SYS_read, libc::SYS_write, libc::SYS_exit];
        let filter = build_whitelist_filter(syscalls);
        // 3 (arch) + 1 (load) + 4 (clone3/clone/socket/ioctl) + 3 (whitelist) + 3 (kill/allow/errno)
        // + 4 (clone handler) + 6 (socket handler) + 6 (ioctl handler) = 30
        assert_eq!(filter.len(), 30);
    }

    #[test]
    fn clone3_returns_enosys() {
        let filter = build_whitelist_filter(DEFAULT_WHITELIST);
        let clone3_check = &filter[4];
        assert_eq!(clone3_check.k, libc::SYS_clone3 as u32);
        assert!(clone3_check.jt > 0);
        // clone3 should jump to ERRNO instruction, not KILL
    }

    #[test]
    fn clone_has_flag_check() {
        let filter = build_whitelist_filter(DEFAULT_WHITELIST);
        let clone_check = &filter[5];
        assert_eq!(clone_check.k, libc::SYS_clone as u32);
        assert!(clone_check.jt > 0);

        let has_jset = filter
            .iter()
            .any(|f| f.code == (BPF_JMP | BPF_JSET | BPF_K));
        assert!(has_jset);
    }

    #[test]
    fn socket_is_filtered() {
        let filter = build_whitelist_filter(DEFAULT_WHITELIST);
        let socket_check = &filter[6];
        assert_eq!(socket_check.k, libc::SYS_socket as u32);
        assert!(socket_check.jt > 0);
    }

    #[test]
    fn ioctl_is_filtered() {
        let filter = build_whitelist_filter(DEFAULT_WHITELIST);
        let ioctl_check = &filter[7];
        assert_eq!(ioctl_check.k, libc::SYS_ioctl as u32);
        assert!(ioctl_check.jt > 0);
    }

    #[test]
    fn blocked_clone_flags_mask() {
        assert_ne!(BLOCKED_CLONE_FLAGS & CLONE_NEWUSER, 0);
        assert_ne!(BLOCKED_CLONE_FLAGS & CLONE_NEWNET, 0);
        assert_ne!(BLOCKED_CLONE_FLAGS & CLONE_NEWNS, 0);
        assert_ne!(BLOCKED_CLONE_FLAGS & CLONE_NEWPID, 0);
        assert_ne!(BLOCKED_CLONE_FLAGS & CLONE_NEWIPC, 0);
        assert_ne!(BLOCKED_CLONE_FLAGS & CLONE_NEWUTS, 0);
        assert_ne!(BLOCKED_CLONE_FLAGS & CLONE_NEWCGROUP, 0);
    }

    #[test]
    fn dangerous_syscalls_removed() {
        // These should NOT be in the whitelist
        assert!(!DEFAULT_WHITELIST.contains(&libc::SYS_clone));
        assert!(!DEFAULT_WHITELIST.contains(&libc::SYS_clone3));
        assert!(!DEFAULT_WHITELIST.contains(&libc::SYS_socket)); // Filtered separately
        assert!(!DEFAULT_WHITELIST.contains(&libc::SYS_memfd_create));
        assert!(!DEFAULT_WHITELIST.contains(&libc::SYS_execveat));
        assert!(!DEFAULT_WHITELIST.contains(&libc::SYS_setresuid));
        assert!(!DEFAULT_WHITELIST.contains(&libc::SYS_setresgid));
        assert!(!DEFAULT_WHITELIST.contains(&libc::SYS_setsid));
        assert!(!DEFAULT_WHITELIST.contains(&libc::SYS_setpgid));
        // Note: ioctl is now allowed as it's needed for terminal ops and Landlock restricts device access
    }

    #[test]
    fn safe_syscalls_present() {
        assert!(DEFAULT_WHITELIST.contains(&libc::SYS_fork));
        assert!(DEFAULT_WHITELIST.contains(&libc::SYS_vfork));
        assert!(DEFAULT_WHITELIST.contains(&libc::SYS_execve));
        assert!(DEFAULT_WHITELIST.contains(&libc::SYS_sendfile));
        assert!(DEFAULT_WHITELIST.contains(&libc::SYS_close_range));
    }

    #[test]
    #[should_panic(expected = "whitelist too large")]
    fn whitelist_overflow_panics() {
        let huge: Vec<i64> = (0..300).map(|i| i as i64).collect();
        build_whitelist_filter(&huge);
    }

    #[test]
    fn notify_filter_structure() {
        let syscalls = &[libc::SYS_openat, libc::SYS_open, libc::SYS_stat];
        let filter = build_notify_filter(syscalls);
        // 3 (arch) + 1 (load) + 3 (checks) + 1 (allow) + 1 (notify) = 9
        assert_eq!(filter.len(), 9);
    }

    #[test]
    fn notify_fs_syscalls_present() {
        assert!(NOTIFY_FS_SYSCALLS.contains(&libc::SYS_openat));
        assert!(NOTIFY_FS_SYSCALLS.contains(&libc::SYS_open));
        assert!(NOTIFY_FS_SYSCALLS.contains(&libc::SYS_stat));
        assert!(NOTIFY_FS_SYSCALLS.contains(&libc::SYS_readlink));
    }
}
