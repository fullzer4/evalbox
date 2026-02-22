//! Unix socket fd passing via `SCM_RIGHTS`.
//!
//! After the child installs its seccomp notify filter, it receives a listener fd.
//! This fd must be passed to the parent process so the parent can handle
//! notifications. We use `SCM_RIGHTS` over an `AF_UNIX` socketpair to transfer
//! the fd across the fork boundary.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

/// Create an `AF_UNIX SOCK_STREAM` socketpair.
///
/// Returns `(parent_sock, child_sock)`. After fork, parent closes `child_sock`
/// and child closes `parent_sock`.
pub fn create_socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    let ret = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Send a file descriptor over a unix socket using `SCM_RIGHTS`.
pub fn send_fd(socket: RawFd, fd: RawFd) -> io::Result<()> {
    let data = [0u8; 1];
    let iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: 1,
    };

    // cmsg buffer: header + one fd
    let cmsg_space = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_space;

    // Fill control message
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(io::Error::other("CMSG_FIRSTHDR null"));
    }
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize;
        let data_ptr = libc::CMSG_DATA(cmsg);
        std::ptr::copy_nonoverlapping(
            (&fd as *const RawFd).cast::<u8>(),
            data_ptr,
            size_of::<RawFd>(),
        );
    }

    let ret = unsafe { libc::sendmsg(socket, &msg, 0) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Receive a file descriptor from a unix socket using `SCM_RIGHTS`.
pub fn recv_fd(socket: RawFd) -> io::Result<OwnedFd> {
    let mut data = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: 1,
    };

    let cmsg_space = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_space;

    let ret = unsafe { libc::recvmsg(socket, &mut msg, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no control message received",
        ));
    }

    unsafe {
        if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected control message type",
            ));
        }
        let mut fd: RawFd = 0;
        let data_ptr = libc::CMSG_DATA(cmsg);
        std::ptr::copy_nonoverlapping(
            data_ptr,
            (&mut fd as *mut RawFd).cast::<u8>(),
            size_of::<RawFd>(),
        );
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;

    #[test]
    fn socketpair_creation() {
        let (a, b) = create_socketpair().unwrap();
        assert!(a.as_raw_fd() >= 0);
        assert!(b.as_raw_fd() >= 0);
        assert_ne!(a.as_raw_fd(), b.as_raw_fd());
    }

    #[test]
    fn send_recv_fd() {
        let (parent, child) = create_socketpair().unwrap();

        // Create a pipe and send its read end
        let mut pipe_fds = [0i32; 2];
        unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        let pipe_read = pipe_fds[0];
        let pipe_write = pipe_fds[1];

        send_fd(child.as_raw_fd(), pipe_read).unwrap();
        let received = recv_fd(parent.as_raw_fd()).unwrap();

        // The received fd should be valid and different from the original
        assert!(received.as_raw_fd() >= 0);

        // Clean up
        unsafe {
            libc::close(pipe_read);
            libc::close(pipe_write);
        }
    }
}
