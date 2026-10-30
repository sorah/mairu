//! `SO_PEERCRED` and pidfds.

/// Credentials of a Unix socket peer at `connect()`, or of the listener at `listen()` when read on the client side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

impl PeerCred {
    pub fn read(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<Self> {
        let cred = nix::sys::socket::getsockopt(&fd, nix::sys::socket::sockopt::PeerCredentials)?;
        let pid = u32::try_from(cred.pid())
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| std::io::Error::other("peer has no pid in SO_PEERCRED"))?;
        Ok(Self {
            pid,
            uid: cred.uid(),
            gid: cred.gid(),
        })
    }
}

/// The peer's pidfd from `SO_PEERPIDFD` (Linux 6.5+). `Ok(None)` when the kernel lacks it.
pub fn peer_pidfd(
    fd: std::os::fd::BorrowedFd<'_>,
) -> std::io::Result<Option<std::os::fd::OwnedFd>> {
    match nix::sys::socket::getsockopt(&fd, nix::sys::socket::sockopt::PeerPidfd) {
        Ok(pidfd) => Ok(Some(pidfd)),
        Err(nix::errno::Errno::ENOPROTOOPT) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// `pidfd_open(2)` (Linux 5.3+).
pub fn pidfd_open(pid: u32) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let pid = libc::pid_t::try_from(pid).map_err(std::io::Error::other)?;
    // SAFETY: pidfd_open takes no pointers. A non-negative return value is a new fd we own.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = std::os::fd::RawFd::try_from(fd).map_err(std::io::Error::other)?;
    // SAFETY: fd is a fresh descriptor returned by the kernel.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// Whether the process behind `pidfd` has not exited, via `pidfd_send_signal(pidfd, 0)`.
pub fn pidfd_alive(pidfd: std::os::fd::BorrowedFd<'_>) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: a null siginfo is allowed; signal 0 only checks for existence.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    ret == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn test_peer_cred_socketpair() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let cred = PeerCred::read(a.as_fd()).unwrap();
        assert_eq!(cred.pid, std::process::id());
        assert_eq!(cred.uid, nix::unistd::geteuid().as_raw());
        assert_eq!(cred.gid, nix::unistd::getegid().as_raw());
    }

    #[test]
    fn test_pidfd_alive_self() {
        let pidfd = pidfd_open(std::process::id()).unwrap();
        assert!(pidfd_alive(pidfd.as_fd()));
    }

    #[test]
    fn test_pidfd_dead_child() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pidfd = pidfd_open(child.id()).unwrap();
        child.wait().unwrap();
        assert!(!pidfd_alive(pidfd.as_fd()));
    }
}
