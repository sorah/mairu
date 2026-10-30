//! Peer verification through `SO_PEERCRED`, pinned with pidfds.

pub mod peer;
pub mod procfs;

#[derive(Debug)]
pub struct LinuxProcess;

/// What is read about a peer while its pidfd pins it.
#[derive(Debug)]
struct Pinned {
    pidfd: std::os::fd::OwnedFd,
    start_time: u64,
    real_gid: u32,
    exe: Option<std::path::PathBuf>,
}

impl Pinned {
    fn obtain(fd: std::os::fd::BorrowedFd<'_>, pid: u32) -> std::io::Result<Self> {
        // pidfd_open leaves a pid-reuse window since connect(), which only affects attribution.
        let pidfd = match peer::peer_pidfd(fd)? {
            Some(pidfd) => pidfd,
            None => peer::pidfd_open(pid)?,
        };
        Self::read(pid, pidfd)
    }

    fn read(pid: u32, pidfd: std::os::fd::OwnedFd) -> std::io::Result<Self> {
        use std::os::fd::AsFd;
        let stat = procfs::Stat::read(pid)?;
        let real_gid = procfs::read_real_gid(pid)?;
        let exe = procfs::read_exe(pid).ok();
        if !peer::pidfd_alive(pidfd.as_fd()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("peer pid {pid} exited while being inspected"),
            ));
        }
        Ok(Self {
            pidfd,
            start_time: stat.start_time,
            real_gid,
            exe,
        })
    }
}

impl LinuxProcess {
    fn inspect(
        fd: std::os::fd::BorrowedFd<'_>,
        state: &crate::hardening::HardeningState,
        euid: u32,
    ) -> crate::Result<crate::platform::PeerIdentity> {
        let cred = peer::PeerCred::read(fd)?;
        if cred.uid != euid {
            return Err(crate::Error::PeerError(format!(
                "peer pid {} runs as uid {}, not {euid}",
                cred.pid, cred.uid
            )));
        }
        let hardened = matches!(state, crate::hardening::HardeningState::Hardened { .. });
        let pinned = match Pinned::obtain(fd, cred.pid) {
            Ok(p) => Some(p),
            Err(e) if hardened => return Err(e.into()),
            Err(e) => {
                tracing::debug!(pid = cred.pid, err = ?e, "Could not pin the peer; continuing unhardened");
                None
            }
        };
        let real_gid = pinned.as_ref().map(|p| p.real_gid);
        let trust = crate::platform::PeerTrust::evaluate(state, cred.gid, real_gid);
        if trust == crate::platform::PeerTrust::Rejected {
            tracing::warn!(
                pid = cred.pid,
                uid = cred.uid,
                gid = cred.gid,
                real_gid = ?real_gid,
                "Peer is not hardened mairu; serving it diagnostics only"
            );
        }
        Ok(match pinned {
            Some(p) => crate::platform::PeerIdentity {
                uid: cred.uid,
                gid: cred.gid,
                real_gid,
                pid: cred.pid,
                pidfd: Some(p.pidfd),
                start_time: p.start_time,
                exe: p.exe,
                trust,
            },
            None => crate::platform::PeerIdentity {
                uid: cred.uid,
                gid: cred.gid,
                real_gid: None,
                pid: cred.pid,
                pidfd: None,
                start_time: 0,
                exe: None,
                trust,
            },
        })
    }

    fn peer_pidfd_supported() -> bool {
        static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *SUPPORTED.get_or_init(|| {
            use std::os::fd::AsFd;
            std::os::unix::net::UnixStream::pair()
                .and_then(|(a, _b)| peer::peer_pidfd(a.as_fd()))
                .is_ok_and(|p| p.is_some())
        })
    }

    fn pidfd_supported() -> bool {
        peer::pidfd_open(std::process::id()).is_ok()
    }
}

impl crate::platform::ProcessPlatform for LinuxProcess {
    fn inspect_peer(
        &self,
        stream: &tokio::net::UnixStream,
    ) -> crate::Result<crate::platform::PeerIdentity> {
        use std::os::fd::AsFd;
        Self::inspect(
            stream.as_fd(),
            crate::hardening::Hardening::state(),
            nix::unistd::geteuid().as_raw(),
        )
    }

    fn verify_agent(
        &self,
        stream: &std::os::unix::net::UnixStream,
    ) -> crate::Result<crate::platform::AgentIdentity> {
        use std::os::fd::AsFd;
        let cred = peer::PeerCred::read(stream.as_fd())?;
        let euid = nix::unistd::geteuid().as_raw();
        if cred.uid != euid {
            return Err(crate::Error::PeerError(format!(
                "agent pid {} runs as uid {}, not {euid}",
                cred.pid, cred.uid
            )));
        }
        let state = crate::hardening::Hardening::state();
        let real_gid = match state {
            crate::hardening::HardeningState::Hardened { .. } => {
                procfs::read_real_gid(cred.pid).ok()
            }
            _ => None,
        };
        Ok(crate::platform::AgentIdentity {
            pid: Some(cred.pid),
            trust: crate::platform::AgentTrust::evaluate(state, cred.gid, real_gid),
        })
    }

    fn peer_verification(&self) -> crate::proto::platform::PeerVerification {
        match crate::hardening::Hardening::marker() {
            Some(_) => crate::proto::platform::PeerVerification::Setgid,
            None => crate::proto::platform::PeerVerification::None,
        }
    }

    fn notes(&self) -> Vec<String> {
        let mut notes = vec![];
        if !Self::pidfd_supported() {
            notes.push("pidfd unavailable (Linux 5.3+); hardened mode cannot pin peers".to_owned());
        } else if !Self::peer_pidfd_supported() {
            notes.push(
                "SO_PEERPIDFD unavailable (Linux 6.5+); peer attribution has a small pid-reuse window"
                    .to_owned(),
            );
        }
        notes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    fn hardened(marker: u32) -> crate::hardening::HardeningState {
        crate::hardening::HardeningState::Hardened {
            marker: nix::unistd::Gid::from_raw(marker),
        }
    }

    fn unhardened() -> crate::hardening::HardeningState {
        crate::hardening::HardeningState::Unhardened {
            setgid_other_group: None,
        }
    }

    fn euid() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    #[test]
    fn test_inspect_socketpair_unhardened() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let peer = LinuxProcess::inspect(a.as_fd(), &unhardened(), euid()).unwrap();
        assert_eq!(peer.pid, std::process::id());
        assert_eq!(peer.uid, euid());
        assert_eq!(peer.real_gid, Some(nix::unistd::getgid().as_raw()));
        assert!(peer.pidfd.is_some());
        assert!(peer.start_time > 0);
        assert_eq!(peer.trust, crate::platform::PeerTrust::Unverifiable);
    }

    #[test]
    fn test_inspect_socketpair_hardened_without_marker() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let egid = nix::unistd::getegid().as_raw();
        let peer = LinuxProcess::inspect(a.as_fd(), &hardened(egid + 1), euid()).unwrap();
        assert_eq!(peer.trust, crate::platform::PeerTrust::Rejected);
    }

    #[test]
    fn test_inspect_socketpair_hardened_real_gid_is_marker() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        // This process's real and effective gids are equal, as after newgrp.
        let egid = nix::unistd::getegid().as_raw();
        let peer = LinuxProcess::inspect(a.as_fd(), &hardened(egid), euid()).unwrap();
        assert_eq!(peer.trust, crate::platform::PeerTrust::Rejected);
    }

    #[test]
    fn test_inspect_other_uid_is_refused() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let err = LinuxProcess::inspect(a.as_fd(), &unhardened(), euid() + 1).unwrap_err();
        assert!(matches!(err, crate::Error::PeerError(_)), "{err:?}");
    }

    #[test]
    fn test_read_detects_dead_pidfd() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pidfd = peer::pidfd_open(child.id()).unwrap();
        child.wait().unwrap();
        // The pid now names another process, as after pid reuse.
        let err = Pinned::read(std::process::id(), pidfd).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn test_read_live_pidfd() {
        let pidfd = peer::pidfd_open(std::process::id()).unwrap();
        let pinned = Pinned::read(std::process::id(), pidfd).unwrap();
        assert!(pinned.start_time > 0);
    }
}
