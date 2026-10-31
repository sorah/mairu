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

    /// Reads the peer's stat, and confirms afterwards that it was the peer's: same start time, pidfd still alive.
    fn peer_stat(peer: &crate::platform::PeerIdentity) -> Option<procfs::Stat> {
        use std::os::fd::AsFd;
        let stat = procfs::Stat::read(peer.pid).ok()?;
        if peer.start_time != 0 && stat.start_time != peer.start_time {
            return None;
        }
        match &peer.pidfd {
            Some(pidfd) if !peer::pidfd_alive(pidfd.as_fd()) => None,
            _ => Some(stat),
        }
    }
}

/// One ancestor's facts, read while its pidfd pins it. `None` when it runs as another uid or exits meanwhile.
fn read_ancestor(
    pid: u32,
    uid: u32,
) -> Option<(
    crate::platform::Ancestor,
    procfs::Stat,
    std::os::fd::OwnedFd,
)> {
    use std::os::fd::AsFd;
    let pidfd = peer::pidfd_open(pid).ok()?;
    let stat = procfs::Stat::read(pid).ok()?;
    let (ruid, euid) = procfs::read_uids(pid).ok()?;
    if ruid != uid || euid != uid {
        return None;
    }
    let mut argv = procfs::read_cmdline(pid).unwrap_or_default();
    argv.truncate(2);
    let session = u32::try_from(stat.session)
        .ok()
        .filter(|sid| *sid > 0)
        .and_then(|sid| procfs::Stat::read(sid).ok())
        .filter(|leader| leader.session == stat.session)
        .map(|leader| crate::platform::SessionIdentity::Tty {
            sid: stat.session,
            leader_start_time: leader.start_time,
        });
    let ancestor = crate::platform::Ancestor {
        pid,
        comm: procfs::read_comm(pid).ok(),
        // Unreadable for a non-dumpable process; the other names still count.
        exe: procfs::read_exe(pid).ok(),
        argv,
        session,
    };
    peer::pidfd_alive(pidfd.as_fd()).then_some((ancestor, stat, pidfd))
}

/// The session rule over `/proc/<pid>/stat` contents; `read` looks up another pid.
fn session_identity_from(
    stat: &procfs::Stat,
    read: impl Fn(i32) -> Option<procfs::Stat>,
) -> Option<crate::platform::SessionIdentity> {
    if stat.tty_nr != 0
        && stat.session > 0
        && let Some(leader) = read(stat.session)
        && leader.session == stat.session
    {
        return Some(crate::platform::SessionIdentity::Tty {
            sid: stat.session,
            leader_start_time: leader.start_time,
        });
    }
    if stat.ppid > 1
        && let Some(parent) = read(stat.ppid)
    {
        return Some(crate::platform::SessionIdentity::Parent {
            ppid: stat.ppid,
            start_time: parent.start_time,
        });
    }
    None
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

    fn verify_parent(&self, fd: std::os::fd::BorrowedFd<'_>) -> crate::Result<u32> {
        let cred = peer::PeerCred::read(fd)?;
        let state = crate::hardening::Hardening::state();
        // A non-dumpable parent's status stays readable.
        let real_gid = match state {
            crate::hardening::HardeningState::Hardened { .. } => {
                procfs::read_real_gid(cred.pid).ok()
            }
            _ => None,
        };
        let ppid = u32::try_from(nix::unistd::getppid().as_raw()).unwrap_or(0);
        crate::platform::ParentCredentials {
            pid: cred.pid,
            uid: cred.uid,
            gid: cred.gid,
            real_gid,
        }
        .verify(nix::unistd::geteuid().as_raw(), ppid, state)?;
        Ok(cred.pid)
    }

    fn session_identity(
        &self,
        peer: &crate::platform::PeerIdentity,
    ) -> Option<crate::platform::SessionIdentity> {
        let stat = Self::peer_stat(peer)?;
        session_identity_from(&stat, |pid| {
            u32::try_from(pid)
                .ok()
                .and_then(|p| procfs::Stat::read(p).ok())
        })
    }

    fn controlling_tty(&self, peer: &crate::platform::PeerIdentity) -> Option<String> {
        procfs::tty_path(Self::peer_stat(peer)?.tty_nr)
    }

    fn ancestry(&self, pid: u32, start_time: u64, uid: u32) -> Vec<crate::platform::Ancestor> {
        use std::os::fd::AsFd;
        let mut ancestry = vec![];
        let mut child: Option<(u32, std::os::fd::OwnedFd)> = None;
        let (mut pid, mut expected_start) = (pid, start_time);
        while ancestry.len() < crate::platform::ANCESTRY_LIMIT && pid > 1 {
            let Some((ancestor, stat, pidfd)) = read_ancestor(pid, uid) else {
                break;
            };
            if expected_start != 0 && stat.start_time != expected_start {
                break;
            }
            // A child still parented to this pid shows that the pid was not reused while it was read.
            if let Some((child_pid, child_pidfd)) = &child {
                let still_parent = procfs::Stat::read(*child_pid)
                    .is_ok_and(|s| i64::from(s.ppid) == i64::from(pid))
                    && peer::pidfd_alive(child_pidfd.as_fd());
                if !still_parent {
                    break;
                }
            }
            ancestry.push(ancestor);
            let Ok(ppid) = u32::try_from(stat.ppid) else {
                break;
            };
            child = Some((pid, pidfd));
            (pid, expected_start) = (ppid, 0);
        }
        ancestry
    }

    fn session_alive(&self, session: &crate::platform::SessionIdentity) -> bool {
        let (pid, start_time, is_leader) = match *session {
            crate::platform::SessionIdentity::Tty {
                sid,
                leader_start_time,
            } => (sid, leader_start_time, true),
            crate::platform::SessionIdentity::Parent { ppid, start_time } => {
                (ppid, start_time, false)
            }
        };
        u32::try_from(pid)
            .ok()
            .and_then(|p| procfs::Stat::read(p).ok())
            .is_some_and(|s| s.start_time == start_time && (!is_leader || s.session == pid))
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
    use crate::platform::ProcessPlatform;
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
    fn test_verify_parent_refuses_own_socketpair() {
        // This process created the pair, and it is not its own parent.
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let err = LinuxProcess.verify_parent(a.as_fd()).unwrap_err();
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

    fn stat(session: i32, tty_nr: i32, ppid: i32, start_time: u64) -> procfs::Stat {
        procfs::Stat {
            ppid,
            pgrp: session,
            session,
            tty_nr,
            start_time,
        }
    }

    #[test]
    fn test_session_identity_tty() {
        let peer = stat(4242, 34819, 4300, 900);
        let id = session_identity_from(&peer, |pid| match pid {
            4242 => Some(stat(4242, 34819, 1, 500)),
            4300 => Some(stat(4242, 34819, 4242, 800)),
            _ => None,
        });
        assert_eq!(
            id,
            Some(crate::platform::SessionIdentity::Tty {
                sid: 4242,
                leader_start_time: 500
            })
        );
    }

    #[test]
    fn test_session_identity_dead_leader_falls_back_to_parent() {
        let peer = stat(4242, 34819, 4300, 900);
        let id = session_identity_from(&peer, |pid| match pid {
            // A reused pid that leads another session.
            4242 => Some(stat(5000, 0, 1, 1000)),
            4300 => Some(stat(4242, 34819, 1, 800)),
            _ => None,
        });
        assert_eq!(
            id,
            Some(crate::platform::SessionIdentity::Parent {
                ppid: 4300,
                start_time: 800
            })
        );
    }

    #[test]
    fn test_session_identity_no_tty() {
        let peer = stat(4400, 0, 777, 900);
        let id = session_identity_from(&peer, |pid| (pid == 777).then(|| stat(4400, 0, 1, 700)));
        assert_eq!(
            id,
            Some(crate::platform::SessionIdentity::Parent {
                ppid: 777,
                start_time: 700
            })
        );
    }

    #[test]
    fn test_session_identity_none() {
        let peer = stat(4400, 0, 1, 900);
        assert_eq!(session_identity_from(&peer, |_| None), None);
        let orphan = stat(4400, 0, 777, 900);
        assert_eq!(session_identity_from(&orphan, |_| None), None);
    }

    #[test]
    fn test_session_identity_self() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let peer = LinuxProcess::inspect(a.as_fd(), &unhardened(), euid()).unwrap();
        assert!(LinuxProcess.session_identity(&peer).is_some());
    }

    #[test]
    fn test_ancestry_self() {
        let uid = euid();
        let stat = procfs::Stat::read(std::process::id()).unwrap();
        let ancestry = LinuxProcess.ancestry(std::process::id(), stat.start_time, uid);
        assert_eq!(ancestry[0].pid, std::process::id());
        assert!(ancestry[0].comm.is_some());
        assert!(!ancestry[0].argv.is_empty() && ancestry[0].argv.len() <= 2);
        assert!(ancestry.len() <= crate::platform::ANCESTRY_LIMIT);
        assert!(ancestry.iter().all(|a| a.pid > 1));
        // The parent follows unless it runs as another uid.
        if let Some(parent) = ancestry.get(1) {
            assert_eq!(i64::from(parent.pid), i64::from(stat.ppid));
        }
    }

    #[test]
    fn test_ancestry_stops_at_uid_change() {
        assert!(
            LinuxProcess
                .ancestry(std::process::id(), 0, euid() + 1)
                .is_empty()
        );
    }

    #[test]
    fn test_ancestry_wrong_start_time() {
        let stat = procfs::Stat::read(std::process::id()).unwrap();
        assert!(
            LinuxProcess
                .ancestry(std::process::id(), stat.start_time + 1, euid())
                .is_empty()
        );
    }

    #[test]
    fn test_session_alive() {
        let stat = procfs::Stat::read(std::process::id()).unwrap();
        let parent = procfs::Stat::read(u32::try_from(stat.ppid).unwrap()).unwrap();
        let alive = crate::platform::SessionIdentity::Parent {
            ppid: stat.ppid,
            start_time: parent.start_time,
        };
        assert!(LinuxProcess.session_alive(&alive));
        let reused = crate::platform::SessionIdentity::Parent {
            ppid: stat.ppid,
            start_time: parent.start_time + 1,
        };
        assert!(!LinuxProcess.session_alive(&reused));
    }

    #[test]
    fn test_read_live_pidfd() {
        let pidfd = peer::pidfd_open(std::process::id()).unwrap();
        let pinned = Pinned::read(std::process::id(), pidfd).unwrap();
        assert!(pinned.start_time > 0);
    }
}
