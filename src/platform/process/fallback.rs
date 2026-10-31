//! Platforms without peer verification yet. Every peer is `Unverifiable`, which keeps the unhardened behavior.

#[derive(Debug)]
pub struct FallbackProcess;

impl crate::platform::ProcessPlatform for FallbackProcess {
    fn inspect_peer(
        &self,
        stream: &tokio::net::UnixStream,
    ) -> crate::Result<crate::platform::PeerIdentity> {
        let cred = stream.peer_cred()?;
        let euid = nix::unistd::geteuid().as_raw();
        if cred.uid() != euid {
            return Err(crate::Error::PeerError(format!(
                "peer runs as uid {}, not {euid}",
                cred.uid()
            )));
        }
        Ok(crate::platform::PeerIdentity {
            uid: cred.uid(),
            gid: cred.gid(),
            real_gid: None,
            pid: cred.pid().and_then(|p| u32::try_from(p).ok()).unwrap_or(0),
            pidfd: None,
            start_time: 0,
            exe: None,
            trust: crate::platform::PeerTrust::Unverifiable,
        })
    }

    fn verify_agent(
        &self,
        stream: &std::os::unix::net::UnixStream,
    ) -> crate::Result<crate::platform::AgentIdentity> {
        #[cfg(any(
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        {
            let (uid, _gid) = nix::unistd::getpeereid(stream)?;
            let euid = nix::unistd::geteuid();
            if uid != euid {
                return Err(crate::Error::PeerError(format!(
                    "agent runs as uid {uid}, not {euid}"
                )));
            }
        }
        #[cfg(not(any(
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "netbsd",
            target_os = "openbsd"
        )))]
        let _ = stream;
        Ok(crate::platform::AgentIdentity {
            pid: None,
            trust: crate::platform::AgentTrust::Unverifiable,
        })
    }

    /// Checks the uid only, where the OS reports one. How the helper and agent check each other here is left to the
    /// OS's own peer verification.
    fn verify_parent(&self, fd: std::os::fd::BorrowedFd<'_>) -> crate::Result<u32> {
        #[cfg(any(
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        {
            let (uid, _gid) = nix::unistd::getpeereid(fd)?;
            let euid = nix::unistd::geteuid();
            if uid != euid {
                return Err(crate::Error::PeerError(format!(
                    "the parent runs as uid {uid}, not {euid}"
                )));
            }
        }
        #[cfg(not(any(
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "netbsd",
            target_os = "openbsd"
        )))]
        let _ = fd;
        Ok(u32::try_from(nix::unistd::getppid().as_raw()).unwrap_or(0))
    }

    fn peer_verification(&self) -> crate::proto::platform::PeerVerification {
        crate::proto::platform::PeerVerification::None
    }

    fn session_identity(
        &self,
        _peer: &crate::platform::PeerIdentity,
    ) -> Option<crate::platform::SessionIdentity> {
        None
    }

    fn controlling_tty(&self, _peer: &crate::platform::PeerIdentity) -> Option<String> {
        None
    }

    fn ancestry(&self, _pid: u32, _start_time: u64, _uid: u32) -> Vec<crate::platform::Ancestor> {
        vec![]
    }

    fn session_alive(&self, _session: &crate::platform::SessionIdentity) -> bool {
        false
    }

    fn notes(&self) -> Vec<String> {
        vec!["peer verification is not implemented on this platform".to_owned()]
    }
}
