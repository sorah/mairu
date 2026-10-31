//! Platform-dependent code: in-process primitives (who is on the other end of a connection) and the platform
//! services that run only inside the platform helper.

#[cfg(feature = "cli")]
pub mod helper;
pub mod integrity;
pub mod process;
#[cfg(feature = "platform-services")]
pub mod services;

/// Exit status of a platform helper that refused its parent.
pub const HELPER_EXIT_PARENT_UNVERIFIED: u8 = 3;

/// Runs in-process in every mairu process; never remoted.
pub trait ProcessPlatform: Send + Sync + std::fmt::Debug {
    /// Agent side, at accept time. An error means the connection must be closed.
    fn inspect_peer(&self, stream: &tokio::net::UnixStream) -> crate::Result<PeerIdentity>;
    /// Client side, right after connect.
    fn verify_agent(&self, stream: &std::os::unix::net::UnixStream)
    -> crate::Result<AgentIdentity>;
    /// How peers are verified, for `GetAgentStatus` and `mairu doctor`.
    fn peer_verification(&self) -> crate::proto::platform::PeerVerification;
    /// Diagnostics about this host, such as missing kernel features.
    fn notes(&self) -> Vec<String>;
    /// Platform helper side: checks that the other end of the inherited socket is this process's parent.
    /// Returns the parent's pid.
    fn verify_parent(&self, fd: std::os::fd::BorrowedFd<'_>) -> crate::Result<u32>;
    /// What remembered human checks of this peer are keyed to; `None` when nothing is.
    fn session_identity(&self, peer: &PeerIdentity) -> Option<SessionIdentity>;
    /// The peer's controlling terminal, such as `/dev/pts/3`.
    fn controlling_tty(&self, peer: &PeerIdentity) -> Option<String>;
    /// The process `pid` and its ancestors through `ppid`, nearest first. Stops before pid 1, at the first process
    /// not running as `uid`, after [`ANCESTRY_LIMIT`] processes, or at a process that exits while being read.
    /// `start_time` of 0 skips checking that `pid` is still the expected process.
    fn ancestry(&self, pid: u32, start_time: u64, uid: u32) -> Vec<Ancestor>;
    /// Whether the process a session identity is keyed to still runs with the recorded start time.
    fn session_alive(&self, session: &SessionIdentity) -> bool;
    /// Present only on WSL2: whether Windows interop is enabled, which makes root reachable. Read on every call.
    fn wsl_interop(&self) -> Option<bool>;
}

/// How many processes [`ProcessPlatform::ancestry`] walks at most.
pub const ANCESTRY_LIMIT: usize = 64;

/// A process in an ancestry, for tool detection. Every field except `session` is chosen by the process itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ancestor {
    pub pid: u32,
    pub comm: Option<String>,
    pub exe: Option<std::path::PathBuf>,
    /// `argv[0]` and `argv[1]`, as far as present.
    pub argv: Vec<std::ffi::OsString>,
    /// The process's session, as [`SessionIdentity::Tty`], while its leader lives.
    pub session: Option<SessionIdentity>,
}

/// A terminal session, or the parent of a caller without one. Ids are paired with start times so that a reused
/// id never matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionIdentity {
    Tty { sid: i32, leader_start_time: u64 },
    Parent { ppid: i32, start_time: u64 },
}

impl SessionIdentity {
    /// `"tty"` or `"parent"`, as the policy context's `session`.
    pub fn kind(&self) -> &'static str {
        match self {
            SessionIdentity::Tty { .. } => "tty",
            SessionIdentity::Parent { .. } => "parent",
        }
    }
}

impl std::fmt::Display for SessionIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionIdentity::Tty { sid, .. } => write!(f, "tty sid={sid}"),
            SessionIdentity::Parent { ppid, .. } => write!(f, "parent pid={ppid}"),
        }
    }
}

/// The `PlatformHelper` contract as a trait. The agent only holds `HelperClient`; the backends that implement it
/// run inside the platform helper.
#[async_trait::async_trait]
pub trait PlatformServices: Send + Sync + std::fmt::Debug {
    /// `req.session` is the requesting client's session, which notifications and open_url depend on.
    async fn capabilities(
        &self,
        req: crate::proto::platform::GetCapabilitiesRequest,
    ) -> crate::proto::platform::Capabilities;

    async fn authorize(
        &self,
        req: crate::proto::platform::AuthorizeRequest,
    ) -> crate::proto::platform::AuthorizeResponse;
    async fn notify(
        &self,
        req: crate::proto::platform::NotifyRequest,
    ) -> crate::proto::platform::NotifyResponse;
    async fn open_url(
        &self,
        req: crate::proto::platform::OpenUrlRequest,
    ) -> crate::proto::platform::OpenUrlResponse;
    async fn record_integrity(
        &self,
        req: crate::proto::platform::RecordIntegrityRequest,
    ) -> crate::proto::platform::RecordIntegrityResponse;
    async fn verify_integrity(
        &self,
        req: crate::proto::platform::VerifyIntegrityRequest,
    ) -> crate::proto::platform::VerifyIntegrityResponse;
}

/// The backend for this OS. Runs only inside the platform helper.
#[cfg(feature = "platform-services")]
pub fn services() -> &'static dyn PlatformServices {
    #[cfg(target_os = "linux")]
    {
        &crate::platform::services::linux::LinuxServices
    }
    #[cfg(not(target_os = "linux"))]
    {
        &crate::platform::services::fallback::FallbackServices
    }
}

/// The credentials the kernel recorded for the creator of the platform helper's socketpair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    /// `None` when it could not be read.
    pub real_gid: Option<u32>,
}

impl ParentCredentials {
    /// The creator must be the parent, of the same uid, and when hardened hold the marker without it being its real
    /// gid.
    pub fn verify(
        &self,
        own_uid: u32,
        ppid: u32,
        state: &crate::hardening::HardeningState,
    ) -> crate::Result<()> {
        if self.uid != own_uid {
            return Err(crate::Error::PeerError(format!(
                "the socket's creator pid {} runs as uid {}, not {own_uid}",
                self.pid, self.uid
            )));
        }
        if self.pid != ppid {
            return Err(crate::Error::PeerError(format!(
                "the socket's creator is pid {}, not the parent pid {ppid}",
                self.pid
            )));
        }
        if let crate::hardening::HardeningState::Hardened { marker } = state
            && !holds_marker(marker.as_raw(), self.gid, self.real_gid)
        {
            let real_gid = self
                .real_gid
                .map_or_else(|| "unknown".to_owned(), |g| g.to_string());
            return Err(crate::Error::PeerError(format!(
                "the parent pid {} is not hardened mairu (gid {}, real gid {real_gid})",
                self.pid, self.gid
            )));
        }
        Ok(())
    }
}

/// The peer of an accepted connection, as the kernel reported it at `connect()`.
#[derive(Debug)]
pub struct PeerIdentity {
    pub uid: u32,
    /// The effective gid at `connect()`.
    pub gid: u32,
    /// `None` when it could not be read.
    pub real_gid: Option<u32>,
    pub pid: u32,
    /// Keeps the pid from being reused for another process while the connection lives.
    pub pidfd: Option<std::os::fd::OwnedFd>,
    /// Clock ticks since boot; 0 when unknown.
    pub start_time: u64,
    pub exe: Option<std::path::PathBuf>,
    pub trust: PeerTrust,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTrust {
    /// Hardened agent, and the peer held the marker at `connect()`.
    Verified,
    /// Hardened agent, and the peer is not hardened mairu.
    Rejected,
    /// The agent is not hardened, so peers are not told apart.
    Unverifiable,
}

impl PeerTrust {
    /// A process that joined the marker group through a group password has it as its real gid too.
    pub fn evaluate(
        agent: &crate::hardening::HardeningState,
        peer_gid: u32,
        peer_real_gid: Option<u32>,
    ) -> Self {
        match agent {
            crate::hardening::HardeningState::Hardened { marker } => {
                if holds_marker(marker.as_raw(), peer_gid, peer_real_gid) {
                    PeerTrust::Verified
                } else {
                    PeerTrust::Rejected
                }
            }
            _ => PeerTrust::Unverifiable,
        }
    }
}

/// The agent at the other end of a client connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentIdentity {
    pub pid: Option<u32>,
    pub trust: AgentTrust,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentTrust {
    /// Hardened client, and the agent held the marker at `listen()`.
    Verified,
    /// Hardened client, and the agent is not hardened mairu. It may receive only diagnostic RPCs and shutdown.
    Unverified,
    /// The client is not hardened, so only the uid is checked.
    Unverifiable,
}

impl AgentTrust {
    pub fn evaluate(
        client: &crate::hardening::HardeningState,
        agent_gid: u32,
        agent_real_gid: Option<u32>,
    ) -> Self {
        match client {
            crate::hardening::HardeningState::Hardened { marker } => {
                if holds_marker(marker.as_raw(), agent_gid, agent_real_gid) {
                    AgentTrust::Verified
                } else {
                    AgentTrust::Unverified
                }
            }
            _ => AgentTrust::Unverifiable,
        }
    }
}

fn holds_marker(marker: u32, gid: u32, real_gid: Option<u32>) -> bool {
    gid == marker && real_gid.is_some_and(|r| r != marker)
}

/// The `ProcessPlatform` for this OS.
pub fn process() -> &'static dyn ProcessPlatform {
    #[cfg(target_os = "linux")]
    {
        &crate::platform::process::linux::LinuxProcess
    }
    #[cfg(not(target_os = "linux"))]
    {
        &crate::platform::process::fallback::FallbackProcess
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RGID: u32 = 1000;
    const MARKER: u32 = 973;

    fn hardened() -> crate::hardening::HardeningState {
        crate::hardening::HardeningState::Hardened {
            marker: nix::unistd::Gid::from_raw(MARKER),
        }
    }

    fn not_hardened() -> [crate::hardening::HardeningState; 2] {
        [
            crate::hardening::HardeningState::Unhardened {
                setgid_other_group: None,
            },
            crate::hardening::HardeningState::Misconfigured {
                reason: crate::hardening::MisconfiguredReason::MarkerMember,
            },
        ]
    }

    #[test]
    fn test_peer_trust_hardened_marker_with_other_real_gid() {
        assert_eq!(
            PeerTrust::evaluate(&hardened(), MARKER, Some(RGID)),
            PeerTrust::Verified
        );
    }

    #[test]
    fn test_peer_trust_hardened_without_marker() {
        assert_eq!(
            PeerTrust::evaluate(&hardened(), RGID, Some(RGID)),
            PeerTrust::Rejected
        );
    }

    #[test]
    fn test_peer_trust_hardened_real_gid_is_marker() {
        assert_eq!(
            PeerTrust::evaluate(&hardened(), MARKER, Some(MARKER)),
            PeerTrust::Rejected
        );
    }

    #[test]
    fn test_peer_trust_hardened_real_gid_unknown() {
        assert_eq!(
            PeerTrust::evaluate(&hardened(), MARKER, None),
            PeerTrust::Rejected
        );
    }

    #[test]
    fn test_peer_trust_not_hardened() {
        for state in not_hardened() {
            for (gid, rgid) in [(MARKER, Some(RGID)), (RGID, Some(RGID)), (MARKER, None)] {
                assert_eq!(
                    PeerTrust::evaluate(&state, gid, rgid),
                    PeerTrust::Unverifiable
                );
            }
        }
    }

    #[test]
    fn test_agent_trust_hardened() {
        assert_eq!(
            AgentTrust::evaluate(&hardened(), MARKER, Some(RGID)),
            AgentTrust::Verified
        );
        assert_eq!(
            AgentTrust::evaluate(&hardened(), RGID, Some(RGID)),
            AgentTrust::Unverified
        );
        assert_eq!(
            AgentTrust::evaluate(&hardened(), MARKER, Some(MARKER)),
            AgentTrust::Unverified
        );
        assert_eq!(
            AgentTrust::evaluate(&hardened(), MARKER, None),
            AgentTrust::Unverified
        );
    }

    fn parent(gid: u32, real_gid: Option<u32>) -> ParentCredentials {
        ParentCredentials {
            pid: 4242,
            uid: 1000,
            gid,
            real_gid,
        }
    }

    #[test]
    fn test_parent_hardened() {
        assert!(
            parent(MARKER, Some(RGID))
                .verify(1000, 4242, &hardened())
                .is_ok()
        );
    }

    #[test]
    fn test_parent_not_parent_pid() {
        let err = parent(MARKER, Some(RGID))
            .verify(1000, 1, &hardened())
            .unwrap_err();
        assert!(matches!(err, crate::Error::PeerError(_)), "{err:?}");
    }

    #[test]
    fn test_parent_other_uid() {
        for state in not_hardened() {
            assert!(parent(RGID, Some(RGID)).verify(1001, 4242, &state).is_err());
        }
        assert!(
            parent(MARKER, Some(RGID))
                .verify(1001, 4242, &hardened())
                .is_err()
        );
    }

    #[test]
    fn test_parent_hardened_without_marker() {
        for (gid, rgid) in [(RGID, Some(RGID)), (MARKER, Some(MARKER)), (MARKER, None)] {
            assert!(
                parent(gid, rgid).verify(1000, 4242, &hardened()).is_err(),
                "{gid} {rgid:?}"
            );
        }
    }

    #[test]
    fn test_parent_unhardened_checks_uid_and_pid_only() {
        for state in not_hardened() {
            assert!(parent(RGID, None).verify(1000, 4242, &state).is_ok());
        }
    }

    #[test]
    fn test_agent_trust_not_hardened() {
        for state in not_hardened() {
            for (gid, rgid) in [(MARKER, Some(RGID)), (RGID, Some(RGID))] {
                assert_eq!(
                    AgentTrust::evaluate(&state, gid, rgid),
                    AgentTrust::Unverifiable
                );
            }
        }
    }
}
