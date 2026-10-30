//! In-process platform primitives: who is on the other end of an agent connection.

pub mod process;

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
