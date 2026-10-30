//! Whether this process was exec'd through the setgid marker binary, and the handling of the marker gid.
//!
//! A hardened process keeps the marker only in its saved gid, raises it with [`with_privileged_gid`] and drops it
//! for good before exec'ing anything.

/// The name the marker group must have.
pub const MARKER_GROUP_NAME: &str = "mairu";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardeningState {
    Unhardened {
        /// The group this exec was setgid to, when it is not a usable marker group.
        setgid_other_group: Option<u32>,
    },
    Hardened {
        marker: nix::unistd::Gid,
    },
    Misconfigured {
        reason: MisconfiguredReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MisconfiguredReason {
    PrimaryGroupIsMarker,
    MarkerMember,
    SuidDumpable,
}

impl std::fmt::Display for MisconfiguredReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MisconfiguredReason::PrimaryGroupIsMarker => write!(
                f,
                "your primary group is the `{MARKER_GROUP_NAME}` marker group"
            ),
            MisconfiguredReason::MarkerMember => write!(
                f,
                "you are a member of the `{MARKER_GROUP_NAME}` marker group, so the marker can be forged"
            ),
            MisconfiguredReason::SuidDumpable => write!(
                f,
                "fs.suid_dumpable is 1, which leaves setgid processes traceable"
            ),
        }
    }
}

/// An entry of the group database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub members: Vec<String>,
}

/// Everything classification looks at, as read at startup.
#[derive(Debug, Clone)]
pub struct Facts {
    pub rgid: u32,
    /// The effective gid at startup: the candidate marker.
    pub egid: u32,
    pub at_secure: bool,
    /// `None` when the lookup failed.
    pub rgid_group: Option<GroupEntry>,
    /// `None` when the lookup failed.
    pub egid_group: Option<GroupEntry>,
    pub supplementary_gids: Vec<u32>,
    pub user_name: Option<String>,
    pub suid_dumpable: Option<u8>,
}

impl Facts {
    pub fn classify(&self) -> HardeningState {
        if self
            .rgid_group
            .as_ref()
            .is_some_and(|g| g.name == MARKER_GROUP_NAME)
        {
            return HardeningState::Misconfigured {
                reason: MisconfiguredReason::PrimaryGroupIsMarker,
            };
        }
        // An effective gid inherited from a parent is never a marker. File capabilities set AT_SECURE too.
        if !self.at_secure || self.egid == self.rgid {
            return HardeningState::Unhardened {
                setgid_other_group: None,
            };
        }
        // The lookup goes from the granted gid to its name, so another `mairu` group in NSS cannot shadow it.
        let group = match &self.egid_group {
            Some(g) if g.name == MARKER_GROUP_NAME && self.egid != 0 && self.egid != 65534 => g,
            _ => {
                return HardeningState::Unhardened {
                    setgid_other_group: Some(self.egid),
                };
            }
        };
        let listed = self
            .user_name
            .as_ref()
            .is_some_and(|u| group.members.iter().any(|m| m == u));
        if listed || self.supplementary_gids.contains(&self.egid) {
            return HardeningState::Misconfigured {
                reason: MisconfiguredReason::MarkerMember,
            };
        }
        if self.suid_dumpable == Some(1) {
            return HardeningState::Misconfigured {
                reason: MisconfiguredReason::SuidDumpable,
            };
        }
        HardeningState::Hardened {
            marker: nix::unistd::Gid::from_raw(self.egid),
        }
    }
}

static STATE: std::sync::OnceLock<HardeningState> = std::sync::OnceLock::new();
static UNDETECTED: HardeningState = HardeningState::Unhardened {
    setgid_other_group: None,
};
// glibc and musl apply set*id calls to every thread, so raising the marker is process-wide.
static PRIVILEGED_GID_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

pub struct Hardening;

impl Hardening {
    /// Classifies this process and settles its gids. Must run first in `main`, before anything changes the ids.
    pub fn detect() -> &'static HardeningState {
        STATE.get_or_init(|| {
            let state = Self::classify_self();
            Self::settle(&state);
            state
        })
    }

    pub fn state() -> &'static HardeningState {
        STATE.get().unwrap_or(&UNDETECTED)
    }

    pub fn marker() -> Option<nix::unistd::Gid> {
        match Self::state() {
            HardeningState::Hardened { marker } => Some(*marker),
            _ => None,
        }
    }

    #[cfg(target_os = "linux")]
    fn classify_self() -> HardeningState {
        match Self::gather() {
            Ok(facts) => facts.classify(),
            Err(e) => {
                eprintln!(
                    "mairu: warning: failed to read process credentials ({e}); running unhardened"
                );
                HardeningState::Unhardened {
                    setgid_other_group: None,
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn classify_self() -> HardeningState {
        HardeningState::Unhardened {
            setgid_other_group: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn gather() -> nix::Result<Facts> {
        let resgid = nix::unistd::getresgid()?;
        // SAFETY: getauxval has no preconditions.
        let at_secure = unsafe { libc::getauxval(libc::AT_SECURE) } != 0;
        let lookup = |gid: nix::unistd::Gid| {
            nix::unistd::Group::from_gid(gid)
                .ok()
                .flatten()
                .map(|g| GroupEntry {
                    name: g.name,
                    members: g.mem,
                })
        };
        let user_name = nix::unistd::User::from_uid(nix::unistd::getuid())
            .ok()
            .flatten()
            .map(|u| u.name);
        Ok(Facts {
            rgid: resgid.real.as_raw(),
            egid: resgid.effective.as_raw(),
            at_secure,
            rgid_group: lookup(resgid.real),
            egid_group: lookup(resgid.effective),
            supplementary_gids: nix::unistd::getgroups()?
                .into_iter()
                .map(|g| g.as_raw())
                .collect(),
            user_name,
            suid_dumpable: read_sysctl("/proc/sys/fs/suid_dumpable"),
        })
    }

    #[cfg(target_os = "linux")]
    fn settle(state: &HardeningState) {
        match state {
            HardeningState::Hardened { marker } => {
                let rgid = nix::unistd::getgid();
                if let Err(e) = set_gids(rgid, rgid, *marker) {
                    fatal(&format!("failed to lower the marker gid: {e}"));
                }
                if read_sysctl("/proc/sys/fs/protected_hardlinks") != Some(1) {
                    eprintln!(
                        "mairu: warning: fs.protected_hardlinks is not 1; hardlinked copies of old hardened binaries keep working after an upgrade"
                    );
                }
            }
            HardeningState::Unhardened {
                setgid_other_group: None,
            } => {}
            HardeningState::Unhardened {
                setgid_other_group: Some(gid),
            } => {
                eprintln!(
                    "mairu: warning: this binary is setgid to group {gid}, not to a dedicated `{MARKER_GROUP_NAME}` group; running unhardened"
                );
                Self::drop_setgid_grant();
            }
            HardeningState::Misconfigured { reason } => {
                eprintln!("mairu: warning: {reason}; running unhardened");
                Self::drop_setgid_grant();
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn settle(_state: &HardeningState) {}

    /// An unhardened process never holds a gid granted by setgid, so it cannot pass as hardened to a peer.
    #[cfg(target_os = "linux")]
    fn drop_setgid_grant() {
        // SAFETY: getauxval has no preconditions.
        if unsafe { libc::getauxval(libc::AT_SECURE) } == 0 {
            return;
        }
        let rgid = nix::unistd::getgid();
        if let Err(e) = set_gids(rgid, rgid, rgid) {
            fatal(&format!("failed to drop the setgid group: {e}"));
        }
    }
}

/// Runs `f` with the marker as the effective gid. Used around `connect()`, `bind()`+`listen()`, and access to files
/// only the marker gid may open. Runs `f` unchanged on an unhardened process. Must not be nested.
pub fn with_privileged_gid<T>(f: impl FnOnce() -> std::io::Result<T>) -> std::io::Result<T> {
    let Some(marker) = Hardening::marker() else {
        return f();
    };
    with_marker_raised(marker, f)
}

#[cfg(target_os = "linux")]
fn with_marker_raised<T>(
    marker: nix::unistd::Gid,
    f: impl FnOnce() -> std::io::Result<T>,
) -> std::io::Result<T> {
    let _guard = PRIVILEGED_GID_LOCK.lock();
    let rgid = nix::unistd::getgid();
    set_gids(rgid, marker, marker)?;
    let retval = f();
    if let Err(e) = set_gids(rgid, rgid, marker) {
        fatal(&format!("failed to lower the marker gid: {e}"));
    }
    retval
}

#[cfg(not(target_os = "linux"))]
fn with_marker_raised<T>(
    _marker: nix::unistd::Gid,
    f: impl FnOnce() -> std::io::Result<T>,
) -> std::io::Result<T> {
    f()
}

/// Drops the marker from every gid slot, for good. Callers must not exec anything when this fails.
pub fn drop_privileged_gid_permanently() -> std::io::Result<()> {
    if Hardening::marker().is_none() {
        return Ok(());
    }
    let _guard = PRIVILEGED_GID_LOCK.lock();
    drop_unlocked()
}

#[cfg(target_os = "linux")]
fn drop_unlocked() -> std::io::Result<()> {
    let rgid = nix::unistd::getgid();
    set_gids(rgid, rgid, rgid)?;
    verify_dropped(&nix::unistd::getresgid()?, rgid)
}

#[cfg(not(target_os = "linux"))]
fn drop_unlocked() -> std::io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_dropped(resgid: &nix::unistd::ResGid, rgid: nix::unistd::Gid) -> std::io::Result<()> {
    if resgid.real == rgid && resgid.effective == rgid && resgid.saved == rgid {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "marker gid still held after dropping it (real={}, effective={}, saved={})",
        resgid.real, resgid.effective, resgid.saved
    )))
}

/// A command whose child drops the marker permanently before exec. Every process mairu spawns goes through this.
pub fn command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(program);
    if Hardening::marker().is_some() {
        // SAFETY: drop_unlocked only makes async-signal-safe system calls. The lock is skipped because another
        // thread of the parent may have held it at fork.
        unsafe {
            cmd.pre_exec(drop_unlocked);
        }
    }
    cmd
}

/// Variables a hardened agent keeps, besides `LC_*`. The rest could redirect its traffic, such as `HTTPS_PROXY`,
/// `SSL_CERT_FILE` or `AWS_ENDPOINT_URL`.
const ENV_ALLOWLIST: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "TZ",
    "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME",
    "XDG_STATE_HOME",
    "MAIRU_AGENT_SOCK",
    "MAIRU_LOG",
    "MAIRU_AGENT_LOG",
];
const SANITIZED_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

fn is_allowed_env(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    ENV_ALLOWLIST.contains(&name) || name.starts_with("LC_")
}

/// The allowlisted part of this process's environment, with a fixed `PATH`. A hardened agent runs with this.
pub fn sanitized_environment() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    std::env::vars_os()
        .filter(|(k, _)| is_allowed_env(k))
        .chain(std::iter::once((
            "PATH".into(),
            std::ffi::OsString::from(SANITIZED_PATH),
        )))
        .collect()
}

/// Clears this process's environment down to [`sanitized_environment`].
///
/// # Safety
///
/// The process must be single-threaded.
pub unsafe fn sanitize_environment() {
    for (name, _) in std::env::vars_os() {
        if !is_allowed_env(&name) {
            // SAFETY: the caller guarantees no other thread reads the environment.
            unsafe { std::env::remove_var(name) };
        }
    }
    // SAFETY: as above.
    unsafe { std::env::set_var("PATH", SANITIZED_PATH) };
}

// The kernel resets dumpability to fs.suid_dumpable on every credential change.
#[cfg(target_os = "linux")]
fn set_gids(
    rgid: nix::unistd::Gid,
    egid: nix::unistd::Gid,
    sgid: nix::unistd::Gid,
) -> nix::Result<()> {
    nix::unistd::setresgid(rgid, egid, sgid)?;
    nix::sys::prctl::set_dumpable(false)
}

#[cfg(target_os = "linux")]
pub(crate) fn read_sysctl(path: &str) -> Option<u8> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(target_os = "linux")]
fn fatal(message: &str) -> ! {
    eprintln!("mairu: fatal: {message}");
    std::process::abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    const RGID: u32 = 1000;
    const MARKER: u32 = 973;

    fn group(name: &str, members: &[&str]) -> Option<GroupEntry> {
        Some(GroupEntry {
            name: name.to_owned(),
            members: members.iter().map(|m| (*m).to_owned()).collect(),
        })
    }

    fn hardened_facts() -> Facts {
        Facts {
            rgid: RGID,
            egid: MARKER,
            at_secure: true,
            rgid_group: group("alice", &[]),
            egid_group: group("mairu", &[]),
            supplementary_gids: vec![RGID, 10],
            user_name: Some("alice".to_owned()),
            suid_dumpable: Some(0),
        }
    }

    fn unhardened(other: Option<u32>) -> HardeningState {
        HardeningState::Unhardened {
            setgid_other_group: other,
        }
    }

    fn misconfigured(reason: MisconfiguredReason) -> HardeningState {
        HardeningState::Misconfigured { reason }
    }

    #[test]
    fn test_hardened() {
        assert_eq!(
            hardened_facts().classify(),
            HardeningState::Hardened {
                marker: nix::unistd::Gid::from_raw(MARKER)
            }
        );
    }

    #[test]
    fn test_hardened_with_suid_dumpable_unreadable_or_2() {
        for v in [None, Some(2)] {
            let facts = Facts {
                suid_dumpable: v,
                ..hardened_facts()
            };
            assert!(matches!(facts.classify(), HardeningState::Hardened { .. }));
        }
    }

    #[test]
    fn test_primary_group_is_marker() {
        let facts = Facts {
            rgid: MARKER,
            rgid_group: group("mairu", &[]),
            ..hardened_facts()
        };
        assert_eq!(
            facts.classify(),
            misconfigured(MisconfiguredReason::PrimaryGroupIsMarker)
        );
    }

    #[test]
    fn test_primary_group_is_marker_without_setgid() {
        let facts = Facts {
            rgid: MARKER,
            egid: MARKER,
            at_secure: false,
            rgid_group: group("mairu", &[]),
            ..hardened_facts()
        };
        assert_eq!(
            facts.classify(),
            misconfigured(MisconfiguredReason::PrimaryGroupIsMarker)
        );
    }

    #[test]
    fn test_no_at_secure() {
        let facts = Facts {
            at_secure: false,
            ..hardened_facts()
        };
        assert_eq!(facts.classify(), unhardened(None));
    }

    #[test]
    fn test_at_secure_without_setgid() {
        // File capabilities set AT_SECURE without changing the effective gid.
        let facts = Facts {
            egid: RGID,
            egid_group: group("alice", &[]),
            ..hardened_facts()
        };
        assert_eq!(facts.classify(), unhardened(None));
    }

    #[test]
    fn test_setgid_other_group() {
        let facts = Facts {
            egid_group: group("utmp", &[]),
            ..hardened_facts()
        };
        assert_eq!(facts.classify(), unhardened(Some(MARKER)));
    }

    #[test]
    fn test_failed_lookup() {
        let facts = Facts {
            egid_group: None,
            ..hardened_facts()
        };
        assert_eq!(facts.classify(), unhardened(Some(MARKER)));
    }

    #[test]
    fn test_gid_0_and_65534_even_if_named_mairu() {
        for gid in [0, 65534] {
            let facts = Facts {
                egid: gid,
                ..hardened_facts()
            };
            assert_eq!(facts.classify(), unhardened(Some(gid)));
        }
    }

    #[test]
    fn test_supplementary_member() {
        let facts = Facts {
            supplementary_gids: vec![RGID, MARKER],
            ..hardened_facts()
        };
        assert_eq!(
            facts.classify(),
            misconfigured(MisconfiguredReason::MarkerMember)
        );
    }

    #[test]
    fn test_listed_member() {
        let facts = Facts {
            egid_group: group("mairu", &["bob", "alice"]),
            ..hardened_facts()
        };
        assert_eq!(
            facts.classify(),
            misconfigured(MisconfiguredReason::MarkerMember)
        );
    }

    #[test]
    fn test_other_listed_member() {
        let facts = Facts {
            egid_group: group("mairu", &["bob"]),
            ..hardened_facts()
        };
        assert!(matches!(facts.classify(), HardeningState::Hardened { .. }));
    }

    #[test]
    fn test_suid_dumpable() {
        let facts = Facts {
            suid_dumpable: Some(1),
            ..hardened_facts()
        };
        assert_eq!(
            facts.classify(),
            misconfigured(MisconfiguredReason::SuidDumpable)
        );
    }

    #[test]
    fn test_is_allowed_env() {
        for name in [
            "HOME",
            "XDG_RUNTIME_DIR",
            "MAIRU_AGENT_SOCK",
            "LC_ALL",
            "LC_CTYPE",
        ] {
            assert!(is_allowed_env(name.as_ref()), "{name}");
        }
        for name in [
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "AWS_ENDPOINT_URL",
            "AWS_CONFIG_FILE",
            "AWS_PROFILE",
            "MAIRU_PROFILE",
            "PATH",
            "LD_PRELOAD",
            "LANGUAGE",
        ] {
            assert!(!is_allowed_env(name.as_ref()), "{name}");
        }
    }

    #[test]
    fn test_sanitized_environment_resets_path() {
        let env = sanitized_environment();
        let paths: Vec<_> = env.iter().filter(|(k, _)| k == "PATH").collect();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].1, SANITIZED_PATH);
    }

    #[test]
    fn test_undetected_is_unhardened() {
        assert_eq!(UNDETECTED, unhardened(None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_verify_dropped() {
        let g = nix::unistd::Gid::from_raw;
        let resgid = |r, e, s| nix::unistd::ResGid {
            real: g(r),
            effective: g(e),
            saved: g(s),
        };
        assert!(verify_dropped(&resgid(RGID, RGID, RGID), g(RGID)).is_ok());
        assert!(verify_dropped(&resgid(RGID, MARKER, RGID), g(RGID)).is_err());
        assert!(verify_dropped(&resgid(RGID, RGID, MARKER), g(RGID)).is_err());
        assert!(verify_dropped(&resgid(MARKER, RGID, RGID), g(RGID)).is_err());
    }
}
