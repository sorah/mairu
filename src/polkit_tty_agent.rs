//! polkit's text authentication agent, `pkttyagent`, registered for this process on its terminal when polkit has no
//! agent that could ask the human, such as in tmux over SSH.

/// Never looked up through `PATH`, which is attacker-controlled: this program receives the password.
pub const PKTTYAGENT: &str = "/usr/bin/pkttyagent";

#[cfg(target_os = "linux")]
const REGISTRATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The fd number pkttyagent closes once it is registered.
#[cfg(target_os = "linux")]
const NOTIFY_FD: std::os::fd::RawFd = 3;

/// At most one pkttyagent runs per process; concurrent fallbacks wait for it.
#[cfg(target_os = "linux")]
static FALLBACK_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    First,
    /// pkttyagent is registered and the human is about to be asked.
    Retry,
}

/// Runs `rpc`. When polkit has no authentication agent for this process, registers pkttyagent on the terminal,
/// prints `notice` for that refusal there, and runs `rpc` once more. The process making the RPC must be this one,
/// since pkttyagent registers for it and the agent asks polkit about its peer.
pub async fn with_fallback<T, N, F, Fut>(notice: N, mut rpc: F) -> tonic::Result<T>
where
    N: FnOnce(&crate::proto::AuthorizationError) -> String,
    F: FnMut(Attempt) -> Fut,
    Fut: std::future::Future<Output = tonic::Result<T>>,
{
    let first = rpc(Attempt::First).await;
    let refusal = match &first {
        Err(status) => match crate::proto::AuthorizationError::from_status(status) {
            Some(e)
                if e.reason()
                    == crate::proto::authorization_error::Reason::NoAuthenticationAgent =>
            {
                e
            }
            _ => return first,
        },
        Ok(_) => return first,
    };
    fallback(&refusal, notice, rpc).await.unwrap_or(first)
}

#[cfg(target_os = "linux")]
async fn fallback<T, N, F, Fut>(
    refusal: &crate::proto::AuthorizationError,
    notice: N,
    mut rpc: F,
) -> Option<tonic::Result<T>>
where
    N: FnOnce(&crate::proto::AuthorizationError) -> String,
    F: FnMut(Attempt) -> Fut,
    Fut: std::future::Future<Output = tonic::Result<T>>,
{
    let _guard = FALLBACK_LOCK.lock().await;
    let agent = match TtyAgent::register().await {
        Ok(agent) => agent,
        Err(e) => {
            tracing::info!(err = %e, "Cannot prompt through pkttyagent");
            return Some(Err(e.into_status(refusal)));
        }
    };
    crate::terminal::send(&notice(refusal)).await;
    let retval = rpc(Attempt::Retry).await;
    drop(agent);
    Some(retval)
}

#[cfg(not(target_os = "linux"))]
async fn fallback<T, N, F, Fut>(
    _refusal: &crate::proto::AuthorizationError,
    _notice: N,
    _rpc: F,
) -> Option<tonic::Result<T>>
where
    N: FnOnce(&crate::proto::AuthorizationError) -> String,
    F: FnMut(Attempt) -> Fut,
    Fut: std::future::Future<Output = tonic::Result<T>>,
{
    None
}

#[derive(Debug, thiserror::Error)]
pub enum FallbackError {
    #[error("there is no terminal to ask for a password on; run the command in a terminal")]
    NoTerminal,
    #[error("{PKTTYAGENT} cannot be used: {0}")]
    Untrusted(#[from] PathError),
    #[error("failed to start {PKTTYAGENT}: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("{PKTTYAGENT} did not register: {0}")]
    Registration(String),
}

impl FallbackError {
    /// Still the agent's `refusal`, with what kept the fallback from asking as its detail.
    pub fn into_status(self, refusal: &crate::proto::AuthorizationError) -> tonic::Status {
        crate::proto::AuthorizationError {
            detail: self.to_string(),
            ..refusal.clone()
        }
        .into_status()
    }
}

/// Why a path cannot be trusted to be root's.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    #[error("not installed (it comes with polkit)")]
    Missing,
    #[error("{0} is not readable: {1}")]
    Unreadable(std::path::PathBuf, String),
    #[error("{0} is a symlink")]
    Symlink(std::path::PathBuf),
    #[error("{0} is not a regular file")]
    NotAFile(std::path::PathBuf),
    #[error("{0} is not a directory")]
    NotADirectory(std::path::PathBuf),
    #[error("{0} is owned by uid {1}, not root")]
    NotRootOwned(std::path::PathBuf, u32),
    #[error("{0} is writable by group or others (mode {1:04o})")]
    Writable(std::path::PathBuf, u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    Other,
}

/// What `lstat` says about a path, for [`check_trusted_path`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFacts {
    pub kind: FileKind,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

impl FileFacts {
    pub fn lstat(path: &std::path::Path) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(path)?;
        let file_type = meta.file_type();
        let kind = if file_type.is_symlink() {
            FileKind::Symlink
        } else if file_type.is_dir() {
            FileKind::Directory
        } else if file_type.is_file() {
            FileKind::File
        } else {
            FileKind::Other
        };
        Ok(Self {
            kind,
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode() & 0o7777,
        })
    }
}

/// [`PKTTYAGENT`] and each of its ancestors must be root-owned, not group/other-writable, and no symlink.
pub fn check_pkttyagent() -> Result<FileFacts, PathError> {
    check_trusted_path(std::path::Path::new(PKTTYAGENT), FileFacts::lstat)
}

pub fn check_trusted_path(
    path: &std::path::Path,
    lstat: impl Fn(&std::path::Path) -> std::io::Result<FileFacts>,
) -> Result<FileFacts, PathError> {
    let check = |p: &std::path::Path, kind: FileKind| -> Result<FileFacts, PathError> {
        let facts = lstat(p).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                PathError::Missing
            } else {
                PathError::Unreadable(p.to_owned(), e.to_string())
            }
        })?;
        match (facts.kind, kind) {
            (FileKind::Symlink, _) => return Err(PathError::Symlink(p.to_owned())),
            (FileKind::File, FileKind::File) | (FileKind::Directory, FileKind::Directory) => {}
            (_, FileKind::Directory) => return Err(PathError::NotADirectory(p.to_owned())),
            _ => return Err(PathError::NotAFile(p.to_owned())),
        }
        if facts.uid != 0 {
            return Err(PathError::NotRootOwned(p.to_owned(), facts.uid));
        }
        if facts.mode & 0o022 != 0 {
            return Err(PathError::Writable(p.to_owned(), facts.mode));
        }
        Ok(facts)
    };
    let facts = check(path, FileKind::File)?;
    for ancestor in path.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        check(ancestor, FileKind::Directory)?;
    }
    Ok(facts)
}

/// Checks in the order of the fallback: a terminal first, so that without one nothing is spawned.
#[cfg(target_os = "linux")]
fn prepare(
    tty: std::io::Result<std::fs::File>,
    lstat: impl Fn(&std::path::Path) -> std::io::Result<FileFacts>,
) -> Result<std::fs::File, FallbackError> {
    let tty = tty.map_err(|_| FallbackError::NoTerminal)?;
    check_trusted_path(std::path::Path::new(PKTTYAGENT), lstat)?;
    Ok(tty)
}

#[cfg(target_os = "linux")]
fn open_tty() -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
}

/// A registered pkttyagent, terminated on drop.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct TtyAgent {
    child: Option<std::process::Child>,
}

#[cfg(target_os = "linux")]
impl TtyAgent {
    async fn register() -> Result<Self, FallbackError> {
        let tty = prepare(open_tty(), FileFacts::lstat)?;
        let (notify_rx, notify_tx) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
            .map_err(|e| FallbackError::Spawn(e.into()))?;
        let mut cmd = Self::command(tty, &notify_tx).map_err(FallbackError::Spawn)?;
        let child = cmd.spawn().map_err(FallbackError::Spawn)?;
        drop(cmd);
        drop(notify_tx);
        let mut agent = Self { child: Some(child) };
        tracing::debug!(pid = ?agent.child.as_ref().map(|c| c.id()), "Spawned pkttyagent");

        match tokio::time::timeout(REGISTRATION_TIMEOUT, wait_for_eof(notify_rx)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(FallbackError::Registration(e.to_string())),
            Err(_) => {
                return Err(FallbackError::Registration(format!(
                    "no answer within {} s",
                    REGISTRATION_TIMEOUT.as_secs()
                )));
            }
        }
        if let Some(status) = agent
            .child
            .as_mut()
            .and_then(|c| c.try_wait().ok().flatten())
        {
            return Err(FallbackError::Registration(format!("it {status}")));
        }
        Ok(agent)
    }

    fn command(
        tty: std::fs::File,
        notify_tx: &std::os::fd::OwnedFd,
    ) -> std::io::Result<std::process::Command> {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        let pid = std::process::id();
        let stat = crate::platform::process::linux::procfs::Stat::read(pid)?;
        let mut cmd = crate::hardening::command(PKTTYAGENT);
        cmd.arg("--process")
            .arg(format!("{pid},{}", stat.start_time))
            // No --fallback: polkit consults a fallback agent registered for a process only when that process has
            // a logind session. Spawned only after polkit found no agent, this replaces nothing.
            .arg("--notify-fd")
            .arg(NOTIFY_FD.to_string())
            // Variables such as LD_PRELOAD or DBUS_SYSTEM_BUS_ADDRESS would hand the password to someone else.
            .env_clear()
            .envs(crate::hardening::sanitized_environment())
            .stdin(tty.try_clone()?)
            .stdout(tty.try_clone()?)
            .stderr(tty);
        if let Some(term) = std::env::var_os("TERM") {
            cmd.env("TERM", term);
        }
        let notify_fd = notify_tx.as_raw_fd();
        // SAFETY: dup2 and fcntl are async-signal-safe.
        unsafe {
            cmd.pre_exec(move || {
                if notify_fd == NOTIFY_FD {
                    if libc::fcntl(notify_fd, libc::F_SETFD, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                } else if libc::dup2(notify_fd, NOTIFY_FD) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(cmd)
    }
}

#[cfg(target_os = "linux")]
impl Drop for TtyAgent {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if let Ok(pid) = i32::try_from(child.id()) {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
        std::thread::spawn(move || {
            let status = child.wait();
            tracing::debug!(status = ?status, "pkttyagent exited");
        });
    }
}

/// pkttyagent closes the notify fd once registered, or exits.
#[cfg(target_os = "linux")]
async fn wait_for_eof(rx: std::os::fd::OwnedFd) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;
    let mut rx = tokio::net::unix::pipe::Receiver::from_owned_fd(rx)?;
    let mut buf = [0u8; 64];
    while rx.read(&mut buf).await? != 0 {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(kind: FileKind, uid: u32, mode: u32) -> FileFacts {
        FileFacts {
            kind,
            uid,
            gid: 0,
            mode,
        }
    }

    fn fake_fs(
        entries: Vec<(&'static str, FileFacts)>,
    ) -> impl Fn(&std::path::Path) -> std::io::Result<FileFacts> {
        move |p: &std::path::Path| {
            entries
                .iter()
                .find(|(path, _)| std::path::Path::new(path) == p)
                .map(|(_, f)| *f)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        }
    }

    fn system(binary: FileFacts) -> Vec<(&'static str, FileFacts)> {
        vec![
            ("/", facts(FileKind::Directory, 0, 0o755)),
            ("/usr", facts(FileKind::Directory, 0, 0o755)),
            ("/usr/bin", facts(FileKind::Directory, 0, 0o755)),
            ("/usr/bin/pkttyagent", binary),
        ]
    }

    fn check(entries: Vec<(&'static str, FileFacts)>) -> Result<FileFacts, PathError> {
        check_trusted_path(std::path::Path::new(PKTTYAGENT), fake_fs(entries))
    }

    #[test]
    fn test_check_trusted_path_accepts_root_owned() {
        assert!(check(system(facts(FileKind::File, 0, 0o755))).is_ok());
    }

    #[test]
    fn test_check_trusted_path_rejects() {
        assert_eq!(
            check(
                system(facts(FileKind::File, 0, 0o755))
                    .into_iter()
                    .take(3)
                    .collect()
            ),
            Err(PathError::Missing)
        );
        assert!(matches!(
            check(system(facts(FileKind::File, 1000, 0o755))),
            Err(PathError::NotRootOwned(_, 1000))
        ));
        assert!(matches!(
            check(system(facts(FileKind::File, 0, 0o775))),
            Err(PathError::Writable(..))
        ));
        assert!(matches!(
            check(system(facts(FileKind::File, 0, 0o757))),
            Err(PathError::Writable(..))
        ));
        assert!(matches!(
            check(system(facts(FileKind::Symlink, 0, 0o777))),
            Err(PathError::Symlink(_))
        ));
        assert!(matches!(
            check(system(facts(FileKind::Directory, 0, 0o755))),
            Err(PathError::NotAFile(_))
        ));
        let mut entries = system(facts(FileKind::File, 0, 0o755));
        entries[2].1 = facts(FileKind::Directory, 1000, 0o755);
        assert!(matches!(
            check(entries),
            Err(PathError::NotRootOwned(p, 1000)) if p == std::path::Path::new("/usr/bin")
        ));
        let mut entries = system(facts(FileKind::File, 0, 0o755));
        entries[1].1 = facts(FileKind::Directory, 0, 0o777);
        assert!(matches!(check(entries), Err(PathError::Writable(..))));
        let mut entries = system(facts(FileKind::File, 0, 0o755));
        entries[1].1 = facts(FileKind::Symlink, 0, 0o777);
        assert!(matches!(check(entries), Err(PathError::Symlink(_))));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_prepare_without_tty() {
        let no_tty = Err(std::io::Error::from_raw_os_error(libc::ENXIO));
        let lstat_called = std::cell::Cell::new(false);
        let result = prepare(no_tty, |p: &std::path::Path| {
            lstat_called.set(true);
            fake_fs(system(facts(FileKind::File, 0, 0o755)))(p)
        });
        assert!(matches!(result, Err(FallbackError::NoTerminal)));
        assert!(!lstat_called.get());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_prepare_untrusted_pkttyagent() {
        let tty = std::fs::File::open("/dev/null");
        let result = prepare(tty, fake_fs(system(facts(FileKind::File, 1000, 0o755))));
        assert!(matches!(
            result,
            Err(FallbackError::Untrusted(PathError::NotRootOwned(..)))
        ));
    }

    #[test]
    fn test_fallback_error_status() {
        let mut refusal = crate::proto::AuthorizationError::new(
            crate::proto::authorization_error::Reason::NoAuthenticationAgent,
            "",
        );
        refusal.gate = crate::proto::GATE_USE_CREDENTIALS.to_owned();
        let status = FallbackError::NoTerminal.into_status(&refusal);
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            crate::proto::AuthorizationError::from_status(&status)
                .unwrap()
                .reason(),
            crate::proto::authorization_error::Reason::NoAuthenticationAgent
        );
        let message = crate::cmd::authorization::refusal_message(&status).unwrap();
        assert!(message.contains("no terminal"), "{message}");
        assert!(
            message.starts_with("refused at use-credentials: "),
            "{message}"
        );
    }

    #[tokio::test]
    async fn test_with_fallback_passes_other_results() {
        let mut calls = vec![];
        let retval: tonic::Result<u8> = with_fallback(
            |_| String::new(),
            |attempt| {
                calls.push(attempt);
                async { Err(tonic::Status::permission_denied("nope")) }
            },
        )
        .await;
        assert_eq!(retval.unwrap_err().code(), tonic::Code::PermissionDenied);
        assert_eq!(calls, vec![Attempt::First]);
    }
}
