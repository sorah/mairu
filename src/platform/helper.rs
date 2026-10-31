//! The agent's only `PlatformServices`: its platform helper child, reached over an inherited socketpair.

/// `AuthorizeResponse.reason` while no verified helper is running.
pub const REASON_UNAVAILABLE: &str = "helper-unavailable";
/// `AuthorizeResponse.reason` when the helper refused to serve this agent.
pub const REASON_UNVERIFIED: &str = "helper-unverified";
/// `AuthorizeResponse.reason` for a request about another user.
pub const REASON_FOREIGN_UID: &str = "foreign-uid";

const RESPAWN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const CAPABILITIES_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const EXIT_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// How the helper is started and how often it may be restarted.
#[derive(Debug, Clone)]
pub struct Launcher {
    program: std::path::PathBuf,
    args: Vec<std::ffi::OsString>,
    arg0: Option<std::ffi::OsString>,
    handshake_timeout: std::time::Duration,
    respawn_interval: std::time::Duration,
}

impl Launcher {
    /// This executable's own image, run as `mairu platform-helper --fd <n>`.
    pub fn own_image() -> std::io::Result<Self> {
        // The setgid bit re-applies when the kernel execs the file behind /proc/self/exe.
        #[cfg(target_os = "linux")]
        let program = std::path::PathBuf::from("/proc/self/exe");
        #[cfg(not(target_os = "linux"))]
        let program = std::env::current_exe()?;
        Ok(Self {
            program,
            args: vec!["platform-helper".into()],
            arg0: Some("mairu".into()),
            handshake_timeout: HANDSHAKE_TIMEOUT,
            respawn_interval: RESPAWN_INTERVAL,
        })
    }

    /// Runs `program args... --fd <n>`.
    pub fn new(
        program: impl Into<std::path::PathBuf>,
        args: impl IntoIterator<Item = impl Into<std::ffi::OsString>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            arg0: None,
            handshake_timeout: HANDSHAKE_TIMEOUT,
            respawn_interval: RESPAWN_INTERVAL,
        }
    }

    pub fn handshake_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    pub fn respawn_interval(mut self, interval: std::time::Duration) -> Self {
        self.respawn_interval = interval;
        self
    }

    fn command(&self, fd: std::os::fd::RawFd) -> std::process::Command {
        use std::os::unix::process::CommandExt;
        let mut cmd = crate::hardening::command(&self.program);
        if let Some(arg0) = &self.arg0 {
            cmd.arg0(arg0);
        }
        cmd.args(&self.args).arg("--fd").arg(fd.to_string());
        // SAFETY: fcntl is async-signal-safe, and fd stays open in the parent until spawn returns.
        unsafe {
            cmd.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd
    }
}

/// Why no helper is serving.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Failure {
    reason: &'static str,
    detail: String,
}

impl Failure {
    fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            reason: REASON_UNAVAILABLE,
            detail: detail.into(),
        }
    }

    fn from_exit(status: std::io::Result<std::process::ExitStatus>) -> Self {
        match status {
            Ok(s)
                if s.code() == Some(i32::from(crate::platform::HELPER_EXIT_PARENT_UNVERIFIED)) =>
            {
                Self {
                    reason: REASON_UNVERIFIED,
                    detail: "the helper refused to serve this agent".to_owned(),
                }
            }
            Ok(s) => Self::unavailable(format!("the helper exited ({s})")),
            Err(e) => Self::unavailable(format!("failed to wait for the helper: {e}")),
        }
    }
}

#[derive(Debug)]
enum State {
    Starting,
    Running {
        pid: u32,
        /// Liveness is checked through it, so a recycled pid is never mistaken for the helper.
        pidfd: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
        client: HelperRpc,
    },
    Unavailable(Failure),
}

type HelperRpc =
    crate::proto::platform::platform_helper_client::PlatformHelperClient<tonic::transport::Channel>;

/// The platform helper as the agent sees it. Every call fails closed while no verified helper is running.
#[derive(Debug)]
pub struct HelperClient {
    state: std::sync::Arc<parking_lot::Mutex<State>>,
    uid: u32,
    supervisor: tokio::task::JoinHandle<()>,
}

impl Drop for HelperClient {
    fn drop(&mut self) {
        // Drops the child, which is killed on drop.
        self.supervisor.abort();
    }
}

impl HelperClient {
    /// Spawns the helper and waits for the first attempt to finish. On failure it is retried in the background.
    pub async fn start(launcher: Launcher) -> Self {
        let state = std::sync::Arc::new(parking_lot::Mutex::new(State::Starting));
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let supervisor = tokio::spawn(supervise(launcher, state.clone(), ready_tx));
        let _ = ready_rx.await;
        Self {
            state,
            uid: nix::unistd::geteuid().as_raw(),
            supervisor,
        }
    }

    /// For `GetAgentStatusResponse.platform_helper`, e.g. `running pid=4321 verified`.
    pub fn describe(&self) -> String {
        match self.client() {
            Ok((pid, _)) => format!("running pid={pid} verified"),
            Err(f) if matches!(*self.state.lock(), State::Starting) => {
                format!("starting ({})", f.detail)
            }
            Err(f) => format!("unavailable: {} ({})", f.reason, f.detail),
        }
    }

    /// The pid of the running, verified helper.
    pub fn pid(&self) -> Option<u32> {
        self.client().ok().map(|(pid, _)| pid)
    }

    fn client(&self) -> Result<(u32, HelperRpc), Failure> {
        match &*self.state.lock() {
            State::Running { pid, pidfd, client } => {
                if pidfd.as_ref().is_some_and(|p| !pidfd_alive(p)) {
                    return Err(Failure::unavailable("the helper exited"));
                }
                Ok((*pid, client.clone()))
            }
            State::Starting => Err(Failure::unavailable("the helper is starting")),
            State::Unavailable(f) => Err(f.clone()),
        }
    }

    fn require_own_uid(&self, uid: u32) -> Result<(), Failure> {
        if uid != self.uid {
            tracing::warn!(
                uid,
                own = self.uid,
                "Refusing a platform request for another uid"
            );
            return Err(Failure {
                reason: REASON_FOREIGN_UID,
                detail: format!("request for uid {uid}; this agent serves uid {}", self.uid),
            });
        }
        Ok(())
    }
}

fn status_failure(status: tonic::Status) -> Failure {
    Failure::unavailable(format!(
        "the helper call failed: {:?}: {}",
        status.code(),
        status.message()
    ))
}

#[async_trait::async_trait]
impl crate::platform::PlatformServices for HelperClient {
    async fn capabilities(
        &self,
        req: crate::proto::platform::GetCapabilitiesRequest,
    ) -> crate::proto::platform::Capabilities {
        let Ok((_, mut client)) = self.client() else {
            return crate::proto::platform::Capabilities::default();
        };
        let call = client.get_capabilities(req);
        match tokio::time::timeout(CAPABILITIES_TIMEOUT, call).await {
            Ok(Ok(resp)) => resp.into_inner(),
            Ok(Err(e)) => {
                tracing::warn!(err = %e, "GetCapabilities failed");
                crate::proto::platform::Capabilities::default()
            }
            Err(_) => {
                tracing::warn!("GetCapabilities timed out");
                crate::proto::platform::Capabilities::default()
            }
        }
    }

    async fn authorize(
        &self,
        req: crate::proto::platform::AuthorizeRequest,
    ) -> crate::proto::platform::AuthorizeResponse {
        let result = async {
            if let Some(subject) = &req.subject {
                self.require_own_uid(subject.uid)?;
            }
            let (_, mut client) = self.client()?;
            client
                .authorize(req)
                .await
                .map(tonic::Response::into_inner)
                .map_err(status_failure)
        };
        result.await.unwrap_or_else(|f| {
            crate::proto::platform::AuthorizeResponse::unavailable(f.reason, f.detail)
        })
    }

    async fn notify(
        &self,
        req: crate::proto::platform::NotifyRequest,
    ) -> crate::proto::platform::NotifyResponse {
        let Ok((_, mut client)) = self.client() else {
            return crate::proto::platform::NotifyResponse { delivered: false };
        };
        client
            .notify(req)
            .await
            .map(tonic::Response::into_inner)
            .unwrap_or(crate::proto::platform::NotifyResponse { delivered: false })
    }

    async fn open_url(
        &self,
        req: crate::proto::platform::OpenUrlRequest,
    ) -> crate::proto::platform::OpenUrlResponse {
        let result = async {
            let (_, mut client) = self.client()?;
            client
                .open_url(req)
                .await
                .map(tonic::Response::into_inner)
                .map_err(status_failure)
        };
        result
            .await
            .unwrap_or_else(|f| crate::proto::platform::OpenUrlResponse {
                opened: false,
                detail: format!("{}: {}", f.reason, f.detail),
            })
    }

    async fn record_integrity(
        &self,
        req: crate::proto::platform::RecordIntegrityRequest,
    ) -> crate::proto::platform::RecordIntegrityResponse {
        let result = async {
            self.require_own_uid(req.uid)?;
            let (_, mut client) = self.client()?;
            client
                .record_integrity(req)
                .await
                .map(tonic::Response::into_inner)
                .map_err(status_failure)
        };
        result.await.unwrap_or_else(|f| {
            tracing::warn!(
                reason = f.reason,
                detail = f.detail,
                "RecordIntegrity failed"
            );
            crate::proto::platform::RecordIntegrityResponse { results: vec![] }
        })
    }

    async fn verify_integrity(
        &self,
        req: crate::proto::platform::VerifyIntegrityRequest,
    ) -> crate::proto::platform::VerifyIntegrityResponse {
        let result = async {
            self.require_own_uid(req.uid)?;
            let (_, mut client) = self.client()?;
            client
                .verify_integrity(req)
                .await
                .map(tonic::Response::into_inner)
                .map_err(status_failure)
        };
        result.await.unwrap_or_else(|f| {
            tracing::warn!(
                reason = f.reason,
                detail = f.detail,
                "VerifyIntegrity failed"
            );
            crate::proto::platform::VerifyIntegrityResponse { results: vec![] }
        })
    }
}

/// Spawn attempts are at least `interval` apart.
#[derive(Debug)]
struct RespawnLimiter {
    interval: std::time::Duration,
    last: Option<tokio::time::Instant>,
}

impl RespawnLimiter {
    fn new(interval: std::time::Duration) -> Self {
        Self {
            interval,
            last: None,
        }
    }

    fn next_attempt(&self) -> Option<tokio::time::Instant> {
        self.last.map(|last| last + self.interval)
    }

    fn record(&mut self, now: tokio::time::Instant) {
        self.last = Some(now);
    }
}

async fn supervise(
    launcher: Launcher,
    state: std::sync::Arc<parking_lot::Mutex<State>>,
    ready: tokio::sync::oneshot::Sender<()>,
) {
    let mut ready = Some(ready);
    let mut limiter = RespawnLimiter::new(launcher.respawn_interval);
    loop {
        if let Some(at) = limiter.next_attempt() {
            tokio::time::sleep_until(at).await;
        }
        limiter.record(tokio::time::Instant::now());
        match Spawned::spawn(&launcher).await {
            Ok(mut helper) => {
                tracing::info!(pid = helper.pid, "Platform helper started");
                *state.lock() = State::Running {
                    pid: helper.pid,
                    pidfd: helper.pidfd.take(),
                    client: helper.client.clone(),
                };
                if let Some(tx) = ready.take() {
                    let _ = tx.send(());
                }
                let failure = Failure::from_exit(helper.child.wait().await);
                tracing::warn!(
                    pid = helper.pid,
                    reason = failure.reason,
                    detail = failure.detail,
                    "Platform helper stopped; platform services fail closed until it is respawned"
                );
                *state.lock() = State::Unavailable(failure);
            }
            Err(failure) => {
                tracing::warn!(
                    reason = failure.reason,
                    detail = failure.detail,
                    "Platform helper is unavailable; platform services fail closed"
                );
                *state.lock() = State::Unavailable(failure);
                if let Some(tx) = ready.take() {
                    let _ = tx.send(());
                }
            }
        }
    }
}

/// A helper that answered the first `GetCapabilities`.
struct Spawned {
    child: tokio::process::Child,
    pid: u32,
    pidfd: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
    client: HelperRpc,
}

impl Spawned {
    async fn spawn(launcher: &Launcher) -> Result<Self, Failure> {
        use std::os::fd::AsRawFd;
        // The kernel records the creator's credentials for the pair, so the helper sees the marker gid.
        let (agent_end, helper_end) =
            crate::hardening::with_privileged_gid(std::os::unix::net::UnixStream::pair)
                .map_err(|e| Failure::unavailable(format!("socketpair failed: {e}")))?;
        let mut cmd = tokio::process::Command::from(launcher.command(helper_end.as_raw_fd()));
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| {
            Failure::unavailable(format!(
                "failed to spawn {}: {e}",
                launcher.program.display()
            ))
        })?;
        drop(helper_end);
        let pid = child.id().unwrap_or(0);
        let pidfd = own_child_pidfd(pid);
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(forward_log(pid, stderr));
        }

        match tokio::time::timeout(launcher.handshake_timeout, handshake(agent_end)).await {
            Ok(Ok(client)) => Ok(Self {
                child,
                pid,
                pidfd,
                client,
            }),
            outcome => {
                let detail = match outcome {
                    Ok(Err(e)) => format!("handshake failed: {e}"),
                    _ => "the helper did not answer in time".to_owned(),
                };
                // A helper that refused this agent has exited with a status saying so.
                match tokio::time::timeout(EXIT_WAIT, child.wait()).await {
                    Ok(status) => {
                        let failure = Failure::from_exit(status);
                        if failure.reason == REASON_UNVERIFIED {
                            return Err(failure);
                        }
                        Err(Failure::unavailable(format!(
                            "{detail}; {}",
                            failure.detail
                        )))
                    }
                    Err(_) => {
                        let _ = child.kill().await;
                        Err(Failure::unavailable(detail))
                    }
                }
            }
        }
    }
}

async fn handshake(stream: std::os::unix::net::UnixStream) -> Result<HelperRpc, anyhow::Error> {
    stream.set_nonblocking(true)?;
    let slot = std::sync::Arc::new(parking_lot::Mutex::new(Some(
        tokio::net::UnixStream::from_std(stream)?,
    )));
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(tower::service_fn(move |_| {
            let stream = slot.lock().take();
            async move {
                stream.map(hyper_util::rt::TokioIo::new).ok_or_else(|| {
                    std::io::Error::other("the platform helper connection cannot be reopened")
                })
            }
        }))
        .await?;
    let mut client = HelperRpc::new(channel);
    client
        .get_capabilities(crate::proto::platform::GetCapabilitiesRequest::default())
        .await?;
    Ok(client)
}

async fn forward_log(pid: u32, stderr: tokio::process::ChildStderr) {
    use tokio::io::AsyncBufReadExt;
    let mut lines = tokio::io::BufReader::new(stderr).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        tracing::info!(helper_pid = pid, "platform-helper: {line}");
    }
}

#[cfg(target_os = "linux")]
fn own_child_pidfd(pid: u32) -> Option<std::sync::Arc<std::os::fd::OwnedFd>> {
    // An unreaped child's pid cannot be recycled, so opening it after spawn is race-free.
    match crate::platform::process::linux::peer::pidfd_open(pid) {
        Ok(fd) => Some(std::sync::Arc::new(fd)),
        Err(e) => {
            tracing::debug!(pid, err = %e, "pidfd_open failed for the platform helper");
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn own_child_pidfd(_pid: u32) -> Option<std::sync::Arc<std::os::fd::OwnedFd>> {
    None
}

#[cfg(target_os = "linux")]
fn pidfd_alive(pidfd: &std::os::fd::OwnedFd) -> bool {
    use std::os::fd::AsFd;
    crate::platform::process::linux::peer::pidfd_alive(pidfd.as_fd())
}

#[cfg(not(target_os = "linux"))]
fn pidfd_alive(_pidfd: &std::os::fd::OwnedFd) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::PlatformServices;

    fn sh(script: &str) -> Launcher {
        Launcher::new("/bin/sh", ["-c", script])
            .handshake_timeout(std::time::Duration::from_millis(500))
            .respawn_interval(std::time::Duration::from_secs(3600))
    }

    async fn assert_fails_closed(helper: &HelperClient, reason: &str) {
        let resp = helper
            .authorize(crate::proto::platform::AuthorizeRequest::default())
            .await;
        assert_eq!(
            resp.result(),
            crate::proto::platform::authorize_response::Result::Unavailable
        );
        assert_eq!(resp.reason, reason, "{}", resp.detail);
        assert_eq!(
            helper.capabilities(Default::default()).await,
            crate::proto::platform::Capabilities::default()
        );
        let verify = helper
            .verify_integrity(crate::proto::platform::VerifyIntegrityRequest {
                uid: nix::unistd::geteuid().as_raw(),
                ..Default::default()
            })
            .await;
        assert!(verify.results.is_empty());
        assert!(
            !helper
                .notify(crate::proto::platform::NotifyRequest::default())
                .await
                .delivered
        );
        assert!(
            helper
                .describe()
                .starts_with(&format!("unavailable: {reason}")),
            "{}",
            helper.describe()
        );
    }

    #[tokio::test]
    async fn test_dead_helper_is_unavailable() {
        let helper = HelperClient::start(sh("exit 0")).await;
        assert_fails_closed(&helper, REASON_UNAVAILABLE).await;
    }

    #[tokio::test]
    async fn test_helper_refusing_agent_is_unverified() {
        let helper = HelperClient::start(sh("exit 3")).await;
        assert_fails_closed(&helper, REASON_UNVERIFIED).await;
    }

    #[tokio::test]
    async fn test_silent_helper_is_unavailable() {
        // Holds the socketpair without speaking the protocol.
        let helper = HelperClient::start(sh("sleep 30")).await;
        assert_fails_closed(&helper, REASON_UNAVAILABLE).await;
    }

    #[tokio::test]
    async fn test_missing_program_is_unavailable() {
        let launcher = Launcher::new("/nonexistent/mairu", ["platform-helper"])
            .respawn_interval(std::time::Duration::from_secs(3600));
        let helper = HelperClient::start(launcher).await;
        assert_fails_closed(&helper, REASON_UNAVAILABLE).await;
    }

    #[tokio::test]
    async fn test_foreign_uid_is_refused_before_the_helper() {
        let helper = HelperClient::start(sh("exit 0")).await;
        let resp = helper
            .authorize(crate::proto::platform::AuthorizeRequest {
                subject: Some(crate::proto::platform::Process {
                    uid: nix::unistd::geteuid().as_raw() + 1,
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await;
        assert_eq!(resp.reason, REASON_FOREIGN_UID);
    }

    #[test]
    fn test_respawn_limiter() {
        let interval = std::time::Duration::from_secs(30);
        let mut limiter = RespawnLimiter::new(interval);
        assert_eq!(limiter.next_attempt(), None);
        let t0 = tokio::time::Instant::now();
        limiter.record(t0);
        assert_eq!(limiter.next_attempt(), Some(t0 + interval));
        let t1 = t0 + std::time::Duration::from_secs(45);
        limiter.record(t1);
        assert_eq!(limiter.next_attempt(), Some(t1 + interval));
    }

    #[test]
    fn test_failure_from_exit() {
        use std::os::unix::process::ExitStatusExt;
        let unverified = Failure::from_exit(Ok(std::process::ExitStatus::from_raw(3 << 8)));
        assert_eq!(unverified.reason, REASON_UNVERIFIED);
        let crashed = Failure::from_exit(Ok(std::process::ExitStatus::from_raw(9)));
        assert_eq!(crashed.reason, REASON_UNAVAILABLE);
        let exited = Failure::from_exit(Ok(std::process::ExitStatus::from_raw(1 << 8)));
        assert_eq!(exited.reason, REASON_UNAVAILABLE);
    }
}
