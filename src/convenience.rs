//! Opening URLs and posting desktop notifications from a client. Each client chooses how they are delivered, from
//! unprotected settings, because nothing relies on them. Failures are logged at debug level and otherwise ignored.

/// How long a user's helper program is waited for before it is left to run and reaped in the background.
const COMMAND_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
/// Bounds an `OpenUrl`/`Notify` call to the agent, whose helper waits for the session bus and `xdg-open`.
const AGENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

const LOGIN_REQUIRED_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);
const AI_AGENT_DENIED_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    OpenUrl,
    Notify,
}

impl Feature {
    pub fn name(self) -> &'static str {
        match self {
            Feature::OpenUrl => "open_url",
            Feature::Notify => "notify",
        }
    }

    fn env_mode(self) -> &'static str {
        match self {
            Feature::OpenUrl => "MAIRU_OPEN_URL",
            Feature::Notify => "MAIRU_NOTIFY",
        }
    }

    fn env_command(self) -> &'static str {
        match self {
            Feature::OpenUrl => "MAIRU_OPEN_URL_COMMAND",
            Feature::Notify => "MAIRU_NOTIFY_COMMAND",
        }
    }
}

/// What a feature resolves to for this client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// The agent's `OpenUrl`/`Notify` RPCs, delivered by the platform helper.
    Agent,
    /// The user's program, as an argv.
    Command(Vec<String>),
    /// The user's shell command line, run as `/bin/sh -c '<line> "$@"' mairu <args…>`.
    Shell(String),
    None,
}

impl std::fmt::Display for Delivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Delivery::Agent => write!(f, "agent"),
            Delivery::Command(argv) => write!(f, "command ({})", argv.join(" ")),
            Delivery::Shell(line) => write!(f, "command ({line})"),
            Delivery::None => write!(f, "none"),
        }
    }
}

/// Everything a feature's mode is resolved from.
#[derive(Debug, Default, Clone)]
pub struct Sources {
    /// `--no-browser`.
    pub no_browser: bool,
    pub env_mode: Option<String>,
    pub env_command: Option<String>,
    pub config: crate::config::ConvenienceConfig,
    /// `$BROWSER`.
    pub browser: Option<String>,
}

impl Sources {
    fn from_env(feature: Feature, no_browser: bool, config: &crate::config::UserConfig) -> Self {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        Self {
            no_browser,
            env_mode: var(feature.env_mode()),
            env_command: var(feature.env_command()),
            config: match feature {
                Feature::OpenUrl => config.open_url.clone(),
                Feature::Notify => config.notify.clone(),
            },
            browser: var("BROWSER"),
        }
    }
}

impl Delivery {
    /// Flag, then environment, then config.json, then `auto`. An explicit mode wins over a `*_COMMAND` variable,
    /// which otherwise implies `command`.
    pub fn resolve(feature: Feature, sources: &Sources) -> Self {
        use crate::config::ConvenienceMode as M;
        if feature == Feature::OpenUrl && sources.no_browser {
            return Delivery::None;
        }
        let env_mode = sources.env_mode.as_deref().and_then(|m| {
            m.parse::<M>()
                .inspect_err(|e| tracing::warn!("{}: {e}", feature.env_mode()))
                .ok()
        });
        let configured_command = || {
            if sources.config.command.is_empty() {
                tracing::debug!(
                    feature = feature.name(),
                    "command mode without a command; disabled"
                );
                Delivery::None
            } else {
                Delivery::Command(sources.config.command.clone())
            }
        };
        match (env_mode, &sources.env_command) {
            (Some(M::Command) | None, Some(line)) => return Delivery::Shell(line.clone()),
            (Some(M::Command), None) => return configured_command(),
            (Some(mode), _) => return Self::from_mode(feature, mode, sources),
            (None, None) => {}
        }
        match sources.config.mode {
            Some(M::Command) => configured_command(),
            Some(mode) => Self::from_mode(feature, mode, sources),
            None => Self::from_mode(feature, M::Auto, sources),
        }
    }

    fn from_mode(
        feature: Feature,
        mode: crate::config::ConvenienceMode,
        sources: &Sources,
    ) -> Self {
        use crate::config::ConvenienceMode as M;
        match mode {
            M::Agent => Delivery::Agent,
            M::None => Delivery::None,
            M::Auto => match (feature, &sources.browser) {
                (Feature::OpenUrl, Some(browser)) => Delivery::Shell(browser.clone()),
                _ => Delivery::Agent,
            },
            M::Command => unreachable!("resolved by the caller"),
        }
    }
}

/// Both features, resolved once per client process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub open_url: Delivery,
    pub notify: Delivery,
}

static SETTINGS: std::sync::OnceLock<Settings> = std::sync::OnceLock::new();

impl Settings {
    /// Resolves the settings with `--no-browser`; the first call in a process wins.
    pub fn init(no_browser: bool) -> &'static Settings {
        SETTINGS.get_or_init(|| Self::load(no_browser))
    }

    pub fn get() -> &'static Settings {
        Self::init(false)
    }

    fn load(no_browser: bool) -> Self {
        let config = crate::config::UserConfig::load_sync().unwrap_or_else(|e| {
            tracing::debug!(err = %e, "Failed to read config.json; using the default open_url and notify");
            Default::default()
        });
        Self {
            open_url: Delivery::resolve(
                Feature::OpenUrl,
                &Sources::from_env(Feature::OpenUrl, no_browser, &config),
            ),
            notify: Delivery::resolve(
                Feature::Notify,
                &Sources::from_env(Feature::Notify, no_browser, &config),
            ),
        }
    }
}

/// Opens `url` as this client's settings say; whether it was opened.
pub async fn open_url(agent: &crate::agent::AgentConn, url: &str) -> bool {
    let req = crate::proto::platform::OpenUrlRequest {
        url: url.to_owned(),
        session: Some(crate::proto::platform::SessionHint::current()),
    };
    if let Err(e) = req.checked_url() {
        tracing::debug!(err = e, "Not opening a URL");
        return false;
    }
    let delivery = &Settings::get().open_url;
    let opened = match delivery {
        Delivery::None => false,
        Delivery::Agent => {
            let Some(mut client) = usable_agent(agent) else {
                return false;
            };
            match tokio::time::timeout(AGENT_TIMEOUT, client.open_url(req)).await {
                Ok(Ok(resp)) => {
                    let resp = resp.into_inner();
                    tracing::debug!(opened = resp.opened, detail = resp.detail, "OpenUrl");
                    resp.opened
                }
                Ok(Err(e)) => {
                    tracing::debug!(err = %e, "OpenUrl failed");
                    false
                }
                Err(_) => {
                    tracing::debug!("OpenUrl timed out");
                    false
                }
            }
        }
        Delivery::Command(argv) => run_argv(argv, &[url], &[]).await,
        Delivery::Shell(line) => run_shell(line, &[url], &[]).await,
    };
    tracing::debug!(%delivery, opened, "Opened a URL");
    opened
}

/// A notification of one of the events clients emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub event: &'static str,
    pub urgency: crate::proto::platform::notify_request::Urgency,
    pub title: String,
    pub body: String,
    /// One notification per key within `interval`; `None` means once per key.
    key: String,
    interval: Option<std::time::Duration>,
}

impl Notification {
    pub fn login_required(server: &str) -> Self {
        let product = env!("CARGO_PKG_NAME");
        Self {
            event: "login-required",
            urgency: crate::proto::platform::notify_request::Urgency::Normal,
            title: format!("{product}: login required"),
            body: format!(
                "Log in to {server} to keep serving AWS credentials: {product} login {server}"
            ),
            key: server.to_owned(),
            interval: Some(LOGIN_REQUIRED_INTERVAL),
        }
    }

    pub fn ai_agent_denied(server: &str, rolespec: &crate::proto::Rolespec, reason: &str) -> Self {
        let product = env!("CARGO_PKG_NAME");
        let role = match &rolespec.assume_role {
            Some(a) => format!("{} (then {})", rolespec.role, a.role_arn),
            None => rolespec.role.clone(),
        };
        Self {
            event: "ai-agent-denied",
            urgency: crate::proto::platform::notify_request::Urgency::Normal,
            title: format!("{product}: refused an AI agent's request"),
            body: format!("{role} on {server}: {reason}"),
            key: format!("{server}\0{role}"),
            interval: Some(AI_AGENT_DENIED_INTERVAL),
        }
    }

    /// `instance` tells agent processes apart, so each lockdown is posted once.
    pub fn policy_lockdown(instance: &str) -> Self {
        let product = env!("CARGO_PKG_NAME");
        Self {
            event: "policy-lockdown",
            urgency: crate::proto::platform::notify_request::Urgency::Critical,
            title: format!("{product}: policy lockdown"),
            body: crate::policy::files::LOCKDOWN_WARNING.to_owned(),
            key: instance.to_owned(),
            interval: None,
        }
    }

    fn urgency_name(&self) -> &'static str {
        use crate::proto::platform::notify_request::Urgency;
        match self.urgency {
            Urgency::Low => "low",
            Urgency::Unspecified | Urgency::Normal => "normal",
            Urgency::Critical => "critical",
        }
    }
}

/// Posts `notification` as this client's settings say, within its rate limit; whether it was delivered.
pub async fn notify(agent: &crate::agent::AgentConn, notification: Notification) -> bool {
    let delivery = &Settings::get().notify;
    if *delivery == Delivery::None {
        return false;
    }
    let limit = RateLimit::default();
    if !limit.due(
        notification.event,
        &notification.key,
        notification.interval,
        std::time::SystemTime::now(),
    ) {
        tracing::debug!(
            event = notification.event,
            "Not repeating a recent notification"
        );
        return false;
    }
    let mut req = crate::proto::platform::NotifyRequest {
        title: notification.title.clone(),
        body: notification.body.clone(),
        urgency: notification.urgency.into(),
        event: notification.event.to_owned(),
        session: Some(crate::proto::platform::SessionHint::current()),
    };
    req.truncate();
    let env = [
        ("MAIRU_NOTIFY_URGENCY", notification.urgency_name()),
        ("MAIRU_NOTIFY_EVENT", notification.event),
    ];
    let delivered = match delivery {
        Delivery::None => false,
        Delivery::Agent => {
            let Some(mut client) = usable_agent(agent) else {
                return false;
            };
            match tokio::time::timeout(AGENT_TIMEOUT, client.notify(req)).await {
                Ok(Ok(resp)) => resp.into_inner().delivered,
                Ok(Err(e)) => {
                    tracing::debug!(err = %e, "Notify failed");
                    false
                }
                Err(_) => {
                    tracing::debug!("Notify timed out");
                    false
                }
            }
        }
        Delivery::Command(argv) => run_argv(argv, &[&req.title, &req.body], &env).await,
        Delivery::Shell(line) => run_shell(line, &[&req.title, &req.body], &env).await,
    };
    tracing::debug!(event = notification.event, %delivery, delivered, "Posted a notification");
    if delivered {
        limit.record(
            notification.event,
            &notification.key,
            std::time::SystemTime::now(),
        );
    }
    delivered
}

/// Posts the AI-agent refusal notification when `status` refuses a request labelled `ai-agent`.
pub async fn notify_refusal(
    agent: &crate::agent::AgentConn,
    req: &crate::proto::AssumeRoleRequest,
    status: &tonic::Status,
) {
    use crate::proto::authorization_error::Reason;
    let Some(refusal) = crate::proto::AuthorizationError::from_status(status) else {
        return;
    };
    if !matches!(refusal.reason(), Reason::Forbidden | Reason::NotPermitted)
        || !refusal
            .tools
            .iter()
            .any(|t| t == crate::tool_detection::AI_AGENT)
    {
        return;
    }
    let notification =
        Notification::ai_agent_denied(&req.server_id, &req.rolespec(), &refusal.user_message());
    notify(agent, notification).await;
}

/// Posts the lockdown notification once per agent process.
pub async fn notify_lockdown(agent: &crate::agent::AgentConn) {
    use std::os::unix::fs::MetadataExt;
    let started = std::fs::metadata(agent.path())
        .map(|m| m.mtime())
        .unwrap_or_default();
    let pid = agent.identity().pid.unwrap_or_default();
    notify(
        agent,
        Notification::policy_lockdown(&format!("{pid}-{started}")),
    )
    .await;
}

/// The agent's client, unless the agent is one this mairu cannot verify.
fn usable_agent(
    agent: &crate::agent::AgentConn,
) -> Option<crate::proto::agent_client::AgentClient<crate::agent::AgentChannel>> {
    if agent.trust() == crate::platform::AgentTrust::Unverified {
        tracing::debug!("Not asking an unverified agent");
        return None;
    }
    Some((**agent).clone())
}

async fn run_argv(argv: &[String], args: &[&str], env: &[(&str, &str)]) -> bool {
    let Some((program, rest)) = argv.split_first() else {
        return false;
    };
    let mut cmd = crate::hardening::command(program);
    cmd.args(rest).args(args);
    run(cmd, env).await
}

async fn run_shell(line: &str, args: &[&str], env: &[(&str, &str)]) -> bool {
    let mut cmd = crate::hardening::command("/bin/sh");
    cmd.arg("-c")
        .arg(format!("{line} \"$@\""))
        .arg(env!("CARGO_PKG_NAME"))
        .args(args);
    run(cmd, env).await
}

/// Waits at most [`COMMAND_WAIT`]; a program still running then counts as success and is reaped in the
/// background.
async fn run(mut cmd: std::process::Command, env: &[(&str, &str)]) -> bool {
    cmd.envs(env.iter().copied())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null());
    let mut child = match tokio::process::Command::from(cmd).spawn() {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(err = %e, "Failed to run the helper program");
            return false;
        }
    };
    match tokio::time::timeout(COMMAND_WAIT, child.wait()).await {
        Ok(Ok(status)) => {
            tracing::debug!(%status, "The helper program exited");
            status.success()
        }
        Ok(Err(e)) => {
            tracing::debug!(err = %e, "Failed to wait for the helper program");
            false
        }
        Err(_) => {
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
            true
        }
    }
}

/// One file per event key under `runtime_dir()/notified/`, compared by mtime. Best-effort: a cleared runtime
/// directory repeats a notification. Only delivered notifications are recorded, so a client without a desktop
/// does not hold one back from a client with one.
#[derive(Debug)]
pub struct RateLimit {
    dir: std::path::PathBuf,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            dir: crate::config::runtime_dir().join("notified"),
        }
    }
}

impl RateLimit {
    pub fn new(dir: std::path::PathBuf) -> Self {
        Self { dir }
    }

    /// Whether the event for `key` may be posted at `now`.
    pub fn due(
        &self,
        event: &str,
        key: &str,
        interval: Option<std::time::Duration>,
        now: std::time::SystemTime,
    ) -> bool {
        let Ok(modified) = std::fs::metadata(self.path(event, key)).and_then(|m| m.modified())
        else {
            return true;
        };
        interval.is_some_and(|i| now.duration_since(modified).unwrap_or_default() >= i)
    }

    /// Records that the event for `key` was posted at `now`.
    pub fn record(&self, event: &str, key: &str, now: std::time::SystemTime) {
        use std::os::unix::fs::DirBuilderExt;
        let path = self.path(event, key);
        let written = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .and_then(|()| std::fs::File::create(&path)?.set_modified(now));
        if let Err(e) = written {
            tracing::debug!(path = %path.display(), err = %e, "Failed to record a notification");
        }
    }

    fn path(&self, event: &str, key: &str) -> std::path::PathBuf {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(key.as_bytes());
        let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        self.dir.join(format!("{event}-{hex}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConvenienceMode as M;

    fn sources() -> Sources {
        Sources::default()
    }

    fn config(mode: Option<M>, command: &[&str]) -> crate::config::ConvenienceConfig {
        crate::config::ConvenienceConfig {
            mode,
            command: command.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_resolve_auto() {
        assert_eq!(
            Delivery::resolve(Feature::OpenUrl, &sources()),
            Delivery::Agent
        );
        assert_eq!(
            Delivery::resolve(Feature::Notify, &sources()),
            Delivery::Agent
        );
        let browser = Sources {
            browser: Some("firefox".to_owned()),
            ..sources()
        };
        assert_eq!(
            Delivery::resolve(Feature::OpenUrl, &browser),
            Delivery::Shell("firefox".to_owned())
        );
        assert_eq!(
            Delivery::resolve(Feature::Notify, &browser),
            Delivery::Agent
        );
    }

    #[test]
    fn test_resolve_no_browser_wins() {
        let s = Sources {
            no_browser: true,
            env_mode: Some("agent".to_owned()),
            env_command: Some("open".to_owned()),
            config: config(Some(M::Agent), &[]),
            browser: Some("firefox".to_owned()),
        };
        assert_eq!(Delivery::resolve(Feature::OpenUrl, &s), Delivery::None);
        // --no-browser is only about URLs.
        assert_eq!(Delivery::resolve(Feature::Notify, &s), Delivery::Agent);
    }

    #[test]
    fn test_resolve_env_over_config() {
        let s = Sources {
            env_mode: Some("none".to_owned()),
            config: config(Some(M::Agent), &[]),
            ..sources()
        };
        assert_eq!(Delivery::resolve(Feature::Notify, &s), Delivery::None);
        let s = Sources {
            env_mode: Some("agent".to_owned()),
            config: config(Some(M::Command), &["my-notify"]),
            browser: Some("firefox".to_owned()),
            ..sources()
        };
        assert_eq!(Delivery::resolve(Feature::OpenUrl, &s), Delivery::Agent);
        // An invalid value is ignored.
        let s = Sources {
            env_mode: Some("bogus".to_owned()),
            config: config(Some(M::None), &[]),
            ..sources()
        };
        assert_eq!(Delivery::resolve(Feature::Notify, &s), Delivery::None);
    }

    #[test]
    fn test_resolve_env_command_implies_command() {
        let s = Sources {
            env_command: Some("notify-send-wrapper --quiet".to_owned()),
            config: config(Some(M::None), &[]),
            ..sources()
        };
        assert_eq!(
            Delivery::resolve(Feature::Notify, &s),
            Delivery::Shell("notify-send-wrapper --quiet".to_owned())
        );
        let s = Sources {
            env_mode: Some("command".to_owned()),
            env_command: Some("x".to_owned()),
            ..sources()
        };
        assert_eq!(
            Delivery::resolve(Feature::Notify, &s),
            Delivery::Shell("x".to_owned())
        );
        // An explicit mode wins over the command variable.
        let s = Sources {
            env_mode: Some("none".to_owned()),
            env_command: Some("x".to_owned()),
            ..sources()
        };
        assert_eq!(Delivery::resolve(Feature::Notify, &s), Delivery::None);
        // MAIRU_*=command without MAIRU_*_COMMAND takes config.json's command.
        let s = Sources {
            env_mode: Some("command".to_owned()),
            config: config(Some(M::Agent), &["my-open-url", "--tab"]),
            ..sources()
        };
        assert_eq!(
            Delivery::resolve(Feature::OpenUrl, &s),
            Delivery::Command(vec!["my-open-url".to_owned(), "--tab".to_owned()])
        );
    }

    #[test]
    fn test_resolve_config() {
        let s = Sources {
            config: config(Some(M::Command), &["my-open-url"]),
            browser: Some("firefox".to_owned()),
            ..sources()
        };
        assert_eq!(
            Delivery::resolve(Feature::OpenUrl, &s),
            Delivery::Command(vec!["my-open-url".to_owned()])
        );
        let s = Sources {
            config: config(Some(M::Command), &[]),
            ..sources()
        };
        assert_eq!(Delivery::resolve(Feature::OpenUrl, &s), Delivery::None);
        let s = Sources {
            config: config(Some(M::Auto), &[]),
            browser: Some("w3m".to_owned()),
            ..sources()
        };
        assert_eq!(
            Delivery::resolve(Feature::OpenUrl, &s),
            Delivery::Shell("w3m".to_owned())
        );
    }

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "mairu-test-convenience-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `due`, then `record` when due, as [`notify`] does for a delivered notification.
    fn post(
        limit: &RateLimit,
        event: &str,
        key: &str,
        interval: Option<std::time::Duration>,
        now: std::time::SystemTime,
    ) -> bool {
        let due = limit.due(event, key, interval, now);
        if due {
            limit.record(event, key, now);
        }
        due
    }

    #[test]
    fn test_rate_limit_interval() {
        let dir = TempDir::new("interval");
        let limit = RateLimit::new(dir.0.join("notified"));
        let minute = Some(std::time::Duration::from_secs(60));
        let t0 = std::time::SystemTime::now();
        let at = |s: u64| t0 + std::time::Duration::from_secs(s);
        assert!(post(&limit, "ai-agent-denied", "a", minute, t0));
        assert!(!post(&limit, "ai-agent-denied", "a", minute, at(30)));
        // Other keys and events are independent.
        assert!(post(&limit, "ai-agent-denied", "b", minute, at(30)));
        assert!(post(&limit, "login-required", "a", minute, at(30)));
        assert!(post(&limit, "ai-agent-denied", "a", minute, at(61)));
        assert!(!post(&limit, "ai-agent-denied", "a", minute, at(100)));
        assert!(post(&limit, "ai-agent-denied", "a", minute, at(121)));
    }

    #[test]
    fn test_rate_limit_undelivered_is_not_recorded() {
        let dir = TempDir::new("undelivered");
        let limit = RateLimit::new(dir.0.join("notified"));
        let t0 = std::time::SystemTime::now();
        assert!(limit.due("login-required", "a", Some(LOGIN_REQUIRED_INTERVAL), t0));
        assert!(limit.due("login-required", "a", Some(LOGIN_REQUIRED_INTERVAL), t0));
        assert!(!dir.0.join("notified").exists());
    }

    #[test]
    fn test_rate_limit_once() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("once");
        let limit = RateLimit::new(dir.0.join("notified"));
        let t0 = std::time::SystemTime::now();
        assert!(post(&limit, "policy-lockdown", "4242-1", None, t0));
        assert!(!post(
            &limit,
            "policy-lockdown",
            "4242-1",
            None,
            t0 + std::time::Duration::from_secs(86400)
        ));
        assert!(post(&limit, "policy-lockdown", "4343-2", None, t0));
        let mode = std::fs::metadata(dir.0.join("notified"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn test_rate_limit_unwritable_still_posts() {
        let dir = TempDir::new("unwritable");
        std::fs::write(&dir.0, b"").unwrap();
        let limit = RateLimit::new(dir.0.join("notified"));
        let t0 = std::time::SystemTime::now();
        assert!(post(
            &limit,
            "login-required",
            "a",
            Some(LOGIN_REQUIRED_INTERVAL),
            t0
        ));
        assert!(post(
            &limit,
            "login-required",
            "a",
            Some(LOGIN_REQUIRED_INTERVAL),
            t0
        ));
        std::fs::remove_file(&dir.0).unwrap();
    }

    #[test]
    fn test_notifications() {
        let n = Notification::login_required("contoso");
        assert_eq!(n.event, "login-required");
        assert!(n.body.contains("login contoso"));
        assert_eq!(n.interval, Some(LOGIN_REQUIRED_INTERVAL));
        let rolespec = crate::proto::Rolespec {
            role: "123456789012/Admin".to_owned(),
            assume_role: None,
        };
        let n = Notification::ai_agent_denied("contoso", &rolespec, "refused by policy");
        assert_eq!(n.event, "ai-agent-denied");
        assert_eq!(n.body, "123456789012/Admin on contoso: refused by policy");
        assert_eq!(n.urgency_name(), "normal");
        let n = Notification::policy_lockdown("1-2");
        assert_eq!(n.urgency_name(), "critical");
        assert_eq!(n.interval, None);
    }

    #[tokio::test]
    async fn test_run_command() {
        let dir = TempDir::new("command");
        std::fs::create_dir_all(&dir.0).unwrap();
        let out = dir.0.join("out");
        let helper = dir.0.join("helper.sh");
        std::fs::write(
            &helper,
            format!(
                "printf '%s|' \"$@\" \"$MAIRU_NOTIFY_EVENT\" > {}\n",
                out.display()
            ),
        )
        .unwrap();
        let env = [("MAIRU_NOTIFY_EVENT", "login-required")];
        assert!(
            run_shell(
                &format!("sh {}", helper.display()),
                &["title", "body with space"],
                &env
            )
            .await
        );
        assert_eq!(
            std::fs::read_to_string(&out).unwrap(),
            "title|body with space|login-required|"
        );
        let argv = ["sh".to_owned(), helper.display().to_string()];
        assert!(run_argv(&argv, &["https://example.com/"], &env).await);
        assert_eq!(
            std::fs::read_to_string(&out).unwrap(),
            "https://example.com/|login-required|"
        );
        assert!(!run_argv(&["false".to_owned()], &[], &[]).await);
        assert!(!run_argv(&["/nonexistent/mairu-test".to_owned()], &[], &[]).await);
        assert!(!run_argv(&[], &[], &[]).await);
    }
}
