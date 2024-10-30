#[derive(clap::Args, Debug, Clone)]
pub struct ExecArgs {
    role: String,

    #[arg(long)]
    server: Option<String>,

    #[arg(long, default_value_t = false)]
    no_cache: bool,

    #[arg(long, short, default_value = "ecs")]
    mode: crate::config::ProviderMode,

    #[arg(long, default_value_t = false)]
    no_login: bool,

    #[arg(long, default_value_t = false)]
    no_auto_refresh: bool,

    #[arg(long)]
    oauth_grant_type: Option<crate::config::OAuthGrantType>,

    #[arg(long, default_value_t = false)]
    no_preflight_check: bool,

    #[arg(long)]
    confirm_trust: Option<String>,

    #[arg(long, env = "MAIRU_SHOW_AUTO_ROLE", default_value_t = false)]
    show_auto: bool,

    #[arg(long)]
    forward_signals: Vec<String>,

    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<std::ffi::OsString>,
}

pub fn run(args: &ExecArgs) -> Result<(), anyhow::Error> {
    crate::config::trust_dir_mkpath()?;
    run_inner(args.clone()) // XXX: &mut
}

#[tokio::main]
async fn run_inner(mut args: ExecArgs) -> Result<(), anyhow::Error> {
    let mut agent = crate::cmd::agent::connect_or_start().await?;

    if args.role == "auto" {
        resolve_auto(&mut args).await?;
    } else if args.server.is_none() {
        anyhow::bail!("--server is required (except when role = 'auto') but not given");
    }

    let mut initial_expiry = None;
    if !args.no_preflight_check {
        let r = preflight_check(&mut agent, &args).await?;

        if !args.no_auto_refresh && !args.no_cache {
            initial_expiry = match r {
                Some(crate::proto::AssumeRoleResponse {
                    credentials: Some(ref creds),
                    ..
                }) => creds.expiration().ok().flatten(),
                _ => None,
            };
        }
    }

    let _auto_refresh_shutdown_tx =
        auto_refresh::start(agent.clone(), args.clone(), initial_expiry); // keep running
    let _provider_shutdown_tx = provider::start(&mut agent, &args).await?; // keep provider running

    execute(&args).await
}
#[tracing::instrument(skip_all)]
async fn resolve_auto(args: &mut ExecArgs) -> Result<(), anyhow::Error> {
    let cwd = std::env::current_dir()
        .map_err(|e| anyhow::anyhow!("Failed to get cwd for resolving 'auto' role: {}", e))?;
    let auto = crate::auto::Auto::find_for(&cwd)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to find and read .mairu.json for resolving 'auto' role: {}",
                e
            )
        })?
        .ok_or_else(|| anyhow::anyhow!("couldn't find .mairu.json for 'auto' role resolution"))?;

    // Check trust status
    let trustability = auto.find_trust().await;
    let trusted = match trustability {
        None => {
            tracing::debug!(cwd = %cwd.display(), auto = ?auto, "Not trusted yet");
            false
        }
        Some(crate::auto::Trustability::Diverged(trust)) => {
            tracing::debug!(cwd = %cwd.display(), auto = ?auto, trust = ?trust, "Trust is given but stale");
            false
        }
        Some(crate::auto::Trustability::Matched(trust)) => {
            tracing::trace!(cwd = %cwd.display(), auto = ?auto, trust = ?trust, "Trust is up to date");
            trust.trust
        }
    };

    if !trusted {
        ask_trust(args, &auto).await?
    }

    // Resolve
    args.server = Some(auto.inner.server.clone());
    args.role = auto.inner.role.clone();
    //TODO: if args.mode.is_none() {
    //   args.mode = auto.inner.mode
    //}

    if args.show_auto {
        crate::terminal::send(&indoc::formatdoc! {"
            :: {product} :: Using server={server:?} role={role:?}
        ", product = env!("CARGO_PKG_NAME"), server=auto.inner.server, role=auto.inner.role})
        .await;
    }

    Ok(())
}

async fn ask_trust(args: &ExecArgs, auto: &crate::auto::Auto) -> Result<(), anyhow::Error> {
    let product = env!("CARGO_PKG_NAME");

    let json = serde_json::to_string_pretty(&auto.inner)
        .unwrap()
        .lines()
        .fold(String::new(), |mut r, l| {
            use std::fmt::Write;
            let _ = writeln!(r, ":: {product} ::     {l}");
            r
        });

    crate::terminal::send(&indoc::formatdoc! {"
        :: {product} :: The following configuration is present but has to be confirmed:
        :: {product} ::
        :: {product} ::     // {path}
        {json}:: {product} ::
    ", path = auto.path.display()})
    .await;

    let hash_string = auto.digest().to_string();
    if let Some(ref given_hash) = args.confirm_trust {
        if given_hash.as_ref() == hash_string {
            tracing::debug!(auto = ?auto, "approved using --confirm-trust");
        } else {
            tracing::warn!(auto = ?auto, "--confirm-trust was given, but it does not match with the expected value");
            crate::terminal::send(&indoc::formatdoc! {"
                :: {product} :: To continue, please approve this configuration using:
                :: {product} ::     $ {product} exec --confirm-trust {hash_string} auto ...
            "})
            .await;
            return Err(crate::Error::FailureButSilentlyExit.into());
        }
    } else if prompt_trust_using_terminal().await? {
        tracing::debug!(auto = ?auto, "approved using terminal");
    } else {
        crate::terminal::send(&indoc::formatdoc! {"
            :: {product} :: To continue, please approve this configuration using:
            :: {product} ::     $ {product} exec --confirm-trust {hash_string} auto ...
        "})
        .await;
        return Err(crate::Error::FailureButSilentlyExit.into());
    }

    if let Err(e) = auto.mark_trust().await {
        tracing::warn!(auto = ?auto, err = ?e, "Failed to save trust");
    }

    Ok(())
}

async fn prompt_trust_using_terminal() -> Result<bool, anyhow::Error> {
    use tokio::io::AsyncBufReadExt;
    if !(crate::terminal::is_terminal().await) {
        return Ok(false);
    }
    let product = env!("CARGO_PKG_NAME");
    let fd = std::fs::OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .map(tokio::fs::File::from_std)?;
    let mut reader = tokio::io::BufReader::with_capacity(16, fd);
    crate::terminal::send(&format!(
        ":: {product} :: Do you trust this directory to use the following configuration (yes/no)? \0"
    ))
    .await;
    loop {
        let mut buf = String::new();
        reader.read_line(&mut buf).await?;
        match buf.trim() {
            "yes" => return Ok(true),
            "no" => anyhow::bail!("The configuration was not approved, aborting"),
            _ => {
                crate::terminal::send(&format!(":: {product} :: Please type 'yes' or 'no': \0"))
                    .await;
            }
        }
    }
}

#[tracing::instrument(skip_all)]
async fn preflight_check(
    agent: &mut crate::agent::AgentConn,
    args: &ExecArgs,
) -> Result<Option<crate::proto::AssumeRoleResponse>, anyhow::Error> {
    let req = crate::proto::AssumeRoleRequest {
        server_id: args.server.as_ref().unwrap().to_owned(),
        role: args.role.clone(),
        cached: !args.no_cache,
    };
    let mut resp = assume_role_with_long_attempt_notice(agent, req.clone()).await;

    if let Err(ref e) = resp {
        if e.code() == tonic::Code::Unauthenticated {
            login(agent, args).await?;
        }
        resp = assume_role_with_long_attempt_notice(agent, req.clone()).await;
    }

    match resp {
        Ok(r) => {
            let resp = r.into_inner();
            let aki = resp.credentials.as_ref().map(|c| c.access_key_id.clone());
            tracing::debug!(args = ?args, aws_access_key_id = ?aki, "preflight check succeeded");
            Ok(Some(resp))
        }
        Err(e) => {
            tracing::debug!(args = ?args, err = ?e, "preflight check failed");
            let product = env!("CARGO_PKG_NAME");
            let server_id = args.server.as_ref().unwrap();
            let role = &args.role;
            let code = e.code();
            let message = e.message();
            crate::terminal::send(&indoc::formatdoc! {"
                :: {product} :: ERROR, Couldn't obtain AWS credentials for {role} from {server_id} :::::::
                :: {product} :: > code={code:?}, message={message}
            "})
            .await;
            if e.code() == tonic::Code::Unauthenticated {
                crate::terminal::send(&format!(
                    ":: {product} :: > logged in but still error is unauthenticated"
                ))
                .await;
            }
            Err(crate::Error::FailureButSilentlyExit.into())
        }
    }
}

const LONG_PREFLIGHT_CHECK_DURATION: tokio::time::Duration = tokio::time::Duration::from_secs(2);

async fn assume_role_with_long_attempt_notice(
    agent: &mut crate::agent::AgentConn,
    req: crate::proto::AssumeRoleRequest,
) -> tonic::Result<tonic::Response<crate::proto::AssumeRoleResponse>> {
    let resp = agent.assume_role(req.clone());
    let sleep = tokio::time::sleep(LONG_PREFLIGHT_CHECK_DURATION);
    let mut elapsed = false;
    tokio::pin!(resp);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            retval = &mut resp => {
                return retval;
            }
            _ = &mut sleep, if !elapsed => {
                elapsed = true;
                let product = env!("CARGO_PKG_NAME");
                crate::terminal::send(&format!(":: {product} :: Waiting for AWS credentials from your remote server...")).await;
            }
        }
    }
}

#[tracing::instrument(skip_all)]
async fn login(agent: &mut crate::agent::AgentConn, args: &ExecArgs) -> Result<(), anyhow::Error> {
    if !args.no_login {
        let login_args = crate::cmd::login::LoginArgs {
            oauth_grant_type: args.oauth_grant_type,
            server_name: args.server.as_ref().unwrap().to_owned(),
        };
        crate::cmd::login::login(agent, &login_args).await
    } else {
        let product = env!("CARGO_PKG_NAME");
        let server_id = args.server.as_ref().unwrap();
        let role = &args.role;
        crate::terminal::send(&indoc::formatdoc! {"
            :: {product} :: Login required for AWS credentials from {server_id} for {role} :::::::
            :: {product} :: > Use the following command to continue
            :: {product} ::   $ {product} login {server_id}
        "})
        .await;
        Err(crate::Error::FailureButSilentlyExit.into())
    }
}

mod provider {
    use super::*;

    pub(super) struct ProviderHandle {
        pub(super) shutdown: tokio::sync::oneshot::Sender<()>,
        pub(super) environment: crate::proto::ExecEnvironment,
    }

    pub(super) async fn start(
        agent: &mut crate::agent::AgentConn,
        args: &ExecArgs,
    ) -> Result<ProviderHandle, anyhow::Error> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let environment = match args.mode {
            crate::config::ProviderMode::Ecs => ecs_provider_start(rx, agent, args).await?,
            crate::config::ProviderMode::Static => static_provider_set(agent, args).await?,
        };
        environment.apply();
        Ok(ProviderHandle {
            shutdown: tx,
            environment,
        })
    }

    #[tracing::instrument(skip_all)]
    async fn ecs_provider_start(
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
        agent: &mut crate::agent::AgentConn,
        args: &ExecArgs,
    ) -> Result<crate::proto::ExecEnvironment, anyhow::Error> {
        let (listener, url) = crate::ecs_server::bind_tcp(None).await?;
        let server = crate::ecs_server::EcsServer::new_with_agent(
            agent.clone(),
            crate::proto::AssumeRoleRequest {
                server_id: args.server.as_ref().unwrap().to_owned(),
                role: args.role.clone(),
                cached: !args.no_cache,
            },
            ExecEcsUserFeedback::from(args),
        );
        let environment = {
            use crate::proto::ExecEnvironmentAction;
            use secrecy::ExposeSecret;
            let vars = [
                ExecEnvironmentAction::Set("AWS_CONTAINER_CREDENTIALS_FULL_URI", url.to_string()),
                ExecEnvironmentAction::Set(
                    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
                    format!("Bearer {}", &server.bearer_token().expose_secret()),
                ),
            ];
            crate::proto::ExecEnvironment::from_iter(vars.into_iter())
        };
        tokio::spawn(async move {
            axum::serve(listener, server.router())
                .with_graceful_shutdown(async {
                    shutdown_rx.await.ok();
                    tracing::trace!("ECS Server shutting down");
                })
                .await
                .ok();
            tracing::debug!("ECS Server down");
        });
        Ok(environment)
    }

    #[derive(Debug, Clone)]
    struct ExecEcsUserFeedback {
        role: String,
        server: String,
    }

    impl From<&ExecArgs> for ExecEcsUserFeedback {
        fn from(a: &ExecArgs) -> Self {
            Self {
                role: a.role.clone(),
                server: a.server.as_ref().unwrap().to_owned(),
            }
        }
    }

    impl crate::ecs_server::UserFeedbackDelegate for ExecEcsUserFeedback {
        async fn on_error(&self, err: &crate::ecs_server::BackendRequestError) {
            let product = env!("CARGO_PKG_NAME");
            let server = &self.server;
            let role = &self.role;
            let e = err.ui_message();
            crate::terminal::send(&(match &err {
            crate::ecs_server::BackendRequestError::Forbidden(_) => {
                indoc::formatdoc! {"
                    :: {product} :: Forbidden while retrieving AWS credentials of {role} from {server}; {e}. To login again, run: $ {product} login {server}
                "}
            }
            crate::ecs_server::BackendRequestError::Unauthorized(_) => {
                indoc::formatdoc! {"
                    :: {product} :: Login required to {server} for AWS credentials of {role}; {e}. Run: $ {product} login {server}
                    :: {product} :: To continue, run: $ {product} login {server}
                "}
            }
            crate::ecs_server::BackendRequestError::Unknown(_) => {
                indoc::formatdoc! {"
                    :: {product} :: Unknown error occured when retrieving AWS credentials for {role} from {server}; {e}. To reauthenticate, run: $ {product} login {server}
                "}
            }
        })).await;
        }
    }

    #[tracing::instrument(skip_all)]
    async fn static_provider_set(
        agent: &mut crate::agent::AgentConn,
        args: &ExecArgs,
    ) -> Result<crate::proto::ExecEnvironment, anyhow::Error> {
        let resp = agent
            .assume_role(crate::proto::AssumeRoleRequest {
                server_id: args.server.as_ref().unwrap().to_owned(),
                role: args.role.clone(),
                cached: !args.no_cache,
            })
            .await?
            .into_inner();
        let creds = resp
            .credentials
            .ok_or_else(|| anyhow::anyhow!("agent sent empty credentials"))?;

        let environment = {
            use crate::proto::ExecEnvironmentAction;
            let vars = [
                ExecEnvironmentAction::Set("AWS_ACCESS_KEY_ID", creds.access_key_id.clone()),
                ExecEnvironmentAction::Set(
                    "AWS_SECRET_ACCESS_KEY",
                    creds.secret_access_key.clone(),
                ),
                if !creds.session_token.is_empty() {
                    ExecEnvironmentAction::Set("AWS_SESSION_TOKEN", creds.session_token.clone())
                } else {
                    ExecEnvironmentAction::Remove("AWS_SESSION_TOKEN")
                },
            ];
            crate::proto::ExecEnvironment::from_iter(vars.into_iter())
        };
        Ok(environment)
    }
}

mod auto_refresh {
    use super::*;

    pub(super) fn start(
        agent: crate::agent::AgentConn,
        args: ExecArgs,
        initial_expiry: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Option<tokio::sync::oneshot::Sender<()>> {
        match initial_expiry {
            None => None,
            Some(id) => {
                let (tx, rx) = tokio::sync::oneshot::channel();
                tokio::spawn(auto_refresh(rx, agent, args, id));
                Some(tx)
            }
        }
    }

    // XXX: align with credential_cache RENEW_CREDENTIALS_BEFORE_SEC
    static AUTO_REFRESH_BEFORE: chrono::TimeDelta = chrono::TimeDelta::seconds(897);

    #[tracing::instrument(skip_all)]
    async fn auto_refresh(
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
        mut agent: crate::agent::AgentConn,
        args: ExecArgs,
        initial_expiry: chrono::DateTime<chrono::Utc>,
    ) {
        let mut expiry = initial_expiry;
        //let mut expiry = chrono::Utc::now() + chrono::TimeDelta::seconds(60);
        loop {
            let mut retries: u32 = 0;
            let Some(deadline) = calculate_deadline_in_duration(&expiry) else {
                return;
            };
            tracing::debug!(retries = ?retries, expiry = %expiry, wait = ?deadline, "auto_refresh waiting");
            let sleep = tokio::time::sleep(deadline);
            tokio::pin!(sleep);
            tokio::select! {
                _ = &mut shutdown_rx => {
                    tracing::debug!("auto_refresh shutting down");
                    return;
                },
                _ = &mut sleep => {},
            }
            tracing::debug!(retries = ?retries, expiry = %expiry, "auto_refresh performing refresh");
            loop {
                match perform(&mut agent, &args).await {
                    Ok(Some(next_expiry)) => {
                        if expiry != next_expiry {
                            expiry = next_expiry;
                            tracing::info!(retries = ?retries, next_expiry = %next_expiry, "auto_refresh refreshed credential cache in agent");
                            break;
                        } else {
                            tracing::info!(retries = ?retries, expiry = %expiry, "auto_refresh attempted to refresh credential cache but still stale");
                            retries += 1;
                        }
                    }
                    Ok(None) => {
                        tracing::warn!(
                            "auto_refresh shutting down due to missing expiration after renewal"
                        );
                        return;
                    }
                    Err(_) => {
                        retries += 1;
                    }
                }

                // retry needed
                let wait = calculate_retry_wait(retries);
                tracing::info!(wait = ?wait, "auto_refresh retrying after {wait:?}");
                let retry_sleep = tokio::time::sleep(wait);
                tokio::pin!(retry_sleep);
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        tracing::debug!("auto_refresh shutting down");
                        return;
                    },
                    _ = &mut retry_sleep => {},
                }
            }
        }
    }

    fn calculate_deadline_in_duration(
        expiry: &chrono::DateTime<chrono::Utc>,
    ) -> Option<tokio::time::Duration> {
        let thres = *expiry - AUTO_REFRESH_BEFORE;
        let delta = thres.signed_duration_since(chrono::Utc::now());
        match delta.to_std() {
            Ok(std) => Some(std),
            Err(_) => Some(tokio::time::Duration::from_secs(1)), // when delta is negative value
        }
    }

    fn calculate_retry_wait(retries: u32) -> tokio::time::Duration {
        use rand::Rng;
        let initial_backoff = 1.0f64;
        let max_backoff = tokio::time::Duration::from_secs(120);
        let base: f64 = rand::thread_rng().gen();

        let wait = match 2u32
            .checked_pow(retries)
            .map(|s| (s as f64) * initial_backoff)
        {
            Some(r) => match tokio::time::Duration::try_from_secs_f64(r) {
                Ok(d) => d.min(max_backoff),
                Err(e) => {
                    tracing::warn!(err = ?e, "auto_refresh failed to calculate backoff");
                    max_backoff
                }
            },
            None => max_backoff,
        };
        // apply jitter
        wait.mul_f64(base)
    }

    async fn perform(
        agent: &mut crate::agent::AgentConn,
        args: &ExecArgs,
    ) -> crate::Result<Option<chrono::DateTime<chrono::Utc>>> {
        let req = crate::proto::AssumeRoleRequest {
            server_id: args.server.as_ref().unwrap().to_owned(),
            role: args.role.clone(),
            cached: true,
        };
        let resp = match agent.assume_role(req.clone()).await {
            Ok(r) => r.into_inner(),
            Err(e) => {
                // When remote access_token is expired, it would lead auto_refresh process backoff
                // to max_backoff (120s). At this moment, taking the process opportunistic - let
                // the process resume in max_backoff (at latest) after mairu agent gains a
                // fresh access_token.
                if e.code() != tonic::Code::Unauthenticated {
                    tracing::warn!(req = ?req, err = ?e, "auto_refresh failing");
                }
                return Err(e.into());
            }
        };
        let next_expiry = resp.credentials.and_then(|c| c.expiration().ok().flatten());
        Ok(next_expiry)
    }
}

#[tracing::instrument(skip_all)]
async fn execute(args: &ExecArgs) -> Result<(), anyhow::Error> {
    use tokio_stream::StreamExt;
    let arg0 = args
        .command
        .first()
        .ok_or_else(|| anyhow::anyhow!("command cannot be empty"))?;
    let mut child = tokio::process::Command::new(arg0)
        .args(&args.command[1..])
        .spawn()?;
    let pid = child.id();

    start_ignoring_signals();
    let forwarded_signals = execute_listen_for_forwarded_signals(&args.forward_signals);
    let waitpid = child.wait();

    tokio::pin!(waitpid);
    tokio::pin!(forwarded_signals);
    loop {
        tokio::select! {
            maybe_status = &mut waitpid => {
                let status = maybe_status.unwrap();
                return match status.code() {
                    Some(0) => Ok(()),
                    Some(code) => {
                        let returning_code = std::process::ExitCode::from(code as u8);
                        Err(crate::Error::SilentlyExitWithCode(returning_code).into())
                    }
                    None => handle_exit_status_signaled(status),
                }
            }
            signal =  forwarded_signals.next() => {
                tracing::debug!(signal = ?signal, pid = ?pid, "Forwarding signal");
                #[cfg(unix)]
                if let Some(pid_u32) = pid {
                    if let Err(e) = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid_u32 as i32), signal) {
                        tracing::warn!(signal = ?signal, pid = ?pid, err = ?e, "Failed to forward signal; kill(2) returned error");
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
fn execute_listen_for_forwarded_signals(
    signal_names: &Vec<String>,
) -> impl futures_core::stream::Stream<Item = nix::sys::signal::Signal> {
    use std::str::FromStr;
    use tokio_stream::StreamExt;

    let streams = signal_names
        .iter()
        .filter_map(
            |name| match nix::sys::signal::Signal::from_str(name.as_str()) {
                Ok(sig) => Some(sig),
                Err(e) => {
                    tracing::warn!(err = ?e, signal_name = ?name, "Unknown signal to forward: {name}");
                    None
                }
            },
        )
        .filter_map(|sig| {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::from_raw(
                sig as std::os::raw::c_int,
            )) {
                Ok(l) => Some((sig, tokio_stream::wrappers::SignalStream::new(l))),
                Err(e) => {
                    tracing::warn!(err = ?e, signal = ?sig, "Failed to listen for forwarded signal");
                    None
                }
            }
        });
    let mut map = tokio_stream::StreamMap::from_iter(streams);

    async_stream::stream! {
        while let Some((sig, _)) = map.next().await {
            yield sig;
        }
    }
}

#[cfg(unix)]
fn handle_exit_status_signaled(status: std::process::ExitStatus) -> Result<(), anyhow::Error> {
    use std::os::unix::process::ExitStatusExt;
    if let Some(sig) = status.signal() {
        let code = std::process::ExitCode::from(128 + (sig as u8));
        return Err(crate::Error::SilentlyExitWithCode(code).into());
    }
    Err(crate::Error::FailureButSilentlyExit.into())
}

#[cfg(unix)]
fn start_ignoring_signals() {
    use nix::sys::signal::{signal, SigHandler, Signal};
    if let Err(e) = unsafe { signal(Signal::SIGINT, SigHandler::SigIgn) } {
        tracing::warn!(err = ?e, "failed to ignore SIGINT")
    }
    if let Err(e) = unsafe { signal(Signal::SIGQUIT, SigHandler::SigIgn) } {
        tracing::warn!(err = ?e, "failed to ignore SIGQUIT")
    }
    if let Err(e) = unsafe { signal(Signal::SIGTSTP, SigHandler::SigIgn) } {
        tracing::warn!(err = ?e, "failed to ignore SIGTSTP")
    }
}
