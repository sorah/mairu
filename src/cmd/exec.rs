#[derive(clap::Args, Debug)]
pub struct ExecArgs {
    role: String,

    #[arg(long)]
    server: String,

    #[arg(long, default_value_t = false)]
    no_cache: bool,

    #[arg(long, short, default_value = "ecs")]
    mode: crate::config::ProviderMode,

    #[arg(long, default_value_t = false)]
    no_login: bool,

    #[arg(long)]
    oauth_grant_type: Option<crate::config::OAuthGrantType>,

    #[arg(long, default_value_t = false)]
    no_preflight_check: bool,

    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<std::ffi::OsString>,
}

#[tokio::main]
pub async fn run(args: &ExecArgs) -> Result<(), anyhow::Error> {
    let mut agent = crate::cmd::agent::connect_or_start().await?;
    preflight_check(&mut agent, args).await?;
    let _provider_shutdown_tx = start_provider(&mut agent, args).await?; // keep provider running
    execute(args).await
}

#[tracing::instrument(skip_all)]
async fn preflight_check(
    agent: &mut crate::agent::AgentConn,
    args: &ExecArgs,
) -> Result<(), anyhow::Error> {
    if args.no_preflight_check {
        return Ok(());
    }

    let resp = agent
        .assume_role(crate::proto::AssumeRoleRequest {
            server_id: args.server.clone(),
            role: args.role.clone(),
            cached: !args.no_cache,
        })
        .await;

    match resp {
        Ok(r) => {
            let aki = r.into_inner().credentials.map(|c| c.access_key_id.clone());
            tracing::debug!(args = ?args, aws_access_key_id = ?aki, "preflight check succeeded");
            Ok(())
        }
        Err(e) => {
            tracing::debug!(args = ?args, err = ?e, "preflight check failed");
            if e.code() == tonic::Code::Unauthenticated {
                login(agent, args).await
            } else {
                let product = env!("CARGO_PKG_NAME");
                let server_id = &args.server;
                let role = &args.role;
                let code = e.code();
                let message = e.message();
                eprintln!(":: {product} :: ERROR, Couldn't obtain AWS credentials for {role} from {server_id} :::::::");
                eprintln!(":: {product} :: > code={code:?}, message={message}");
                Err(crate::Error::FailureButSilentlyExit.into())
            }
        }
    }
}

#[tracing::instrument(skip_all)]
async fn login(agent: &mut crate::agent::AgentConn, args: &ExecArgs) -> Result<(), anyhow::Error> {
    if !args.no_login {
        let login_args = crate::cmd::login::LoginArgs {
            oauth_grant_type: args.oauth_grant_type,
            server_name: args.server.clone(),
        };
        crate::cmd::login::login(agent, &login_args).await
    } else {
        let product = env!("CARGO_PKG_NAME");
        let server_id = &args.server;
        let role = &args.role;
        eprintln!(":: {product} :: Login required for AWS credentials from {server_id} for {role} :::::::");
        eprintln!(":: {product} :: > Use the following command to continue");
        eprintln!(":: {product} ::   $ {product} login {server_id}");
        Err(crate::Error::FailureButSilentlyExit.into())
    }
}

async fn start_provider(
    agent: &mut crate::agent::AgentConn,
    args: &ExecArgs,
) -> Result<tokio::sync::oneshot::Sender<()>, anyhow::Error> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    match args.mode {
        crate::config::ProviderMode::Ecs => {
            ecs_provider_start(rx, agent, args).await?;
            Ok(tx)
        }
        crate::config::ProviderMode::Static => {
            static_provider_set(agent, args).await?;
            Ok(tx)
        }
    }
}

#[tracing::instrument(skip_all)]
async fn ecs_provider_start(
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    agent: &mut crate::agent::AgentConn,
    args: &ExecArgs,
) -> Result<(), anyhow::Error> {
    let (listener, url) = crate::ecs_server::bind_tcp(None).await?;
    let axum_server = axum::Server::from_tcp(listener.into_std()?)?;
    let server = crate::ecs_server::EcsServer::new_with_agent(
        agent.clone(),
        crate::proto::AssumeRoleRequest {
            server_id: args.server.clone(),
            role: args.role.clone(),
            cached: !args.no_cache,
        },
        crate::ecs_server::NoUserFeedback,
    );
    {
        use secrecy::ExposeSecret;
        std::env::set_var("AWS_CONTAINER_CREDENTIALS_FULL_URI", url.to_string());
        std::env::set_var(
            "AWS_CONTAINER_AUTHORIZATION_TOKEN",
            zeroize::Zeroizing::new(format!("Bearer {}", &server.bearer_token().expose_secret())),
        );
    }
    tokio::spawn(async move {
        axum_server
            .serve(server.router().into_make_service())
            .with_graceful_shutdown(async {
                shutdown_rx.await.ok();
                tracing::trace!("ECS Server shutting down");
            })
            .await
            .ok();
        tracing::debug!("ECS Server down");
    });
    Ok(())
}

#[tracing::instrument(skip_all)]
async fn static_provider_set(
    agent: &mut crate::agent::AgentConn,
    args: &ExecArgs,
) -> Result<(), anyhow::Error> {
    let resp = agent
        .assume_role(crate::proto::AssumeRoleRequest {
            server_id: args.server.clone(),
            role: args.role.clone(),
            cached: !args.no_cache,
        })
        .await?
        .into_inner();
    let creds = resp
        .credentials
        .ok_or_else(|| anyhow::anyhow!("agent sent empty credentials"))?;

    {
        std::env::set_var("AWS_ACCESS_KEY_ID", &creds.access_key_id);
        std::env::set_var("AWS_SECRET_ACCESS_KEY", &creds.secret_access_key);
        if !creds.session_token.is_empty() {
            std::env::set_var("AWS_SESSION_TOKEN", &creds.session_token);
        } else {
            std::env::remove_var("AWS_SESSION_TOKEN");
        }
    }
    Ok(())
}

#[tracing::instrument(skip_all)]
async fn execute(args: &ExecArgs) -> Result<(), anyhow::Error> {
    let arg0 = args
        .command
        .get(0)
        .ok_or_else(|| anyhow::anyhow!("command cannot be empty"))?;
    let status = tokio::process::Command::new(arg0)
        .args(&args.command[1..])
        .status()
        .await?;

    match status.code() {
        Some(0) => Ok(()),
        Some(code) => {
            let returning_code = std::process::ExitCode::from(code as u8);
            Err(crate::Error::SilentlyExitWithCode(returning_code).into())
        }
        None => handle_exit_status_signaled(status),
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
