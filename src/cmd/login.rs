#[derive(clap::Args)]
pub struct LoginArgs {
    /// Override OAuth 2 grant type to use.
    #[arg(long)]
    pub oauth_grant_type: Option<crate::config::OAuthGrantType>,

    /// Credential server ID or URL to use.
    pub server_name: String,
}

#[tokio::main]
pub async fn run(args: &LoginArgs) -> Result<(), anyhow::Error> {
    let mut agent = crate::cmd::agent::connect_or_start().await?;
    login(&mut agent, args).await
}

pub async fn login(
    agent: &mut crate::agent::AgentConn,
    args: &LoginArgs,
) -> Result<(), anyhow::Error> {
    let mut server = get_server(agent, &args.server_name).await?;
    if server.aws_sso.is_some() && server.oauth.is_none() {
        agent
            .refresh_aws_sso_client_registration(
                crate::proto::RefreshAwsSsoClientRegistrationRequest {
                    server_id: server.id().to_owned(),
                },
            )
            .await?;
        server = get_server(agent, &args.server_name).await?;
    }
    server.validate()?;

    let oauth = server.oauth.as_ref().unwrap();
    let oauth_grant_type = match args.oauth_grant_type {
        Some(x) => Ok(x),
        None => oauth.default_grant_type(),
    }?;

    tracing::debug!(oauth_grant_type = ?oauth_grant_type, server = ?server, "Using OAuth");

    match oauth_grant_type {
        crate::config::OAuthGrantType::Code => do_oauth_code(agent, server).await,
        crate::config::OAuthGrantType::DeviceCode => do_oauth_device_code(agent, server).await,
    }
}

pub async fn do_oauth_code(
    agent: &mut crate::agent::AgentConn,
    server: crate::config::Server,
) -> Result<(), anyhow::Error> {
    let (_oauth, code_grant) = server.try_oauth_code_grant()?;

    let (listener, url) =
        match crate::oauth_code::bind_tcp_for_callback(code_grant.local_port).await {
            Ok(t) => t,
            Err(e) => anyhow::bail!(
                "Failed to bind TCP server for OAuth 2.0 callback acceptance, perhaps there is concurrent mairu-exec call waitng for login, or occupied by oher process; {}",
                e
            ),
        };

    let session = agent
        .initiate_oauth_code(crate::proto::InitiateOAuthCodeRequest {
            server_id: server.id().to_owned(),
            redirect_url: url.to_string(),
        })
        .await?
        .into_inner();
    tracing::debug!(session = ?session, "Initiated OAuth 2.0 authorization code flow");

    let product = env!("CARGO_PKG_NAME");
    let server_id = server.id();
    let server_url = &server.url;
    let authorize_url = &session.authorize_url;

    crate::terminal::send(&indoc::formatdoc! {"
        :: {product} :: Login to {server_id} ({server_url}) ::::::::
        :: {product} ::
        :: {product} ::
        :: {product} :: Open the following URL to continue
        :: {product} :: {authorize_url}
        :: {product} ::
        :: {product} ::
    "})
    .await;

    crate::oauth_code::listen_for_callback(listener, session, agent).await?;
    tracing::info!("Logged in");
    Ok(())
}

pub async fn do_oauth_device_code(
    agent: &mut crate::agent::AgentConn,
    server: crate::config::Server,
) -> Result<(), anyhow::Error> {
    if server.aws_sso.is_none() {
        server.try_oauth_device_code_grant()?;
    }

    let session = agent
        .initiate_oauth_device_code(crate::proto::InitiateOAuthDeviceCodeRequest {
            server_id: server.id().to_owned(),
        })
        .await?
        .into_inner();
    tracing::debug!(session = ?session, "Initiated flow");

    let product = env!("CARGO_PKG_NAME");
    let server_id = server.id();
    let server_url = &server.url;
    let user_code = &session.user_code;
    let mut authorize_url = &session.verification_uri_complete;
    if authorize_url.is_empty() {
        authorize_url = &session.verification_uri;
    }

    crate::terminal::send(&indoc::formatdoc! {"
        :: {product} :: Login to {server_id} ({server_url}) ::::::::
        :: {product} ::
        :: {product} ::   Your Verification Code: {user_code}
        :: {product} ::      To authorize, visit: {authorize_url}
        :: {product} ::
    "})
    .await;

    let mut interval = session.interval as u64;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        let completion = agent
            .complete_oauth_device_code(crate::proto::CompleteOAuthDeviceCodeRequest {
                handle: session.handle.clone(),
            })
            .await;

        match completion {
            Ok(_) => break,
            Err(e) if e.code() == tonic::Code::ResourceExhausted => {
                interval += 5;
                tracing::debug!(interval = ?interval, "Received slow_down request");
            }
            Err(e) if e.code() == tonic::Code::FailedPrecondition => {
                // continue
            }
            Err(e) => {
                anyhow::bail!(e);
            }
        }
    }

    tracing::info!("Logged in");
    Ok(())
}

async fn get_server(
    agent: &mut crate::agent::AgentConn,
    query: &str,
) -> anyhow::Result<crate::config::Server> {
    Ok(agent
        .get_server(tonic::Request::new(crate::proto::GetServerRequest {
            query: query.to_owned(),
            no_cache: true,
        }))
        .await?
        .into_inner()
        .try_into()?)
}
