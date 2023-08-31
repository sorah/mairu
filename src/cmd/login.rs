#[derive(clap::Args)]
pub struct LoginArgs {
    #[arg(long)]
    oauth_grant_type: Option<crate::config::OAuthGrantType>,

    server_name: String,
}

#[tokio::main]
pub async fn run(args: &LoginArgs) -> Result<(), anyhow::Error> {
    let mut agent = crate::cmd::agent::connect_or_start().await?;

    let server: crate::config::Server = agent
        .get_server(tonic::Request::new(crate::proto::GetServerRequest {
            query: args.server_name.clone(),
            no_cache: true,
        }))
        .await?
        .into_inner()
        .try_into()?;
    server.validate()?;

    let oauth = server.oauth.as_ref().unwrap();
    let oauth_grant_type = args
        .oauth_grant_type
        .unwrap_or_else(|| oauth.default_grant_type());

    tracing::debug!(oauth_grant_type = ?oauth_grant_type, server = ?server, "Using OAuth");

    match oauth_grant_type {
        crate::config::OAuthGrantType::Code => do_oauth_code(agent, server).await,
    }
}

pub async fn do_oauth_code(
    mut agent: crate::agent::AgentConn,
    server: crate::config::Server,
) -> Result<(), anyhow::Error> {
    let (_oauth, code_grant) = server.try_oauth_code_grant()?;
    let (listener, url) = crate::oauth_code::bind_tcp_for_callback(code_grant.local_port).await?;

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
    eprintln!(":: {product} :: Login to {server_id} ({server_url}) ::::::::");
    eprintln!(":: {product} :: ");
    eprintln!(":: {product} :: ");
    eprintln!(":: {product} :: Open the following URL to continue");
    eprintln!(":: {product} :: {authorize_url}");
    eprintln!(":: {product} :: ");
    eprintln!(":: {product} :: ");

    crate::oauth_code::listen_for_callback(listener, session, &agent).await?;
    tracing::info!("Logged in");
    Ok(())
}
