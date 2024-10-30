#[derive(clap::Args, Debug)]
pub struct SetupSsoArgs {
    /// Credential server ID to use. Also be used for configuration file name.
    /// ($XDG_CONFIG_HOME/servers.d/${server_id}.json)
    server_id: String,
    /// AWS region name of your AWS SSO instance.
    #[arg(short, long)]
    region: String,
    /// Start URL of your AWS SSO instance; e.g. https://{something}.awsapps.com/start
    #[arg(short = 'u', long)]
    start_url: url::Url,

    /// Customize scope for OAuth 2.0 authorization.
    #[arg(short, long, default_values_t  = vec!["sso:account:access".to_owned()])]
    scope: Vec<String>,

    /// Proceed and override even if the configuration file with the same SERVER_ID already exists.
    #[arg(short = 'y', long, default_value_t = false)]
    overwrite: bool,
}

#[tokio::main]
pub async fn run(args: &SetupSsoArgs) -> Result<(), anyhow::Error> {
    let mut agent = crate::cmd::agent::connect_or_start().await?;

    if !args.overwrite {
        let server_resp = agent
            .get_server(tonic::Request::new(crate::proto::GetServerRequest {
                query: args.server_id.clone(),
                no_cache: true,
            }))
            .await;
        match server_resp {
            Err(s) if s.code() == tonic::Code::NotFound => {
                // expected
            }
            Err(e) => {
                return Err(e.into());
            }
            Ok(_) => {
                anyhow::bail!("Server configuration already exist with save id, confirm overwrite using --overwrite (-y)");
            }
        }
    }

    let id = args.server_id.clone();
    let server = crate::config::Server {
        config_path: crate::config::config_dir()
            .join("servers.d")
            .join(format!("{id}.json")),
        id: Some(id.clone()),
        url: args.start_url.clone(),
        oauth: None,
        aws_sso: Some(crate::config::ServerAwsSso {
            region: args.region.clone(),
            scope: args.scope.clone(),
        }),
    };

    tokio::fs::create_dir_all(server.config_path.parent().unwrap()).await?;
    {
        use tokio::io::AsyncWriteExt;
        let data = serde_json::to_string_pretty(&server)?;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&server.config_path)
            .await?;
        file.write_all(data.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
    }

    agent
        .refresh_aws_sso_client_registration(crate::proto::RefreshAwsSsoClientRegistrationRequest {
            server_id: id.clone(),
        })
        .await?;
    Ok(())
}
