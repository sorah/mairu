#[derive(clap::Args, Debug)]
pub struct SetupSsoArgs {
    server_id: String,
    #[arg(short, long)]
    region: String,
    #[arg(short = 'u', long)]
    start_url: url::Url,
    #[arg(short, long, default_values_t  = vec!["sso:account:access".to_owned()])]
    scope: Vec<String>,

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
