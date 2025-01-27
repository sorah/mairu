#[derive(clap::Args)]
pub struct ListRolesArgs {
    /// List only roles from specified credential server (ID or URL)
    #[arg(long)]
    server: Option<String>,

    #[arg(long, short = 'j', default_value_t = false)]
    json: bool,
}

#[tokio::main]
pub async fn run(args: &ListRolesArgs) -> Result<(), anyhow::Error> {
    use tokio::io::AsyncWriteExt;

    let mut agent = crate::cmd::agent::connect_or_start().await?;
    let list = agent
        .list_roles(tonic::Request::new(crate::proto::ListRolesRequest {
            server_id: args.server.clone().unwrap_or_default(),
        }))
        .await?
        .into_inner();

    let json = serde_json::to_string_pretty(&list)?;
    let mut stdout = tokio::io::stdout();
    stdout.write_all(json.as_bytes()).await.unwrap();
    stdout.write_all(b"\n").await.unwrap();
    stdout.flush().await.unwrap();

    Ok(())
}
