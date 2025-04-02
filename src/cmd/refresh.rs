#[derive(clap::Args)]
pub struct RefreshArgs {
    /// Server id
    pub query: String,

    /// Show time in UTC instead of local time
    #[arg(long, default_value_t = false)]
    pub utc: bool,
}

#[tokio::main]
pub async fn run(args: &RefreshArgs) -> Result<(), anyhow::Error> {
    let mut agent = crate::cmd::agent::connect_or_start().await?;
    let result = agent
        .refresh_session(tonic::Request::new(crate::proto::RefreshSessionRequest {
            query: args.query.clone(),
        }))
        .await?
        .into_inner();
    let session = result.session.unwrap();
    crate::cmd::list_sessions::print_session(&session, args.utc);
    Ok(())
}
