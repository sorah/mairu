#[tokio::main]
pub async fn run() -> Result<(), anyhow::Error> {
    let mut agent = crate::agent::connect_to_agent().await?;
    agent
        .shutdown_agent(tonic::Request::new(crate::proto::ShutdownAgentRequest {}))
        .await?;
    Ok(())
}
