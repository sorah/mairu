#[tokio::main]
pub async fn run() -> Result<(), anyhow::Error> {
    use tokio::io::AsyncWriteExt;

    let mut agent = match crate::agent::connect_to_agent().await {
        Ok(agent) => agent,
        Err(e) => {
            tracing::warn!(e=?e, "Failed to connect to agent");
            let mut stderr = tokio::io::stderr();
            stderr
                .write_all(
                    format!(
                        "Failed to connect to agent - it may have been stopped already. (err={e})\n",
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            return Err(crate::Error::FailureButSilentlyExit.into());
        }
    };
    agent
        .shutdown_agent(tonic::Request::new(crate::proto::ShutdownAgentRequest {}))
        .await?;
    Ok(())
}
