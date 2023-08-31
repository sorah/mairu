#[tokio::main]
pub async fn run() -> Result<(), anyhow::Error> {
    let mut agent = crate::cmd::agent::connect_or_start().await?;
    let list = agent
        .list_sessions(tonic::Request::new(crate::proto::ListSessionsRequest {}))
        .await?
        .into_inner();

    for session in list.sessions.iter() {
        let expiring = session
            .expires_at
            .as_ref()
            .and_then(|ts| std::time::SystemTime::try_from(ts.clone()).ok())
            .map(|st| -> chrono::DateTime<chrono::Local> { chrono::DateTime::from(st) })
            .map(|t| format!(" [until {}]", t))
            .unwrap_or_else(|| "".to_owned());
        println!(
            "{}. {}: {}{}",
            session.id, session.server_id, session.server_url, expiring
        );
    }

    Ok(())
}
