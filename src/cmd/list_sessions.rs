#[tokio::main]
pub async fn run() -> Result<(), anyhow::Error> {
    let mut agent = crate::cmd::agent::connect_or_start().await?;
    let list = agent
        .list_sessions(tonic::Request::new(crate::proto::ListSessionsRequest {}))
        .await?
        .into_inner();

    for session in list.sessions.iter() {
        let expiring = match session.expiration() {
            Ok(Some(e)) => {
                if session.refreshable {
                    format!(" [renews after {e}]")
                } else {
                    format!(" [until {e}]")
                }
            }
            Ok(None) => {
                if session.refreshable {
                    "[refreshable]".to_string()
                } else {
                    "".to_string()
                }
            }
            Err(e) => {
                tracing::warn!(err = ?e, session = ?session, "Invalid expiration timestamp");
                "".to_string()
            }
        };
        println!(
            "{}. {}: {}{}",
            session.id, session.server_id, session.server_url, expiring
        );
    }

    Ok(())
}
