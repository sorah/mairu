#[derive(clap::Args)]
pub struct ListSessionsArgs {
    /// Show time in UTC instead of local time
    #[arg(long, default_value_t = false)]
    pub utc: bool,
}

#[tokio::main]
pub async fn run(args: &ListSessionsArgs) -> Result<(), anyhow::Error> {
    let mut agent = crate::cmd::agent::connect_or_start().await?;
    let list = agent
        .list_sessions(tonic::Request::new(crate::proto::ListSessionsRequest {}))
        .await?
        .into_inner();

    for session in list.sessions.iter() {
        let expiring = match session.expiration() {
            Ok(Some(e)) => {
                let t = format_time(e, args.utc);
                if session.refreshable {
                    format!(" [renews after {t}]")
                } else {
                    format!(" [until {t}]")
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

fn format_time(t: chrono::DateTime<chrono::Utc>, utc: bool) -> String {
    if utc {
        t.to_rfc3339_opts(chrono::SecondsFormat::Secs, false)
    } else {
        chrono::DateTime::<chrono::Local>::from(t)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, false)
    }
}
