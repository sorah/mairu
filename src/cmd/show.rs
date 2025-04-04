#[derive(clap::Args)]
pub struct ShowArgs {
    /// Exit as failure when .mairu.json is missing (auto role)
    #[arg(short = 'f', long, default_value_t = false)]
    fail_when_missing_auto: bool,

    /// Quiet mode
    #[arg(short = 'q', long, default_value_t = false)]
    quiet: bool,
}

#[derive(Debug, serde::Serialize)]
struct ShowOutput {
    auto: Option<crate::auto::AutoData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_source: Option<std::path::PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_trusted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_logged_in: Option<bool>,
}

#[tokio::main]
pub async fn run(args: &ShowArgs) -> Result<(), anyhow::Error> {
    use tokio::io::AsyncWriteExt;
    let agent = crate::agent::connect_to_agent().await;

    let cwd = std::env::current_dir().map_err(|e| anyhow::anyhow!("Failed to get cwd: {}", e))?;
    let auto = match crate::auto::Auto::find_for(&cwd).await {
        Ok(x) => x,
        Err(e) => {
            tracing::warn!(e=?e, "Failed to load .mairu.json");
            None
        }
    };

    let trustability = match auto.as_ref() {
        Some(a) => a.find_trust().await,
        None => None,
    };
    let auto_trusted = match (auto.as_ref(), trustability) {
        (None, _) => None,
        (Some(_), None) => Some(false),
        (Some(_), Some(crate::auto::Trustability::Diverged(_))) => Some(false),
        (Some(_), Some(crate::auto::Trustability::Matched(trust))) => Some(trust.trust),
    };

    let auto_logged_in = match auto.as_ref() {
        None => None,
        Some(auto) => {
            if let Ok(mut agent) = agent {
                let resp = agent
                    .get_server(tonic::Request::new(crate::proto::GetServerRequest {
                        query: auto.inner.server.to_owned(),
                        no_cache: false,
                        check_session: true,
                    }))
                    .await;
                if let Ok(server) = resp {
                    Some(server.into_inner().session.is_some())
                } else {
                    Some(false)
                }
            } else {
                Some(false)
            }
        }
    };

    let output = ShowOutput {
        auto: auto.as_ref().map(|x| x.inner.clone()),
        auto_source: auto.as_ref().map(|x| x.path.clone()),
        auto_trusted,
        auto_logged_in,
    };

    if !args.quiet {
        let json = serde_json::to_string_pretty(&output).unwrap();
        let mut stdout = tokio::io::stdout();
        stdout.write_all(json.as_bytes()).await.unwrap();
        stdout.write_all(b"\n").await.unwrap();
        stdout.flush().await.unwrap();
    }

    if args.fail_when_missing_auto && auto.is_none() {
        return Err(crate::Error::SilentlyExitWithCode(std::process::ExitCode::from(1)).into());
    }

    Ok(())
}
