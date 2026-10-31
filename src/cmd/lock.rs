#[derive(clap::Args)]
pub struct LockArgs {
    /// Drop the approvals of this terminal session only
    #[arg(long)]
    session: bool,

    /// Also drop the approvals of running `mairu exec`, which then ask again on their next refresh
    #[arg(long)]
    running: bool,

    /// Mark this terminal session as running a tool, such as ai-agent, until the session ends (implies --session)
    #[arg(long = "tool", value_name = "LABEL", value_parser = parse_label)]
    tools: Vec<String>,
}

#[derive(clap::Args)]
pub struct UnlockArgs {
    /// Remove this tool mark from this terminal session; asks for approval
    #[arg(long = "tool", value_name = "LABEL", value_parser = parse_label, required = true)]
    tools: Vec<String>,
}

pub fn parse_label(s: &str) -> Result<String, String> {
    if crate::tool_detection::ToolLabel::is_valid_name(s) {
        Ok(s.to_owned())
    } else {
        Err("use lowercase letters, digits and '-'".to_owned())
    }
}

fn has_terminal() -> bool {
    std::fs::File::open("/dev/tty").is_ok()
}

#[tokio::main]
pub async fn run(args: &LockArgs) -> Result<(), anyhow::Error> {
    if !args.tools.is_empty() && !has_terminal() {
        anyhow::bail!(crate::authorization::NO_TERMINAL_SESSION);
    }
    let mut agent = match crate::agent::connect_to_agent().await {
        Ok(agent) => agent,
        Err(e) if args.tools.is_empty() => {
            tracing::debug!(err = ?e, "No agent to lock");
            println!("No agent is running; nothing is remembered.");
            return Ok(());
        }
        Err(_) => crate::cmd::agent::connect_or_start().await?,
    };
    let scope = if args.session || !args.tools.is_empty() {
        crate::proto::revoke_authorizations_request::Scope::CallerSession
    } else {
        crate::proto::revoke_authorizations_request::Scope::All
    };
    let resp = agent
        .revoke_authorizations(crate::proto::RevokeAuthorizationsRequest {
            scope: scope.into(),
            include_leases: args.running,
            mark_tools: args.tools.clone(),
        })
        .await?
        .into_inner();
    println!(
        "Revoked {} grant(s) and {} lease(s).",
        resp.revoked_grants, resp.revoked_leases
    );
    if !args.tools.is_empty() {
        let product = env!("CARGO_PKG_NAME");
        let tty = crate::cmd::authorization::terminal_path()
            .map_or_else(String::new, |t| format!(" ({t})"));
        println!(
            ":: {product} :: Marked this terminal session{tty} as: {}",
            args.tools.join(", ")
        );
    }
    Ok(())
}

#[tokio::main]
pub async fn run_unlock(args: &UnlockArgs) -> Result<(), anyhow::Error> {
    if !has_terminal() {
        anyhow::bail!(crate::authorization::NO_TERMINAL_SESSION);
    }
    let agent = match crate::agent::connect_to_agent().await {
        Ok(agent) => agent,
        Err(e) => {
            tracing::debug!(err = ?e, "No agent to unlock");
            println!("No agent is running; nothing is marked.");
            return Ok(());
        }
    };
    let product = env!("CARGO_PKG_NAME");
    let tty =
        crate::cmd::authorization::terminal_path().unwrap_or_else(|| "this terminal".to_owned());
    let labels = args.tools.join(", ");
    crate::terminal::send(&format!(
        ":: {product} :: Removing the tool marks of {tty} ({labels}) needs approval.\n"
    ))
    .await;
    let req = crate::proto::UnmarkToolsRequest {
        tools: args.tools.clone(),
        client_context: Some(crate::proto::ClientContext {
            cwd: crate::cmd::authorization::cwd(),
            env_names: crate::tool_detection::env_names(),
            ..Default::default()
        }),
    };
    let notice = |_: &crate::proto::AuthorizationError| {
        format!(
            ":: {product} :: Approve removing the tool marks of {tty} ({labels}).\n:: {product} :: Enter your password below.\n"
        )
    };
    let relay = crate::ssh_agent_presence::Relay::from_env();
    let signature_notice =
        |_: &crate::proto::AuthorizationError, signer: crate::ssh_agent_presence::Signer<'_>| {
            format!(
                ":: {product} :: {} to remove the tool marks of {tty} ({labels})\n",
                signer.instruction()
            )
        };
    let resp = crate::polkit_tty_agent::with_fallback(notice, |_| {
        let agent = agent.clone();
        let req = req.clone();
        let relay = relay.clone();
        async move {
            relay
                .with_challenges(signature_notice, |response| {
                    let mut agent = agent.clone();
                    let mut req = req.clone();
                    crate::ssh_agent_presence::set_response(&mut req.client_context, response);
                    async move { agent.unmark_tools(req).await }
                })
                .await
        }
    })
    .await;
    let remaining = match resp {
        Ok(r) => r.into_inner().remaining,
        Err(status) => match crate::cmd::authorization::refusal_message(&status) {
            Some(message) => anyhow::bail!("{message}"),
            None => return Err(status.into()),
        },
    };
    if remaining.is_empty() {
        println!(":: {product} :: This terminal session is no longer marked.");
    } else {
        println!(
            ":: {product} :: This terminal session is still marked as: {}",
            remaining.join(", ")
        );
    }
    Ok(())
}
