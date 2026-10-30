#[derive(clap::Args)]
pub struct LockArgs {
    /// Drop the approvals of this terminal session only
    #[arg(long)]
    session: bool,

    /// Also drop the approvals of running `mairu exec`, which then ask again on their next refresh
    #[arg(long)]
    running: bool,
}

#[tokio::main]
pub async fn run(args: &LockArgs) -> Result<(), anyhow::Error> {
    let mut agent = match crate::agent::connect_to_agent().await {
        Ok(agent) => agent,
        Err(e) => {
            tracing::debug!(err = ?e, "No agent to lock");
            println!("No agent is running; nothing is remembered.");
            return Ok(());
        }
    };
    let scope = if args.session {
        crate::proto::revoke_authorizations_request::Scope::CallerSession
    } else {
        crate::proto::revoke_authorizations_request::Scope::All
    };
    let resp = agent
        .revoke_authorizations(crate::proto::RevokeAuthorizationsRequest {
            scope: scope.into(),
            include_leases: args.running,
        })
        .await?
        .into_inner();
    println!(
        "Revoked {} grant(s) and {} lease(s).",
        resp.revoked_grants, resp.revoked_leases
    );
    Ok(())
}
