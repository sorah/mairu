#[derive(clap::Args)]
pub struct DoctorArgs {}

/// Uses only `PingAgent` and `GetAgentStatus`, so it works from a binary the agent does not verify.
#[tokio::main]
pub async fn run(_args: &DoctorArgs) -> Result<(), anyhow::Error> {
    let mut warnings = vec![];

    let state = crate::hardening::Hardening::state();
    let exe = process_path::get_executable_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(unknown path)".to_owned());
    println!(
        "client   {}  {exe} {} (profile {})",
        describe_state(state),
        crate::version::VERSION,
        crate::config::Profile::current()
    );
    warnings.extend(client_warnings(state));
    warnings.extend(crate::platform::process().notes());

    let path = crate::config::socket_path();
    match crate::agent::connect_to_agent_with_path(&path).await {
        Err(e) => println!("agent    not running at {} ({e})", path.display()),
        Ok(mut conn) => {
            let verification = match conn.trust() {
                crate::platform::AgentTrust::Verified => "verified",
                crate::platform::AgentTrust::Unverified => "NOT VERIFIED",
                crate::platform::AgentTrust::Unverifiable => "not checked (client not hardened)",
            };
            let status = conn
                .get_agent_status(tonic::Request::new(crate::proto::GetAgentStatusRequest {}))
                .await;
            match status {
                Ok(status) => {
                    let status = status.into_inner();
                    print_agent_status(&status, &path, verification);
                    let agent_hardened =
                        status.agent_hardening() == crate::proto::HardeningState::Hardened;
                    if agent_hardened && !status.caller.is_some_and(|c| c.verified) {
                        warnings.push("the agent is hardened and does not verify this mairu, so it refuses everything but diagnostics; use the hardened mairu".to_owned());
                    }
                }
                Err(e) if e.code() == tonic::Code::Unimplemented => println!(
                    "agent    {} (too old to report its status) {}  {verification}",
                    conn.version(),
                    path.display()
                ),
                Err(e) => println!(
                    "agent    {} {}  {verification}; GetAgentStatus failed: {}",
                    conn.version(),
                    path.display(),
                    e.message()
                ),
            }
            match conn.replacement_reason() {
                Some(crate::agent::ReplacementReason::Unverified) => warnings.push(format!(
                    "the agent at the socket path ({}) is not hardened mairu; the next mairu command replaces it",
                    describe_pid(conn.identity().pid)
                )),
                Some(crate::agent::ReplacementReason::Outdated) => warnings.push(format!(
                    "the agent ({}) is older than {}, the minimum agent version; the next mairu command replaces it",
                    describe_pid(conn.identity().pid),
                    crate::version::MINIMUM_AGENT_VERSION
                )),
                None => {}
            }
        }
    }

    for w in warnings {
        println!("warning  {w}");
    }
    Ok(())
}

fn print_agent_status(
    status: &crate::proto::GetAgentStatusResponse,
    path: &std::path::Path,
    verification: &str,
) {
    let hardening = match status.agent_hardening() {
        crate::proto::HardeningState::Unspecified => "unknown",
        crate::proto::HardeningState::Unhardened => "unhardened",
        crate::proto::HardeningState::Hardened => "hardened",
        crate::proto::HardeningState::Misconfigured => "misconfigured",
    };
    println!(
        "agent    {hardening}  {} (profile {}) {}  {verification}",
        status.version,
        status.profile,
        path.display()
    );
    match &status.caller {
        Some(c) => println!(
            "caller   {}  pid {} start_time {}",
            if c.verified { "verified" } else { "unverified" },
            c.pid,
            c.start_time
        ),
        None => println!("caller   unknown"),
    }
    if let Some(caps) = &status.capabilities {
        let verification = caps.peer_verification().as_str_name();
        println!(
            "capabilities  peer_verification={}",
            verification
                .strip_prefix("PEER_VERIFICATION_")
                .unwrap_or(verification)
        );
        for note in &caps.notes {
            println!("  note: {note}");
        }
    }
}

fn describe_state(state: &crate::hardening::HardeningState) -> &'static str {
    match state {
        crate::hardening::HardeningState::Unhardened { .. } => "unhardened",
        crate::hardening::HardeningState::Hardened { .. } => "hardened",
        crate::hardening::HardeningState::Misconfigured { .. } => "misconfigured",
    }
}

fn describe_pid(pid: Option<u32>) -> String {
    pid.map(|p| format!("pid {p}"))
        .unwrap_or_else(|| "unknown pid".to_owned())
}

fn client_warnings(state: &crate::hardening::HardeningState) -> Vec<String> {
    let mut warnings = vec![];
    match state {
        crate::hardening::HardeningState::Misconfigured { reason } => {
            warnings.push(format!("{reason}; this mairu runs unhardened"));
            if *reason == crate::hardening::MisconfiguredReason::PrimaryGroupIsMarker {
                warnings.push(format!(
                    "a hardened agent rejects a process whose real gid is the `{}` group",
                    crate::hardening::MARKER_GROUP_NAME
                ));
            }
        }
        crate::hardening::HardeningState::Unhardened {
            setgid_other_group: Some(gid),
        } => warnings.push(format!(
            "this binary is setgid to group {gid}, not to a dedicated `{}` group",
            crate::hardening::MARKER_GROUP_NAME
        )),
        _ => {}
    }
    #[cfg(target_os = "linux")]
    if crate::hardening::read_sysctl("/proc/sys/fs/protected_hardlinks") != Some(1) {
        warnings.push("fs.protected_hardlinks is not 1; hardlinked copies of old hardened binaries keep working after an upgrade".to_owned());
    }
    warnings
}
