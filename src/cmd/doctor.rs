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
    #[cfg(target_os = "linux")]
    {
        warnings.extend(install::report());
        warnings.extend(root_reachability_warnings());
    }

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

/// Groups whose members can become root without a password.
#[cfg(target_os = "linux")]
const ROOT_EQUIVALENT_GROUPS: &[&str] = &["docker", "lxd", "incus-admin", "disk"];

/// Every guarantee is bounded by how easily code running as this user becomes root.
#[cfg(target_os = "linux")]
fn root_reachability_warnings() -> Vec<String> {
    let mut warnings = vec![];
    let sudo = crate::hardening::command("sudo")
        .args(["-n", "true"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    if sudo.is_ok_and(|s| s.success()) {
        warnings.push("`sudo -n true` succeeds (NOPASSWD or a cached sudo timestamp), so any program running as you can become root and read the agent's memory".to_owned());
    }
    let names: Vec<String> = nix::unistd::getgroups()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|gid| nix::unistd::Group::from_gid(gid).ok().flatten())
        .map(|g| g.name)
        .collect();
    let groups = root_equivalent_groups(&names);
    if !groups.is_empty() {
        warnings.push(format!(
            "you are a member of {}, which can become root without a password",
            groups.join(", ")
        ));
    }
    warnings
}

#[cfg(target_os = "linux")]
fn root_equivalent_groups(names: &[String]) -> Vec<&'static str> {
    ROOT_EQUIVALENT_GROUPS
        .iter()
        .copied()
        .filter(|g| names.iter().any(|n| n == g))
        .collect()
}

#[cfg(target_os = "linux")]
mod install {
    const INSTALLS: &str = "/var/lib/mairu/installs";

    /// Prints the harden home and every known hardened copy; returns warnings.
    pub fn report() -> Vec<String> {
        let mut warnings = vec![];
        let home = crate::hardening::home::HardenHome::for_client();
        println!("harden home  {} ({})", home.path.display(), home.source);

        let mut copies = vec![home.binary()];
        match read_installs() {
            Ok(homes) => copies.extend(homes.into_iter().map(|h| {
                crate::hardening::home::HardenHome {
                    path: h.into(),
                    source: crate::hardening::home::HardenHomeSource::Default,
                }
                .binary()
            })),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => println!("installs     {INSTALLS} not readable ({e})"),
        }
        copies.push(crate::hardening::home::DISTRO_BINARY.into());
        let mut seen = std::collections::HashSet::new();
        copies.retain(|c| seen.insert(c.clone()));

        let marker = crate::hardening::reexec::marker_group_gid();
        for copy in copies {
            if !copy.exists() {
                continue;
            }
            let validity = match marker {
                Some(gid) => match crate::hardening::candidate::hardened_candidate(&copy, gid) {
                    Ok(_) => "hardened".to_owned(),
                    Err(e) => format!("not usable: {e}"),
                },
                None => format!(
                    "not usable: no `{}` group",
                    crate::hardening::MARKER_GROUP_NAME
                ),
            };
            let version = copy_version(&copy);
            println!(
                "copy         {} {}  {validity}",
                copy.display(),
                version.as_deref().unwrap_or("(unknown version)")
            );
            if let Some(v) = version.as_deref() {
                for (kind, minimum) in [
                    ("client", crate::version::MINIMUM_CLIENT_VERSION),
                    ("agent", crate::version::MINIMUM_AGENT_VERSION),
                ] {
                    if !crate::version::at_least(v, minimum) {
                        warnings.push(format!(
                            "{} is mairu {v}, older than the minimum {kind} version {minimum}; upgrade it, or remove it with `sudo mairu harden --uninstall --home <its harden home>`",
                            copy.display()
                        ));
                        break;
                    }
                }
            }
        }
        warnings
    }

    /// Only the marker gid can traverse /var/lib/mairu.
    fn read_installs() -> std::io::Result<Vec<String>> {
        let content = crate::hardening::with_privileged_gid(|| std::fs::read_to_string(INSTALLS))?;
        Ok(content
            .lines()
            .filter(|l| l.starts_with('/'))
            .map(ToOwned::to_owned)
            .collect())
    }

    fn copy_version(path: &std::path::Path) -> Option<String> {
        let output = crate::hardening::command(path)
            .arg("--version")
            .env("MAIRU_NO_HARDENED_REEXEC", "1")
            .env("MAIRU_NO_HARDEN_SUGGESTION", "1")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        parse_version_output(&String::from_utf8_lossy(&output.stdout))
    }

    /// `mairu 0.13.0 (abc1234)` to `0.13.0`.
    pub(super) fn parse_version_output(output: &str) -> Option<String> {
        let version = output.split_whitespace().nth(1)?;
        crate::version::at_least(version, "0.0.0").then(|| version.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn test_root_equivalent_groups() {
        let names: Vec<String> = ["alice", "wheel", "docker", "disk"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(root_equivalent_groups(&names), vec!["docker", "disk"]);
        assert!(root_equivalent_groups(&["alice".to_owned()]).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_version_output() {
        assert_eq!(
            install::parse_version_output("mairu 0.13.0 (abc1234)\n"),
            Some("0.13.0".to_owned())
        );
        assert_eq!(
            install::parse_version_output("mairu 0.13.0\n"),
            Some("0.13.0".to_owned())
        );
        assert_eq!(install::parse_version_output("garbage"), None);
        assert_eq!(install::parse_version_output(""), None);
    }
}
