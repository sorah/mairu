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
    let mut agent_status = None;
    match crate::agent::connect_to_agent_with_path(&path).await {
        Err(e) => println!("agent    not running at {} ({e})", path.display()),
        Ok(mut conn) => {
            let verification = match conn.trust() {
                crate::platform::AgentTrust::Verified => "verified",
                crate::platform::AgentTrust::Unverified => "NOT VERIFIED",
                crate::platform::AgentTrust::Unverifiable => "not checked (client not hardened)",
            };
            // Environment names and the session go only to an agent this mairu trusts.
            let trusted = conn.trust() != crate::platform::AgentTrust::Unverified;
            let client_context = trusted.then(|| crate::proto::ClientContext {
                env_names: crate::tool_detection::env_names(),
                ..Default::default()
            });
            let session = trusted.then(crate::proto::platform::SessionHint::current);
            let status = conn
                .get_agent_status(tonic::Request::new(crate::proto::GetAgentStatusRequest {
                    client_context,
                    session,
                }))
                .await;
            match status {
                Ok(status) => {
                    let status = status.into_inner();
                    print_agent_status(&status, &path, verification);
                    agent_status = Some(status.clone());
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

    let agent_hardened = agent_status.as_ref().map_or(
        matches!(state, crate::hardening::HardeningState::Hardened { .. }),
        |s| s.agent_hardening() == crate::proto::HardeningState::Hardened,
    );
    let (policy_warnings, keys) = print_policy(agent_hardened, agent_status.as_ref());
    warnings.extend(policy_warnings);
    warnings.extend(ssh_agent::report(&keys.ssh_agent).await);
    warnings.extend(windows_hello::report(&keys).await);

    #[cfg(target_os = "linux")]
    warnings.extend(headless::report(agent_status.as_ref()));
    #[cfg(target_os = "linux")]
    wsl::report().await;
    print_desktop(agent_status.as_ref());

    for w in warnings {
        println!("warning  {w}");
    }
    Ok(())
}

/// How this client opens URLs and posts notifications, with what the agent can deliver for its session.
fn print_desktop(status: Option<&crate::proto::GetAgentStatusResponse>) {
    let settings = crate::convenience::Settings::get();
    let caps = status.and_then(|s| s.capabilities.as_ref());
    println!("desktop");
    for (feature, delivery, capable) in [
        (
            crate::convenience::Feature::OpenUrl,
            &settings.open_url,
            caps.map(|c| c.open_url),
        ),
        (
            crate::convenience::Feature::Notify,
            &settings.notify,
            caps.map(|c| c.notifications),
        ),
    ] {
        let note = match (delivery, capable) {
            (crate::convenience::Delivery::Agent, Some(true)) => "  (the agent can deliver here)",
            (crate::convenience::Delivery::Agent, Some(false)) => {
                "  (the agent cannot deliver here; see the notes above)"
            }
            (crate::convenience::Delivery::Agent, None) => "  (no status from the agent)",
            _ => "",
        };
        println!("  {:<12}  {delivery}{note}", feature.name());
    }
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
        Some(c) => {
            println!(
                "caller   {}  pid {} start_time {}",
                if c.verified { "verified" } else { "unverified" },
                c.pid,
                c.start_time
            );
            if !c.session.is_empty() {
                println!("session  {}", c.session);
            }
            println!(
                "tools    {}",
                if c.tools.is_empty() {
                    "none".to_owned()
                } else {
                    format!("{} ({})", c.tools.join(", "), c.tool_matches.join(", "))
                }
            );
            if !c.marks.is_empty() {
                println!(
                    "marks    {} on this terminal session; `mairu unlock --tool <label>` removes one",
                    c.marks.join(", ")
                );
            }
        }
        None => println!("caller   unknown"),
    }
    println!(
        "authorization  grants={} leases={} methods={}",
        status.grants,
        status.leases,
        if status.authorization_methods.is_empty() {
            "-".to_owned()
        } else {
            status.authorization_methods.join(",")
        }
    );
    if !status.platform_helper.is_empty() {
        println!("helper   {}", status.platform_helper);
    }
    if let Some(caps) = &status.capabilities {
        println!("capabilities  {}", describe_capabilities(caps));
        for note in &caps.notes {
            println!("  note: {note}");
        }
    }
}

/// The keys and helper pin in force, as the client computes them.
#[derive(Debug, Default)]
pub struct Keys {
    pub ssh_agent: Vec<crate::ssh_agent_presence::RegisteredKey>,
    pub windows_hello: Vec<crate::windows_hello::RegisteredKey>,
    pub windows_hello_helper_sha256: Option<String>,
}

impl Keys {
    pub fn of(effective: &crate::policy::files::Effective) -> Self {
        Self {
            ssh_agent: effective.ssh_agent_keys.clone(),
            windows_hello: effective.windows_hello_keys.clone(),
            windows_hello_helper_sha256: effective.settings.windows_hello_helper_sha256.clone(),
        }
    }
}

/// The policy files evaluated here, for the state the agent reports, or as unapproved without an agent. Returns
/// warnings and the keys registered for the key-based methods.
fn print_policy(
    hardened: bool,
    status: Option<&crate::proto::GetAgentStatusResponse>,
) -> (Vec<String>, Keys) {
    use crate::policy::settings::PolicyState;
    let mut warnings = vec![];
    let dir = crate::config::config_dir();
    let (state, built) = crate::policy::files::Effective::for_status(&dir, hardened, status);
    let mut keys = Keys::default();
    match built {
        Ok(effective) => {
            keys = Keys::of(&effective);
            let own = effective
                .engine
                .policy_ids()
                .iter()
                .filter(|id| !id.starts_with(crate::policy::BUILTIN_PREFIX))
                .count();
            let state = state.unwrap_or(effective.state);
            let detail = match effective.state {
                PolicyState::Approved => format!("{own} policies of yours apply"),
                _ => format!("{own} forbid policies of yours apply"),
            };
            let detail = if state == PolicyState::Tampered {
                format!("lockdown; {detail}")
            } else {
                detail
            };
            println!("policy   {} ({detail})", state.as_str());
            for note in &effective.notes {
                println!("  note: {note}");
            }
            if state == PolicyState::Tampered {
                warnings.push(crate::policy::files::LOCKDOWN_WARNING.to_owned());
            }
        }
        Err(e) => println!("policy   error: {e}"),
    }
    let Some(status) = status else {
        return (warnings, keys);
    };
    for store in &status.policy_stores {
        let detail = if store.detail.is_empty() {
            String::new()
        } else {
            format!(" ({})", store.detail)
        };
        let generation = store
            .stored
            .as_ref()
            .map(|r| format!(" generation {}", r.generation))
            .unwrap_or_default();
        println!(
            "  store: {} {}{generation}{detail}",
            crate::platform::integrity::store_name(store.store()),
            crate::platform::integrity::status_name(store.status()),
        );
    }
    if let Some(anchor) = &status.approval_anchor {
        println!("  approval: {}", anchor.methods.join(", "));
        let has_keys = !anchor.ssh_agent_keys.is_empty() || !anchor.windows_hello_keys.is_empty();
        if has_keys
            && anchor
                .methods
                .iter()
                .any(|m| m == crate::authorization::METHOD_PLATFORM)
        {
            warnings.push("the approval anchor allows \"platform\" while keys are registered, so a captured password can approve a policy that registers someone else's key; remove it from approval_methods and approve again".to_owned());
        }
    }
    (warnings, keys)
}

/// Whether the Windows Hello helper can run here, matches its pin, and holds a registered key.
mod windows_hello {
    /// Prints the windows-hello section when Windows Hello is in play here; returns warnings.
    pub async fn report(keys: &super::Keys) -> Vec<String> {
        let mut warnings = vec![];
        let interop = crate::windows_hello::interop_available();
        if !interop {
            if !keys.windows_hello.is_empty() {
                warnings.push("windows_hello_keys are registered, and Windows Hello needs WSL2 with interop, which this is not, so the next method asks instead".to_owned());
            }
            return warnings;
        }
        println!("windows-hello");
        let config = crate::config::UserConfig::load().await.unwrap_or_default();
        let source = if config.windows_hello_helper.is_some() {
            "windows_hello_helper"
        } else {
            "shipped"
        };
        let Some(path) = crate::windows_hello::Helper::locate(&config) else {
            println!(
                "  helper        not found (no {} next to mairu, no windows_hello_helper in config.json)",
                crate::windows_hello::HELPER_FILE_NAME
            );
            print_registered(keys, None);
            if !keys.windows_hello.is_empty() {
                warnings.push(format!("windows_hello_keys are registered, and there is no {}, so the windows-hello method declines; set windows_hello_helper in config.json to the helper from the release", crate::windows_hello::HELPER_FILE_NAME));
            }
            return warnings;
        };
        let helper = crate::windows_hello::Helper {
            path,
            pin: crate::windows_hello::Pin::resolve(keys.windows_hello_helper_sha256.as_deref()),
            hardened: crate::hardening::Hardening::marker().is_some(),
        };
        println!("  helper        {} ({source})", helper.path.display());
        match crate::windows_hello::digest(&helper.path) {
            Ok(actual) => println!("  sha256        {actual}"),
            Err(e) => println!("  sha256        unreadable ({e})"),
        }
        println!("  pin           {}", helper.pin);
        if let Err(e) = helper.check() {
            println!("  check         {e}");
            print_registered(keys, None);
            warnings.push(format!("the Windows Hello helper is not run: {e}"));
            return warnings;
        }
        let key = match helper.public_key().await {
            Ok(spki) => {
                let fingerprint = crate::windows_hello::fingerprint(&spki);
                println!("  key           {fingerprint}");
                Some(fingerprint)
            }
            Err(e) if e.is_not_enrolled() => {
                println!("  key           none; `mairu policy enroll-windows-hello` creates it");
                None
            }
            Err(e) => {
                println!("  key           unknown; the helper failed ({e})");
                warnings.push(format!(
                    "the Windows Hello helper at {} failed: {e}",
                    helper.path.display()
                ));
                None
            }
        };
        print_registered(keys, key.as_deref());
        if !keys.windows_hello.is_empty()
            && !key
                .as_deref()
                .is_some_and(|k| keys.windows_hello.iter().any(|r| r.fingerprint() == k))
        {
            warnings.push("no registered windows_hello_keys entry matches the Windows Hello key here, so the windows-hello method declines and the next method asks".to_owned());
        }
        warnings
    }

    fn print_registered(keys: &super::Keys, held: Option<&str>) {
        if keys.windows_hello.is_empty() {
            println!("  registered    none");
        }
        for key in &keys.windows_hello {
            let state = match held {
                Some(k) if k == key.fingerprint() => " (this Windows Hello key)",
                _ => "",
            };
            println!("  registered    {} {}{state}", key.fingerprint(), key.name);
        }
    }
}

/// Whether `$SSH_AUTH_SOCK` reaches an SSH agent, and which registered keys it holds.
mod ssh_agent {
    /// Prints the ssh-agent section; returns warnings.
    pub async fn report(keys: &[crate::ssh_agent_presence::RegisteredKey]) -> Vec<String> {
        let mut warnings = vec![];
        println!("ssh-agent");
        let socket = std::env::var_os("SSH_AUTH_SOCK").filter(|s| !s.is_empty());
        let held = match &socket {
            None => {
                println!("  SSH_AUTH_SOCK not set");
                if !keys.is_empty() {
                    warnings.push("keys are registered for the ssh-agent method, and SSH_AUTH_SOCK is not set here, so the next method asks instead".to_owned());
                }
                None
            }
            Some(path) => {
                let path = std::path::Path::new(path);
                match crate::ssh_agent_presence::probe(path).await {
                    Ok(identities) => {
                        println!(
                            "  SSH_AUTH_SOCK {} reachable ({} keys)",
                            path.display(),
                            identities.len()
                        );
                        Some(identities)
                    }
                    Err(e) => {
                        println!("  SSH_AUTH_SOCK {} unreachable ({e})", path.display());
                        warnings.push(format!("SSH_AUTH_SOCK ({}) is stale or unreachable ({e}), so the ssh-agent method declines and the next method asks; point it at a live agent, e.g. a ~/.ssh/agent.sock symlink kept current by ~/.ssh/rc", path.display()));
                        None
                    }
                }
            }
        };
        if keys.is_empty() {
            println!("  registered    none");
        }
        let mut any_held = false;
        for key in keys {
            let state = match &held {
                Some(identities) => {
                    if identities
                        .iter()
                        .any(|i| i.fingerprint() == key.fingerprint())
                    {
                        any_held = true;
                        "held by the SSH agent"
                    } else {
                        "not held"
                    }
                }
                None => "unknown",
            };
            println!(
                "  registered    {} {} ({state})",
                key.fingerprint(),
                key.public.comment()
            );
        }
        if held.is_some() && !keys.is_empty() && !any_held {
            warnings.push("the SSH agent at SSH_AUTH_SOCK holds no registered key, so the ssh-agent method declines and the next method asks".to_owned());
        }
        warnings
    }
}

fn describe_capabilities(caps: &crate::proto::platform::Capabilities) -> String {
    let strip = |name: &'static str, prefix: &str| name.strip_prefix(prefix).unwrap_or(name);
    let stores: Vec<&str> = caps
        .integrity_stores()
        .map(|s| strip(s.as_str_name(), "INTEGRITY_STORE_KIND_"))
        .collect();
    let yes_no = |b: bool| if b { "yes" } else { "no" };
    format!(
        "peer_verification={} authorization={} integrity_stores={} notifications={} open_url={}",
        strip(caps.peer_verification().as_str_name(), "PEER_VERIFICATION_"),
        strip(
            caps.authorization().as_str_name(),
            "AUTHORIZATION_FACILITY_"
        ),
        if stores.is_empty() {
            "-".to_owned()
        } else {
            stores.join(",")
        },
        yes_no(caps.notifications),
        yes_no(caps.open_url),
    )
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

/// The WSL version, interop and profile, and how the Windows SSH agent reaches this distribution. Root reachability
/// through interop is among the process notes, which are warnings here.
#[cfg(target_os = "linux")]
mod wsl {
    pub async fn report() {
        use crate::platform::process::linux::wsl::Wsl;
        let Some(wsl) = Wsl::detect() else {
            return;
        };
        println!("wsl");
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        println!("  version       {} ({})", wsl.version(), release.trim());
        let Wsl::Wsl2 { interop } = wsl else {
            println!("  hardening     unsupported; use WSL2");
            return;
        };
        println!("  interop       {interop}");
        let profile = interop.profile();
        let detail = match profile {
            crate::platform::process::linux::wsl::Profile::Integrated => {
                "a guardrail: root is reachable through `wsl.exe -u root`"
            }
            crate::platform::process::linux::wsl::Profile::Isolated => {
                "native-Linux strength against code inside this distribution"
            }
        };
        println!("  profile       {profile} ({detail})");
        println!("  ssh-agent     {}", relayed_agent().await);
    }

    /// Whether `$SSH_AUTH_SOCK` reaches an agent, and how it would come from Windows.
    async fn relayed_agent() -> String {
        let via = if std::env::var_os("SSH_CONNECTION").is_some_and(|s| !s.is_empty()) {
            "forwarded over SSH"
        } else {
            "local socket, e.g. a relay of the Windows OpenSSH agent"
        };
        match std::env::var_os("SSH_AUTH_SOCK").filter(|s| !s.is_empty()) {
            None => "SSH_AUTH_SOCK not set; relay the Windows OpenSSH agent (npiperelay + socat, or wsl2-ssh-agent), or connect with `ssh -A` from Windows".to_owned(),
            Some(path) => {
                let path = std::path::Path::new(&path);
                match crate::ssh_agent_presence::probe(path).await {
                    Ok(ids) => format!(
                        "{} reachable, {} keys ({via})",
                        path.display(),
                        ids.len()
                    ),
                    Err(e) => format!("{} unreachable ({e})", path.display()),
                }
            }
        }
    }
}

/// Whether a password prompt can be shown here when no desktop authentication agent can ask.
#[cfg(target_os = "linux")]
mod headless {
    /// Prints the headless section; returns warnings.
    pub fn report(agent: Option<&crate::proto::GetAgentStatusResponse>) -> Vec<String> {
        let mut warnings = vec![];
        println!("headless");

        let authorization = agent.map(|a| {
            (
                a.agent_hardening() == crate::proto::HardeningState::Hardened,
                a.capabilities
                    .as_ref()
                    .map(|c| c.authorization())
                    .unwrap_or_default(),
            )
        });
        // An unhardened agent never asks, so nothing here matters to it.
        let asks = !matches!(authorization, Some((false, _)));

        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty");
        match tty {
            Ok(_) => println!(
                "  tty           {}",
                crate::cmd::authorization::terminal_origin()
                    .unwrap_or_else(|| "/dev/tty".to_owned())
            ),
            Err(e) => {
                println!("  tty           none ({e})");
                if asks {
                    warnings.push("there is no terminal here, so a password prompt cannot be shown when no desktop authentication agent can ask".to_owned());
                }
            }
        }

        let ssh = ["SSH_CONNECTION", "SSH_TTY"]
            .into_iter()
            .find(|v| std::env::var_os(v).is_some_and(|s| !s.is_empty()));
        match ssh {
            Some(var) => println!("  ssh           yes (${var})"),
            None => println!("  ssh           no"),
        }

        match authorization {
            None => println!("  polkit        unknown (no status from the agent)"),
            Some((false, _)) => println!("  polkit        not used (the agent is not hardened)"),
            Some((true, facility)) => {
                let name = facility.as_str_name();
                let name = name.strip_prefix("AUTHORIZATION_FACILITY_").unwrap_or(name);
                if facility == crate::proto::platform::AuthorizationFacility::Polkit {
                    println!("  polkit        available (authorization: {name})");
                } else {
                    println!("  polkit        unavailable (authorization: {name})");
                    warnings.push("polkit is unavailable to the agent, so roles that need approval are refused".to_owned());
                }
            }
        }

        let pkttyagent = crate::polkit_tty_agent::PKTTYAGENT;
        match crate::polkit_tty_agent::check_pkttyagent() {
            Ok(facts) => println!(
                "  pkttyagent    {pkttyagent} {}:{} {:04o} ✓",
                user_name(facts.uid),
                group_name(facts.gid),
                facts.mode
            ),
            Err(e) => {
                println!("  pkttyagent    {pkttyagent} ✗ {e}");
                if asks {
                    warnings.push(format!("{pkttyagent} cannot be used ({e}), so password prompts in a terminal are unavailable"));
                }
            }
        }
        warnings
    }

    fn user_name(uid: u32) -> String {
        nix::unistd::User::from_uid(uid.into())
            .ok()
            .flatten()
            .map(|u| u.name)
            .unwrap_or_else(|| uid.to_string())
    }

    fn group_name(gid: u32) -> String {
        nix::unistd::Group::from_gid(gid.into())
            .ok()
            .flatten()
            .map(|g| g.name)
            .unwrap_or_else(|| gid.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_describe_capabilities() {
        let caps = crate::proto::platform::Capabilities {
            peer_verification: crate::proto::platform::PeerVerification::Setgid.into(),
            authorization: crate::proto::platform::AuthorizationFacility::Polkit.into(),
            integrity_stores: vec![
                crate::proto::platform::IntegrityStoreKind::ProtectedDirectory.into(),
                crate::proto::platform::IntegrityStoreKind::SecretService.into(),
            ],
            notifications: true,
            open_url: false,
            notes: vec![],
        };
        assert_eq!(
            describe_capabilities(&caps),
            "peer_verification=SETGID authorization=POLKIT integrity_stores=PROTECTED_DIRECTORY,SECRET_SERVICE notifications=yes open_url=no"
        );
        assert_eq!(
            describe_capabilities(&Default::default()),
            "peer_verification=UNSPECIFIED authorization=UNSPECIFIED integrity_stores=- notifications=no open_url=no"
        );
    }

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
