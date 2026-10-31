const TEMPLATE_POLICY: &str = include_str!("../policy/templates/policy.cedar");
const TEMPLATE_SETTINGS: &str = include_str!("../policy/templates/authorization.json");

#[derive(clap::Args)]
pub struct PolicyArgs {
    #[clap(subcommand)]
    command: PolicyCommand,
}

#[derive(clap::Subcommand)]
enum PolicyCommand {
    /// Write policy.cedar and authorization.json templates into the configuration directory
    Init {
        /// Overwrite existing files
        #[arg(long)]
        force: bool,
    },
    /// Validate the policy files, list their policies and flag risky permits (no agent involved)
    Check,
    /// Show the policies and settings the agent has in force, the integrity stores and each server's state
    Show,
    /// Approve the policy files and server configs, so that the agent applies them in full
    Approve {
        /// Skip the confirmation question when DIGEST is the approval digest this command prints
        #[arg(long, value_name = "DIGEST")]
        confirm: Option<String>,
    },
    /// Show what the agent's policy decides for a request, for each way it could be covered
    Explain(ExplainArgs),
    /// Print the Cedar schema policies are validated against
    Schema,
}

#[derive(clap::Args)]
struct ExplainArgs {
    /// Server ID
    server: String,
    /// Role, as given to `mairu exec`
    role: String,
    /// Role ARN to assume with the role's credentials
    #[arg(long, value_name = "ARN")]
    assume_role: Option<String>,
    /// Tool label of the request, such as ai-agent
    #[arg(long = "tool", value_name = "LABEL", value_parser = crate::cmd::lock::parse_label)]
    tools: Vec<String>,
    /// What the client is about to do; implied by --exec
    #[arg(long, value_enum)]
    intent: Option<Intent>,
    /// Working directory of the request
    #[arg(long, value_name = "PATH")]
    cwd: Option<String>,
    /// Command line of `mairu exec`
    #[arg(long = "exec", value_name = "CMD")]
    exec: Option<String>,
    /// Age of a remembered approval, in seconds
    #[arg(long, value_name = "SECS", default_value_t = 0)]
    age: i64,
    /// Idle time of a remembered approval, in seconds
    #[arg(long, value_name = "SECS", default_value_t = 0)]
    idle: i64,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Intent {
    Exec,
    CredentialProcess,
}

pub fn run(args: &PolicyArgs) -> Result<(), anyhow::Error> {
    match &args.command {
        PolicyCommand::Init { force } => init(*force),
        PolicyCommand::Check => check(),
        PolicyCommand::Show => show(),
        PolicyCommand::Approve { confirm } => approve(confirm.as_deref()),
        PolicyCommand::Explain(a) => explain(a),
        PolicyCommand::Schema => {
            print!("{}", crate::policy::schema_text());
            Ok(())
        }
    }
}

fn init(force: bool) -> Result<(), anyhow::Error> {
    let dir = crate::config::config_dir();
    let files = [
        (
            crate::policy::files::PolicyFiles::policy_path(&dir),
            TEMPLATE_POLICY,
        ),
        (
            crate::policy::files::PolicyFiles::settings_path(&dir),
            TEMPLATE_SETTINGS,
        ),
    ];
    if !force && let Some((path, _)) = files.iter().find(|(p, _)| p.exists()) {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite",
            path.display()
        );
    }
    std::fs::create_dir_all(&dir)?;
    for (path, content) in &files {
        std::fs::write(path, content)?;
        println!("Wrote {}", path.display());
    }
    println!(
        "Edit them, then run `mairu policy check` and `mairu policy approve`. Until the files are approved, only their forbid policies apply."
    );
    Ok(())
}

fn check() -> Result<(), anyhow::Error> {
    use crate::policy::files::Content;
    let dir = crate::config::config_dir();
    let (policy, settings) = crate::policy::files::PolicyFiles::read_contents(&dir);
    let policy_path = crate::policy::files::PolicyFiles::policy_path(&dir);
    let settings_path = crate::policy::files::PolicyFiles::settings_path(&dir);
    if policy == Content::Absent && settings == Content::Absent {
        println!(
            "No {} or {} in {}; the built-in policies apply. `mairu policy init` writes templates.",
            crate::policy::user::FILE_NAME,
            crate::policy::files::SETTINGS_FILE_NAME,
            dir.display()
        );
        return Ok(());
    }
    let mut errors: Vec<String> = vec![];
    let mut warnings: Vec<String> = vec![];

    match &policy {
        Content::Absent => println!("{}  absent", policy_path.display()),
        Content::Unreadable(e) => errors.push(format!("{}: {e}", policy_path.display())),
        Content::Text(source) => match crate::policy::user::PolicyFile::parse(source) {
            Err(e) => errors.push(format!("{}: {e}", policy_path.display())),
            Ok(file) => {
                println!("{}", policy_path.display());
                let schema = crate::policy::schema()?;
                errors.extend(file.errors(&schema));
                for p in &file.policies {
                    let effect = match p.effect() {
                        cedar_policy::Effect::Permit => "permit",
                        cedar_policy::Effect::Forbid => "forbid",
                    };
                    println!("  {effect}  {}", p.label());
                    println!("      {}", p.scope());
                    if !p.annotated {
                        warnings.push(format!("{} has no @id", p.position));
                    }
                    if p.effect() == cedar_policy::Effect::Permit {
                        if p.applies_without_check() {
                            println!("      ! can apply without a human check");
                        }
                        if p.uses_tools() {
                            println!(
                                "      ! depends on a tool label, which same-user code can produce or avoid"
                            );
                        }
                    }
                }
                if file
                    .policies
                    .iter()
                    .any(|p| p.effect() == cedar_policy::Effect::Permit)
                {
                    warnings.push(
                        "permit policies apply only once approved with `mairu policy approve`"
                            .to_owned(),
                    );
                }
            }
        },
    }

    match &settings {
        Content::Absent => println!("{}  absent", settings_path.display()),
        Content::Unreadable(e) => errors.push(format!("{}: {e}", settings_path.display())),
        Content::Text(source) => {
            match crate::policy::settings::AuthorizationSettings::parse(source) {
                Err(e) => errors.push(format!("{}: {e}", settings_path.display())),
                Ok(s) => {
                    println!("{}  valid", settings_path.display());
                    let relaxing: Vec<&str> = [
                        ("methods", s.methods.is_some()),
                        ("approval_methods", s.approval_methods.is_some()),
                        ("ssh_agent_keys", s.ssh_agent_keys.is_some()),
                        ("sts", s.sts.is_some()),
                        ("network", s.network.is_some()),
                    ]
                    .into_iter()
                    .filter_map(|(name, set)| set.then_some(name))
                    .collect();
                    for key in s.registered_keys() {
                        let uv = if key.require_user_verification {
                            ", user verification required"
                        } else {
                            ""
                        };
                        println!(
                            "  ssh-agent key  {} {} ({}{uv})",
                            key.fingerprint(),
                            key.public.comment(),
                            key.public.algorithm().as_str()
                        );
                    }
                    if !relaxing.is_empty() {
                        warnings.push(format!(
                            "{} in {} apply only once approved",
                            relaxing.join(", "),
                            crate::policy::files::SETTINGS_FILE_NAME
                        ));
                    }
                    warnings.extend(s.warnings());
                }
            }
        }
    }

    for w in &warnings {
        println!("warning  {w}");
    }
    for e in &errors {
        println!("error    {e}");
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(crate::Error::FailureButSilentlyExit.into())
    }
}

async fn get_policy(server_id: &str) -> Result<crate::proto::GetPolicyResponse, anyhow::Error> {
    let mut agent = crate::cmd::agent::connect_or_start().await?;
    Ok(agent
        .get_policy(crate::proto::GetPolicyRequest {
            server_id: server_id.to_owned(),
        })
        .await?
        .into_inner())
}

#[tokio::main]
async fn show() -> Result<(), anyhow::Error> {
    let resp = get_policy("").await?;
    let detail = match resp.integrity() {
        crate::proto::PolicyIntegrity::Absent => " (built-in policies only)",
        crate::proto::PolicyIntegrity::Unapproved => " (built-ins plus your forbid policies)",
        crate::proto::PolicyIntegrity::Approved => " (your policy.cedar and authorization.json)",
        crate::proto::PolicyIntegrity::Tampered => " (lockdown plus your forbid policies)",
        crate::proto::PolicyIntegrity::Unspecified => "",
    };
    println!("policy   {}{detail}", describe_integrity(resp.integrity()));
    if !resp.digest.is_empty() {
        println!("digest   {}", crate::platform::integrity::hex(&resp.digest));
    }
    for store in &resp.stores {
        let generation = store
            .stored
            .as_ref()
            .map(|r| format!(" generation {}", r.generation))
            .unwrap_or_default();
        let detail = if store.detail.is_empty() {
            String::new()
        } else {
            format!(" ({})", store.detail)
        };
        println!(
            "store    {} {}{generation}{detail}",
            crate::platform::integrity::store_name(store.store()),
            crate::platform::integrity::status_name(store.status()),
        );
    }
    if let Some(anchor) = &resp.approval_anchor {
        println!("approval {}", anchor.methods.join(", "));
    }
    for server in &resp.servers {
        let state = match server.state() {
            crate::proto::server_integrity::State::Approved => "approved",
            crate::proto::server_integrity::State::Unapproved => "unapproved",
            crate::proto::server_integrity::State::Changed => {
                "changed (refused until approved again)"
            }
            crate::proto::server_integrity::State::Unspecified => "unknown",
        };
        let source = if server.logged_in { "session" } else { "file" };
        println!("server   {} {state} ({source})", server.server_id);
    }
    for note in &resp.notes {
        println!("note     {note}");
    }
    println!();
    println!("# Settings in force");
    println!("{}", resp.effective_settings_json.trim_end());
    println!();
    println!("# Policies in force");
    println!("{}", resp.effective_policies.trim_end());
    Ok(())
}

/// Each server of `servers.d`, with its counted fields and digest.
async fn server_files() -> Result<
    Vec<(
        crate::config::Server,
        crate::policy::integrity_state::Digest,
    )>,
    anyhow::Error,
> {
    Ok(crate::config::Server::find_all_from_fs()
        .await?
        .into_iter()
        .map(|s| {
            let d = crate::policy::integrity_state::server_digest(&s);
            (s, d)
        })
        .collect())
}

#[tokio::main]
async fn approve(confirm: Option<&str>) -> Result<(), anyhow::Error> {
    use crate::platform::integrity::hex;
    use crate::policy::files::Content;
    let product = env!("CARGO_PKG_NAME");
    check()?;
    let dir = crate::config::config_dir();
    let (policy, settings) = crate::policy::files::PolicyFiles::read_contents(&dir);
    for (path, content) in [
        (
            crate::policy::files::PolicyFiles::policy_path(&dir),
            &policy,
        ),
        (
            crate::policy::files::PolicyFiles::settings_path(&dir),
            &settings,
        ),
    ] {
        println!();
        match content {
            Content::Absent => println!("# {} (absent)", path.display()),
            Content::Text(text) => {
                println!("# {}", path.display());
                println!("{}", text.trim_end());
            }
            Content::Unreadable(e) => anyhow::bail!("{}: {e}", path.display()),
        }
    }
    let servers = server_files().await?;
    println!();
    println!("# Servers ({})", dir.join("servers.d").display());
    if servers.is_empty() {
        println!("(none)");
    }
    for (server, digest) in &servers {
        println!("{}  {}", server.id(), hex(digest));
        println!(
            "    {}",
            crate::policy::integrity_state::server_counted_json(server)
        );
    }
    let digest = crate::policy::integrity_state::policy_digest(&policy, &settings);
    let server_digests: std::collections::BTreeMap<String, crate::policy::integrity_state::Digest> =
        servers
            .iter()
            .map(|(s, d)| (s.id().to_owned(), *d))
            .collect();
    let approval_digest = hex(&crate::policy::integrity_state::approval_digest(
        &digest,
        &server_digests,
    ));
    println!();
    println!("policy digest    {}", hex(&digest));
    println!("approval digest  {approval_digest}");

    let mut agent = crate::cmd::agent::connect_or_start().await?;
    let current = agent
        .get_policy(crate::proto::GetPolicyRequest::default())
        .await?
        .into_inner();
    println!(
        "current state    {}",
        describe_integrity(current.integrity())
    );
    let mut relogin = vec![];
    for server in &current.servers {
        if server.logged_in
            && let Some(file) = server_digests.get(&server.server_id)
            && server.digest.as_slice() != file.as_slice()
        {
            println!(
                "warning  the session of server '{}' holds another config than servers.d; log in to it again after approving",
                server.server_id
            );
            relogin.push(server.server_id.clone());
        }
    }
    println!();

    let instruction = format!(
        "To approve without the question, run:\n    {product} policy approve --confirm {approval_digest}"
    );
    match confirm {
        Some(given) if given == approval_digest => {}
        Some(_) => {
            eprintln!("The policy differs from the digest given to --confirm. {instruction}");
            return Err(crate::Error::FailureButSilentlyExit.into());
        }
        None => match ask_to_proceed().await? {
            Some(true) => {}
            Some(false) => {
                eprintln!("Not approved.");
                return Err(crate::Error::FailureButSilentlyExit.into());
            }
            None => {
                eprintln!("There is no terminal to ask on. {instruction}");
                return Err(crate::Error::FailureButSilentlyExit.into());
            }
        },
    }

    let req = crate::proto::ApprovePolicyRequest {
        expected_digest: digest.to_vec(),
        client_context: Some(crate::proto::ClientContext {
            env_names: crate::tool_detection::env_names(),
            ..Default::default()
        }),
        expected_server_digests: server_digests
            .iter()
            .map(|(id, d)| (id.clone(), d.to_vec()))
            .collect(),
    };
    let notice = |_: &crate::proto::AuthorizationError| {
        format!(
            ":: {product} :: Policy approval required: {approval_digest}\n:: {product} :: Enter your password below.\n"
        )
    };
    let relay = crate::ssh_agent_presence::Relay::from_env();
    let signature_notice = |_: &crate::proto::AuthorizationError, comment: &str| {
        format!(
            ":: {product} :: Policy approval required: {approval_digest}\n:: {product} :: Approve the signature on your SSH agent ({comment}) to approve this policy (not for AWS credentials)\n"
        )
    };
    let resp = crate::polkit_tty_agent::with_fallback(notice, |attempt| {
        let agent = agent.clone();
        let req = req.clone();
        let relay = relay.clone();
        async move {
            relay
                .with_challenges(signature_notice, |response| {
                    let mut agent = agent.clone();
                    let mut req = req.clone();
                    let signed = crate::ssh_agent_presence::is_signed(response.as_ref());
                    crate::ssh_agent_presence::set_response(&mut req.client_context, response);
                    async move {
                        match attempt {
                            crate::polkit_tty_agent::Attempt::First if !signed => {
                                approve_while_waiting(&mut agent, req).await
                            }
                            _ => agent.approve_policy(req).await,
                        }
                    }
                })
                .await
        }
    })
    .await;
    let resp = match resp {
        Ok(r) => r.into_inner(),
        Err(status) => {
            let message = crate::cmd::authorization::refusal_message(&status)
                .unwrap_or_else(|| status.message().to_owned());
            eprintln!("Not approved: {message}");
            return Err(crate::Error::FailureButSilentlyExit.into());
        }
    };
    println!(
        "Approved; the policy is {}.",
        describe_integrity(resp.integrity())
    );
    for store in &resp.stores {
        let detail = if store.detail.is_empty() {
            String::new()
        } else {
            format!(" ({})", store.detail)
        };
        let status = match store.status() {
            crate::proto::platform::IntegrityStatus::Matched => "recorded",
            _ => "skipped",
        };
        println!(
            "store    {} {status}{detail}",
            crate::platform::integrity::store_name(store.store())
        );
    }
    for id in relogin {
        println!(
            "Log in to '{id}' again (`{product} login {id}`) so that its session uses the approved config."
        );
    }
    Ok(())
}

/// Prints that the agent waits for the approval, not for credentials, once it takes long enough to be prompting.
async fn approve_while_waiting(
    agent: &mut crate::agent::AgentConn,
    req: crate::proto::ApprovePolicyRequest,
) -> tonic::Result<tonic::Response<crate::proto::ApprovePolicyResponse>> {
    let product = env!("CARGO_PKG_NAME");
    let resp = agent.approve_policy(req);
    let notice = tokio::time::sleep(std::time::Duration::from_millis(500));
    tokio::pin!(resp, notice);
    let mut noticed = false;
    loop {
        tokio::select! {
            retval = &mut resp => return retval,
            _ = &mut notice, if !noticed => {
                noticed = true;
                crate::terminal::send(&format!(":: {product} :: Waiting for the policy approval (not for AWS credentials). Approve in the system dialog if one appears.")).await;
            }
        }
    }
}

/// `Proceed to authorize this policy? [y/N]` on the terminal; `None` without one.
async fn ask_to_proceed() -> Result<Option<bool>, anyhow::Error> {
    use tokio::io::AsyncBufReadExt;
    if !crate::terminal::is_terminal().await {
        return Ok(None);
    }
    let Ok(tty) = std::fs::OpenOptions::new().read(true).open("/dev/tty") else {
        return Ok(None);
    };
    let mut reader = tokio::io::BufReader::with_capacity(16, tokio::fs::File::from_std(tty));
    crate::terminal::send("Proceed to authorize this policy? [y/N] \0").await;
    let mut answer = String::new();
    reader.read_line(&mut answer).await?;
    Ok(Some(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    )))
}

fn describe_integrity(integrity: crate::proto::PolicyIntegrity) -> &'static str {
    match integrity {
        crate::proto::PolicyIntegrity::Unspecified => "unknown",
        crate::proto::PolicyIntegrity::Absent => "absent",
        crate::proto::PolicyIntegrity::Approved => "approved",
        crate::proto::PolicyIntegrity::Unapproved => "unapproved",
        crate::proto::PolicyIntegrity::Tampered => "tampered",
    }
}

#[tokio::main]
async fn explain(args: &ExplainArgs) -> Result<(), anyhow::Error> {
    let resp = get_policy(&args.server).await?;
    let engine = crate::policy::Engine::from_text(&resp.effective_policies)?;
    let settings: serde_json::Value = serde_json::from_str(&resp.effective_settings_json)?;
    let methods: Vec<String> = settings["methods"]
        .as_array()
        .map(|m| {
            m.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let hardened = engine
        .policy_ids()
        .iter()
        .all(|id| id != "builtin-unhardened");

    let server_url = match crate::config::Server::find_from_fs(&args.server).await {
        Ok(server) => server.url.to_string(),
        Err(e) => {
            tracing::debug!(err = ?e, "Server not found");
            String::new()
        }
    };
    let uid = nix::unistd::geteuid().as_raw();
    let user_name = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| uid.to_string());
    let tty = crate::cmd::authorization::terminal_path();
    let intent = match (args.intent, &args.exec) {
        (Some(Intent::Exec), _) | (None, Some(_)) => "exec",
        (Some(Intent::CredentialProcess), _) => "credential-process",
        (None, None) => "unknown",
    };
    let facts = crate::policy::Facts {
        uid,
        user_name: user_name.clone(),
        server_id: args.server.clone(),
        server_url,
        role: args.role.clone(),
        // Without a terminal, a request is remembered per parent process.
        session: if tty.is_some() { "tty" } else { "parent" },
        tty: tty.clone(),
        hardened,
        intent,
        exec_command: args.exec.as_ref().and_then(|c| {
            c.split_whitespace()
                .next()
                .map(|argv0| argv0.rsplit('/').next().unwrap_or_default().to_owned())
        }),
        exec_command_line: args.exec.clone(),
        cwd: args.cwd.clone(),
        chained_role_arn: args.assume_role.clone(),
        tools: args.tools.iter().cloned().collect(),
        tool_matches: Default::default(),
        wsl_interop: crate::platform::process().wsl_interop(),
    };

    println!(
        "{} on {} ({} agent, session {}{}{}, policy {})",
        args.role,
        args.server,
        if hardened { "hardened" } else { "unhardened" },
        facts.session,
        tty.map(|t| format!(" {t}")).unwrap_or_default(),
        match facts.wsl_interop {
            Some(true) => ", WSL2 interop enabled",
            Some(false) => ", WSL2 interop disabled",
            None => "",
        },
        describe_integrity(resp.integrity()),
    );
    let mut candidates = vec![
        ("no check".to_owned(), crate::policy::Presence::none()),
        (
            format!("process lease (age {}s, idle {}s)", args.age, args.idle),
            crate::policy::Presence::remembered(
                crate::policy::Scope::Process,
                crate::authorization::METHOD_PLATFORM,
                args.age,
                args.idle,
            ),
        ),
        (
            format!("session grant (age {}s, idle {}s)", args.age, args.idle),
            crate::policy::Presence::remembered(
                crate::policy::Scope::Session,
                crate::authorization::METHOD_PLATFORM,
                args.age,
                args.idle,
            ),
        ),
    ];
    for method in &methods {
        candidates.push((
            format!("fresh check by {method}"),
            crate::policy::Presence::fresh(method),
        ));
    }

    println!("assume-role (gate 1)");
    print_decisions(
        &engine,
        &facts,
        crate::policy::Action::AssumeRole,
        &candidates,
    )?;

    if hardened {
        let account = args
            .assume_role
            .as_deref()
            .and_then(crate::policy::account_id)
            .or_else(|| crate::policy::account_id(&args.role));
        match account {
            Some(account) => {
                let role_name = args
                    .assume_role
                    .as_deref()
                    .unwrap_or(&args.role)
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                let caller = crate::caller_identity::Caller::new(
                    account.clone(),
                    format!("arn:aws:sts::{account}:assumed-role/{role_name}/{user_name}"),
                    format!("AROAEXPLAIN:{user_name}"),
                );
                println!("use-credentials (gate 2), for credentials of {account}");
                print_decisions(
                    &engine,
                    &facts,
                    crate::policy::Action::UseCredentials(&caller),
                    &candidates,
                )?;
            }
            None => println!(
                "use-credentials (gate 2): depends on the real account of the credentials, which the role name does not declare"
            ),
        }
    }
    Ok(())
}

fn print_decisions(
    engine: &crate::policy::Engine,
    facts: &crate::policy::Facts,
    action: crate::policy::Action<'_>,
    candidates: &[(String, crate::policy::Presence)],
) -> Result<(), anyhow::Error> {
    let prepared = engine
        .prepare(facts, action)
        .map_err(|e| anyhow::anyhow!("invalid request: {e}"))?;
    let width = candidates.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
    for (name, presence) in candidates {
        let eval = engine.evaluate(&prepared, presence);
        let detail = if !eval.errors.is_empty() {
            format!("error: {}", eval.errors.join("; "))
        } else if eval.allowed {
            eval.policies.join(", ")
        } else if !eval.forbids.is_empty() {
            format!("forbidden by {}", eval.forbids.join(", "))
        } else {
            "no policy permits".to_owned()
        };
        let decision = if eval.allowed { "allow" } else { "deny " };
        println!("  {name:<width$}  {decision}  {detail}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_templates_check_clean() {
        let file = crate::policy::user::PolicyFile::parse(TEMPLATE_POLICY).unwrap();
        let schema = crate::policy::schema().unwrap();
        assert_eq!(file.errors(&schema), Vec::<String>::new());
        let ids: Vec<_> = file.policies.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["human", "ai-agent-per-request"]);
        assert!(
            file.policies
                .iter()
                .all(|p| p.annotated && !p.applies_without_check())
        );
        crate::policy::settings::AuthorizationSettings::parse(TEMPLATE_SETTINGS).unwrap();
    }

    #[test]
    fn test_template_examples_validate() {
        let uncommented: String = TEMPLATE_POLICY
            .lines()
            .filter_map(|l| l.strip_prefix("// "))
            .filter(|l| {
                l.starts_with('@')
                    || l.starts_with("forbid")
                    || l.starts_with("when")
                    || l.starts_with("unless")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let file = crate::policy::user::PolicyFile::parse(&uncommented).unwrap();
        assert_eq!(file.policies.len(), 2);
        assert_eq!(
            file.errors(&crate::policy::schema().unwrap()),
            Vec::<String>::new()
        );
    }
}
