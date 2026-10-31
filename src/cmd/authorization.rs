//! The client side of authorization: the context a client reports, the lines it prints while the agent may be
//! asking a human, and messages for refusals.

/// A hardened agent may be prompting once a request takes this long.
const PROMPT_NOTICE_DELAY: std::time::Duration = std::time::Duration::from_millis(500);
const LONG_ATTEMPT_DURATION: std::time::Duration = std::time::Duration::from_secs(2);

/// This process's working directory, as `ClientContext.cwd`.
pub fn cwd() -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    std::env::current_dir()
        .map(|p| p.as_os_str().as_bytes().to_vec())
        .unwrap_or_default()
}

/// How the human is asked, which decides the first and last of the [`context_lines`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prompt {
    /// The agent may be asking through a system dialog; the client cannot tell.
    MaybeDialog,
    /// pkttyagent is about to ask for a password on this terminal.
    Password,
}

/// The lines of "What the human sees", for the terminal. `caller_arn` is the identity of credentials already
/// fetched, when the agent asks before vending them.
pub fn context_lines(
    server: &str,
    role: &str,
    context: &crate::proto::ClientContext,
    prompt: Prompt,
    caller_arn: Option<&str>,
    tools: Option<&str>,
) -> String {
    let heading = match prompt {
        Prompt::MaybeDialog => "Authorization may be required",
        Prompt::Password => "Authorization required",
    };
    let instruction = match prompt {
        Prompt::MaybeDialog => "Approve in the system dialog if one appears.".to_owned(),
        Prompt::Password => "Enter your password below.".to_owned(),
    };
    lines(
        heading,
        server,
        role,
        context,
        caller_arn,
        tools,
        &instruction,
    )
}

/// The lines of "What the human sees" before the SSH agent is asked to sign with the key named `comment`.
pub fn ssh_agent_lines(
    server: &str,
    role: &str,
    context: &crate::proto::ClientContext,
    comment: &str,
    caller_arn: Option<&str>,
    tools: Option<&str>,
) -> String {
    lines(
        "Authorization required",
        server,
        role,
        context,
        caller_arn,
        tools,
        &format!(
            "Approve the signature on your SSH agent ({comment}) to authorize {role} on {server}"
        ),
    )
}

fn lines(
    heading: &str,
    server: &str,
    role: &str,
    context: &crate::proto::ClientContext,
    caller_arn: Option<&str>,
    tools: Option<&str>,
    instruction: &str,
) -> String {
    let product = env!("CARGO_PKG_NAME");
    let command = match &context.intent {
        Some(crate::proto::client_context::Intent::Exec(e)) => {
            crate::authorization::shell_join(&e.command)
        }
        Some(crate::proto::client_context::Intent::CredentialProcess(_)) => {
            "(credential-process)".to_owned()
        }
        None => "(unknown)".to_owned(),
    };
    let mut lines = format!(":: {product} :: {heading}: {role} on {server}\n");
    if let Some(arn) = caller_arn.filter(|a| !a.is_empty()) {
        lines.push_str(&format!(
            ":: {product} ::   identity: {}\n",
            crate::caller_identity::summary(arn)
        ));
    }
    lines.push_str(&format!(":: {product} ::   command: {command}\n"));
    if !context.cwd.is_empty() {
        lines.push_str(&format!(
            ":: {product} ::   cwd:     {}\n",
            String::from_utf8_lossy(&context.cwd)
        ));
    }
    match (terminal_origin(), tools) {
        (Some(from), Some(tools)) => lines.push_str(&format!(
            ":: {product} ::   from:    {from}   tools: {tools}\n"
        )),
        (Some(from), None) => lines.push_str(&format!(":: {product} ::   from:    {from}\n")),
        (None, Some(tools)) => lines.push_str(&format!(":: {product} ::   tools:   {tools}\n")),
        (None, None) => {}
    }
    lines.push_str(&format!(":: {product} :: {instruction}\n"));
    lines
}

/// `/dev/pts/3`: this process's controlling terminal.
#[cfg(target_os = "linux")]
pub fn terminal_path() -> Option<String> {
    let stat = crate::platform::process::linux::procfs::Stat::read(std::process::id()).ok()?;
    crate::platform::process::linux::procfs::tty_path(stat.tty_nr)
}

#[cfg(not(target_os = "linux"))]
pub fn terminal_path() -> Option<String> {
    None
}

/// `/dev/pts/3 (zsh, tmux pane)`: this process's controlling terminal and its session leader.
#[cfg(target_os = "linux")]
pub fn terminal_origin() -> Option<String> {
    let procfs = |pid: u32| crate::platform::process::linux::procfs::Stat::read(pid).ok();
    let stat = procfs(std::process::id())?;
    let tty = crate::platform::process::linux::procfs::tty_path(stat.tty_nr)?;
    let mut traits = vec![];
    if let Ok(pid) = u32::try_from(stat.session)
        && let Ok(comm) = crate::platform::process::linux::procfs::read_comm(pid)
    {
        traits.push(comm);
    }
    if std::env::var_os("TMUX").is_some() {
        traits.push("tmux pane".to_owned());
    } else if std::env::var_os("SSH_TTY").is_some() {
        traits.push("ssh".to_owned());
    }
    Some(if traits.is_empty() {
        tty
    } else {
        format!("{tty} ({})", traits.join(", "))
    })
}

#[cfg(not(target_os = "linux"))]
pub fn terminal_origin() -> Option<String> {
    None
}

/// Calls `AssumeRole`, printing the context lines while a hardened agent may be asking a human, and the long
/// attempt notice when `long_attempt_notice` is set. Answers challenges through the SSH agent, and falls back to a
/// password prompt on this terminal when polkit has no authentication agent for this process.
pub async fn assume_role_with_notice(
    agent: &mut crate::agent::AgentConn,
    req: crate::proto::AssumeRoleRequest,
    long_attempt_notice: bool,
) -> tonic::Result<tonic::Response<crate::proto::AssumeRoleResponse>> {
    let relay = crate::ssh_agent_presence::Relay::from_env();
    let notice = |refusal: &crate::proto::AuthorizationError| password_notice(&req, refusal);
    crate::polkit_tty_agent::with_fallback(notice, |attempt| {
        let agent = agent.clone();
        let req = req.clone();
        let relay = relay.clone();
        async move {
            let signature_notice = |refusal: &crate::proto::AuthorizationError, comment: &str| {
                ssh_agent_notice(&req, refusal, comment)
            };
            relay
                .with_challenges(signature_notice, |response| {
                    let mut agent = agent.clone();
                    let mut req = req.clone();
                    let signed = crate::ssh_agent_presence::is_signed(response.as_ref());
                    crate::ssh_agent_presence::set_response(&mut req.client_context, response);
                    async move {
                        match attempt {
                            crate::polkit_tty_agent::Attempt::First if !signed => {
                                notify_while_waiting(&mut agent, req, long_attempt_notice).await
                            }
                            // The context is already printed; the SSH agent or the password prompt asks.
                            _ => agent.assume_role(req).await,
                        }
                    }
                })
                .await
        }
    })
    .await
}

/// Calls `AssumeRole` printing nothing unless it falls back to a password prompt on this terminal. Challenges are
/// still answered through the SSH agent.
pub async fn assume_role_quietly(
    agent: &mut crate::agent::AgentConn,
    req: crate::proto::AssumeRoleRequest,
) -> tonic::Result<tonic::Response<crate::proto::AssumeRoleResponse>> {
    let relay = crate::ssh_agent_presence::Relay::from_env();
    let notice = |refusal: &crate::proto::AuthorizationError| password_notice(&req, refusal);
    crate::polkit_tty_agent::with_fallback(notice, |_| {
        let agent = agent.clone();
        let req = req.clone();
        let relay = relay.clone();
        async move {
            relay
                .with_challenges(
                    |_, _| String::new(),
                    |response| {
                        let mut agent = agent.clone();
                        let mut req = req.clone();
                        crate::ssh_agent_presence::set_response(&mut req.client_context, response);
                        async move { agent.assume_role(req).await }
                    },
                )
                .await
        }
    })
    .await
}

fn ssh_agent_notice(
    req: &crate::proto::AssumeRoleRequest,
    refusal: &crate::proto::AuthorizationError,
    comment: &str,
) -> String {
    ssh_agent_lines(
        &req.server_id,
        &req.rolespec().role,
        &req.client_context.clone().unwrap_or_default(),
        comment,
        Some(&refusal.caller_arn),
        tools_summary(&refusal.tools).as_deref(),
    )
}

fn password_notice(
    req: &crate::proto::AssumeRoleRequest,
    refusal: &crate::proto::AuthorizationError,
) -> String {
    context_lines(
        &req.server_id,
        &req.rolespec().role,
        &req.client_context.clone().unwrap_or_default(),
        Prompt::Password,
        Some(&refusal.caller_arn),
        tools_summary(&refusal.tools).as_deref(),
    )
}

/// The tool labels of this request: what this process can see of itself, plus the labels the agent reported.
pub fn tools_summary(agent_tools: &[String]) -> Option<String> {
    let mut detection = crate::tool_detection::Detection::of_current_process();
    detection.tools.extend(agent_tools.iter().cloned());
    (!detection.is_empty()).then(|| detection.summary())
}

async fn notify_while_waiting(
    agent: &mut crate::agent::AgentConn,
    req: crate::proto::AssumeRoleRequest,
    long_attempt_notice: bool,
) -> tonic::Result<tonic::Response<crate::proto::AssumeRoleResponse>> {
    let may_prompt = agent.trust() == crate::platform::AgentTrust::Verified;
    let context = req.client_context.clone().unwrap_or_default();
    let role = req.rolespec().role;
    let server = req.server_id.clone();
    let resp = agent.assume_role(req);
    let prompt_notice = tokio::time::sleep(PROMPT_NOTICE_DELAY);
    let long_attempt = tokio::time::sleep(LONG_ATTEMPT_DURATION);
    tokio::pin!(resp, prompt_notice, long_attempt);
    let (mut prompt_noticed, mut long_noticed) = (!may_prompt, !long_attempt_notice);
    loop {
        tokio::select! {
            retval = &mut resp => return retval,
            _ = &mut prompt_notice, if !prompt_noticed => {
                prompt_noticed = true;
                let tools = tools_summary(&[]);
                crate::terminal::send(&context_lines(&server, &role, &context, Prompt::MaybeDialog, None, tools.as_deref())).await;
            }
            _ = &mut long_attempt, if !long_noticed => {
                long_noticed = true;
                let product = env!("CARGO_PKG_NAME");
                crate::terminal::send(&format!(":: {product} :: Waiting for AWS credentials from your remote server...")).await;
            }
        }
    }
}

/// The agent's authorization refusal in `status`, worded for the terminal.
pub fn refusal_message(status: &tonic::Status) -> Option<String> {
    crate::proto::AuthorizationError::from_status(status).map(|e| e.user_message())
}

/// Whether `status` asks a pre-fetch to stop until the command next needs credentials.
pub fn is_presence_required(status: &tonic::Status) -> bool {
    crate::proto::AuthorizationError::from_status(status)
        .is_some_and(|e| e.reason() == crate::proto::authorization_error::Reason::PresenceRequired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_lines() {
        let context = crate::proto::ClientContext {
            intent: Some(crate::proto::client_context::Intent::Exec(
                crate::proto::ExecIntent {
                    command: vec![b"terraform".to_vec(), b"apply".to_vec()],
                    mode: "ecs".to_owned(),
                    prefetch: false,
                },
            )),
            cwd: b"/home/u/src/infra".to_vec(),
            auto_config_path: vec![],
            env_names: vec![],
            authorization_response: None,
        };
        let lines = context_lines(
            "contoso",
            "123456789012/Admin",
            &context,
            Prompt::MaybeDialog,
            None,
            Some("ai-agent (process:claude)"),
        );
        assert!(!lines.contains("identity:"));
        assert!(lines.contains("ai-agent (process:claude)\n"), "{lines}");
        assert!(
            lines.starts_with(
                ":: mairu :: Authorization may be required: 123456789012/Admin on contoso\n"
            ),
            "{lines}"
        );
        assert!(lines.contains(":: mairu ::   command: terraform apply\n"));
        assert!(lines.contains(":: mairu ::   cwd:     /home/u/src/infra\n"));
        assert!(lines.ends_with(":: mairu :: Approve in the system dialog if one appears.\n"));
        let lines = context_lines(
            "contoso",
            "admin",
            &context,
            Prompt::Password,
            Some("arn:aws:sts::999999999999:assumed-role/Admin/alice"),
            None,
        );
        assert!(
            lines.starts_with(
                ":: mairu :: Authorization required: admin on contoso\n:: mairu ::   identity: 999999999999 assumed-role/Admin\n:: mairu ::   command: terraform apply\n"
            ),
            "{lines}"
        );
        assert!(lines.ends_with(":: mairu :: Enter your password below.\n"));
    }

    #[test]
    fn test_refusal_message() {
        let status = crate::proto::AuthorizationError::new(
            crate::proto::authorization_error::Reason::Denied,
            "nope",
        )
        .into_status();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert!(refusal_message(&status).unwrap().contains("nope"));
        assert!(!is_presence_required(&status));
        let status = crate::proto::AuthorizationError::new(
            crate::proto::authorization_error::Reason::PresenceRequired,
            "",
        )
        .into_status();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(is_presence_required(&status));
        assert!(refusal_message(&tonic::Status::permission_denied("plain")).is_none());

        let mut gate2 = crate::proto::AuthorizationError::new(
            crate::proto::authorization_error::Reason::Denied,
            "",
        );
        gate2.gate = crate::proto::GATE_USE_CREDENTIALS.to_owned();
        gate2.caller_arn = "arn:aws:sts::999999999999:assumed-role/Admin/alice".to_owned();
        assert_eq!(
            refusal_message(&gate2.into_status()).unwrap(),
            "refused at use-credentials: authorization was denied, or the dialog was dismissed (credentials of arn:aws:sts::999999999999:assumed-role/Admin/alice)"
        );
    }
}
