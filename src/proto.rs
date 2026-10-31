tonic::include_proto!("mairu");

pub mod platform {
    tonic::include_proto!("mairu.platform");

    impl AuthorizeResponse {
        pub fn unavailable(reason: &str, detail: impl Into<String>) -> Self {
            Self {
                result: authorize_response::Result::Unavailable.into(),
                reason: reason.to_owned(),
                detail: detail.into(),
            }
        }
    }

    /// Bytes a notification title is cut to.
    pub const MAX_NOTIFICATION_TITLE: usize = 256;
    /// Bytes a notification body is cut to.
    pub const MAX_NOTIFICATION_BODY: usize = 1024;

    impl OpenUrlRequest {
        /// Only http(s) URLs are opened, so a URL cannot name a local file or an application.
        pub fn checked_url(&self) -> Result<url::Url, String> {
            let parsed = url::Url::parse(&self.url).map_err(|e| format!("invalid URL: {e}"))?;
            match parsed.scheme() {
                "http" | "https" => Ok(parsed),
                scheme => Err(format!("refusing to open a {scheme}: URL")),
            }
        }
    }

    impl OpenUrlResponse {
        pub fn failed(detail: impl Into<String>) -> Self {
            Self {
                opened: false,
                detail: detail.into(),
            }
        }
    }

    impl NotifyRequest {
        /// Cuts the title and body to [`MAX_NOTIFICATION_TITLE`] and [`MAX_NOTIFICATION_BODY`] bytes.
        pub fn truncate(&mut self) {
            truncate_utf8(&mut self.title, MAX_NOTIFICATION_TITLE);
            truncate_utf8(&mut self.body, MAX_NOTIFICATION_BODY);
        }
    }

    impl SessionHint {
        /// This process's desktop session, from its environment.
        pub fn current() -> Self {
            let var = |name: &str| std::env::var(name).unwrap_or_default();
            Self {
                display: var("DISPLAY"),
                wayland_display: var("WAYLAND_DISPLAY"),
                dbus_session_bus_address: var("DBUS_SESSION_BUS_ADDRESS"),
                ssh: ["SSH_CONNECTION", "SSH_TTY"]
                    .into_iter()
                    .any(|v| std::env::var_os(v).is_some_and(|s| !s.is_empty())),
            }
        }

        /// Why nothing should be shown in this session: SSH without a display, or no display at all.
        pub fn refusal(&self) -> Option<&'static str> {
            if !self.display.is_empty() || !self.wayland_display.is_empty() {
                None
            } else if self.ssh {
                Some("the client is in an SSH session without a display")
            } else {
                Some("the client has no display")
            }
        }
    }

    fn truncate_utf8(s: &mut String, max: usize) {
        if s.len() <= max {
            return;
        }
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_checked_url() {
            let req = |url: &str| OpenUrlRequest {
                url: url.to_owned(),
                session: None,
            };
            assert!(
                req("https://example.com/device?code=ABCD")
                    .checked_url()
                    .is_ok()
            );
            assert!(req("http://localhost:8080/").checked_url().is_ok());
            assert!(req("file:///etc/passwd").checked_url().is_err());
            assert!(req("x-apple.systempreferences:").checked_url().is_err());
            assert!(req("javascript:alert(1)").checked_url().is_err());
            assert!(req("not a url").checked_url().is_err());
        }

        #[test]
        fn test_notify_truncate() {
            let mut req = NotifyRequest {
                title: "t".repeat(300),
                body: "\u{3042}".repeat(400),
                ..Default::default()
            };
            req.truncate();
            assert_eq!(req.title.len(), MAX_NOTIFICATION_TITLE);
            // 3-byte characters: cut at the last boundary below the limit.
            assert_eq!(req.body.len(), 1023);
            assert!(req.body.chars().all(|c| c == '\u{3042}'));
            let mut short = NotifyRequest {
                title: "hello".to_owned(),
                body: "world".to_owned(),
                ..Default::default()
            };
            short.truncate();
            assert_eq!(
                (short.title.as_str(), short.body.as_str()),
                ("hello", "world")
            );
        }

        #[test]
        fn test_session_hint_refusal() {
            let hint = |display: &str, wayland: &str, ssh: bool| SessionHint {
                display: display.to_owned(),
                wayland_display: wayland.to_owned(),
                dbus_session_bus_address: String::new(),
                ssh,
            };
            assert_eq!(hint(":0", "", false).refusal(), None);
            assert_eq!(hint("", "wayland-0", true).refusal(), None);
            assert_eq!(hint(":10", "", true).refusal(), None);
            assert!(hint("", "", true).refusal().unwrap().contains("SSH"));
            assert!(
                hint("", "", false)
                    .refusal()
                    .unwrap()
                    .contains("no display")
            );
        }
    }
}

impl Credentials {
    pub fn expiration(
        &self,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, prost_types::TimestampError> {
        match self.expiration {
            None => Ok(None),
            Some(ref e) => Ok(Some(std::time::SystemTime::try_from(*e).map(
                |st| -> chrono::DateTime<chrono::Utc> { chrono::DateTime::from(st) },
            )?)),
        }
    }
}

impl Session {
    pub fn expiration(
        &self,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, prost_types::TimestampError> {
        match self.expires_at {
            None => Ok(None),
            Some(ref e) => Ok(Some(std::time::SystemTime::try_from(*e).map(
                |st| -> chrono::DateTime<chrono::Utc> { chrono::DateTime::from(st) },
            )?)),
        }
    }
}

/// `AuthorizationError.gate` of gate 1, before anything is fetched.
pub const GATE_ASSUME_ROLE: &str = "assume-role";
/// `AuthorizationError.gate` of gate 2, before credentials are vended.
pub const GATE_USE_CREDENTIALS: &str = "use-credentials";

impl AuthorizationError {
    pub fn new(reason: authorization_error::Reason, detail: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            detail: detail.into(),
            policy_ids: vec![],
            tools: vec![],
            gate: String::new(),
            caller_arn: String::new(),
            challenge: None,
        }
    }

    /// `REASON_CHALLENGE`: the client signs `challenge` and retries the same request.
    pub fn challenge(challenge: AuthorizationChallenge) -> Self {
        Self {
            challenge: Some(challenge),
            ..Self::new(authorization_error::Reason::Challenge, "")
        }
    }

    pub fn unverified_peer(detail: impl Into<String>) -> Self {
        Self::new(authorization_error::Reason::UnverifiedPeer, detail)
    }

    /// A non-OK status carrying this error in its binary details. The message repeats the detail, or the summary
    /// without one, for clients that do not decode details.
    pub fn into_status(self) -> tonic::Status {
        use authorization_error::Reason;
        use prost::Message;
        let code = match self.reason() {
            Reason::Unavailable
            | Reason::NoAuthenticationAgent
            | Reason::PresenceRequired
            | Reason::CheckPending
            | Reason::Challenge => tonic::Code::FailedPrecondition,
            Reason::Unspecified
            | Reason::UnverifiedPeer
            | Reason::Denied
            | Reason::Forbidden
            | Reason::NotPermitted
            | Reason::InvalidResponse => tonic::Code::PermissionDenied,
        };
        let message = if self.detail.is_empty() {
            self.user_message()
        } else {
            self.detail.clone()
        };
        tonic::Status::with_details(code, message, self.encode_to_vec().into())
    }

    /// What a client prints for this refusal.
    pub fn user_message(&self) -> String {
        use authorization_error::Reason;
        let summary = match self.reason() {
            Reason::Unspecified | Reason::UnverifiedPeer => "the agent refused this request",
            Reason::Denied => "authorization was denied, or the dialog was dismissed",
            Reason::Forbidden => "refused by policy",
            Reason::NotPermitted => "no policy permits this role, even after a human check",
            // At gate 2 without a caller, the identity itself could not be obtained.
            Reason::Unavailable
                if self.gate == GATE_USE_CREDENTIALS && self.caller_arn.is_empty() =>
            {
                "the identity of the credentials could not be checked"
            }
            Reason::Unavailable => "no method could ask for approval",
            Reason::NoAuthenticationAgent => {
                "polkit has no authentication agent for this process, for example outside a desktop session"
            }
            Reason::PresenceRequired => "a fresh approval is required",
            Reason::CheckPending => "another human check is pending",
            Reason::Challenge => "a signature from your SSH agent is required",
            Reason::InvalidResponse => "the signature was refused",
        };
        let mut message = summary.to_owned();
        if !self.policy_ids.is_empty() {
            message.push_str(&format!(" (policies: {})", self.policy_ids.join(", ")));
        }
        if !self.detail.is_empty() {
            message.push_str(&format!(": {}", self.detail));
        }
        if !self.tools.is_empty() {
            message.push_str(&format!(" (tools: {})", self.tools.join(", ")));
        }
        if self.gate == GATE_USE_CREDENTIALS {
            if !self.caller_arn.is_empty() && !message.contains(&self.caller_arn) {
                message.push_str(&format!(" (credentials of {})", self.caller_arn));
            }
            message = format!("refused at {}: {message}", self.gate);
        }
        message
    }

    pub fn from_status(status: &tonic::Status) -> Option<Self> {
        use prost::Message;
        if status.code() == tonic::Code::Ok || status.details().is_empty() {
            return None;
        }
        Self::decode(status.details()).ok()
    }
}

impl Rolespec {
    pub fn base(&self) -> Rolespec {
        Rolespec {
            role: self.role.clone(),
            assume_role: None,
        }
    }
}

impl AssumeRoleRequest {
    pub fn rolespec(&self) -> Rolespec {
        match self.query {
            Some(assume_role_request::Query::Role(ref role)) => Rolespec {
                role: role.clone(),
                assume_role: None,
            },
            Some(assume_role_request::Query::Rolespec(ref rs)) => rs.clone(),
            None => Rolespec {
                role: String::new(),
                assume_role: None,
            },
        }
    }

    pub fn with_role(server_id: String, role: String, cached: bool) -> Self {
        Self {
            server_id,
            query: Some(assume_role_request::Query::Role(role)),
            cached,
            client_context: None,
        }
    }
}

#[cfg(feature = "cli")]
impl ExecEnvironment {
    pub(crate) unsafe fn apply(&self) {
        for name in self.remove_vars.iter() {
            unsafe {
                std::env::remove_var(name);
            }
        }
        for ExecEnvVar { name, value } in self.set_vars.iter() {
            unsafe {
                std::env::set_var(name, value);
            }
        }
    }
}

#[cfg(feature = "cli")]
#[derive(zeroize::ZeroizeOnDrop)]
pub(crate) enum ExecEnvironmentAction {
    Set(#[zeroize(skip)] &'static str, String),
    Remove(#[zeroize(skip)] &'static str),
}

#[cfg(feature = "cli")]
impl FromIterator<ExecEnvironmentAction> for ExecEnvironment {
    fn from_iter<I: IntoIterator<Item = ExecEnvironmentAction>>(iter: I) -> Self {
        let mut set_vars = vec![];
        let mut remove_vars = vec![];

        for action in iter {
            match &action {
                ExecEnvironmentAction::Set(name, value) => set_vars.push(ExecEnvVar {
                    name: name.to_string(),
                    value: value.clone(),
                }),
                ExecEnvironmentAction::Remove(name) => remove_vars.push(name.to_string()),
            }
        }

        ExecEnvironment {
            set_vars,
            remove_vars,
        }
    }
}

#[cfg(feature = "cli")]
static EXEC_IPC_VERSION: u32 = 100u32;

#[cfg(feature = "cli")]
impl ExecIpcInformExecutorRequest {
    #[inline]
    pub(crate) fn ready(ready: crate::proto::exec_ipc_inform_executor_request::Ready) -> Self {
        crate::proto::ExecIpcInformExecutorRequest {
            version: EXEC_IPC_VERSION,
            result: Some(crate::proto::exec_ipc_inform_executor_request::Result::Ready(ready)),
        }
    }

    #[inline]
    pub(crate) fn failure(
        failure: crate::proto::exec_ipc_inform_executor_request::Failure,
    ) -> Self {
        crate::proto::ExecIpcInformExecutorRequest {
            version: EXEC_IPC_VERSION,
            result: Some(crate::proto::exec_ipc_inform_executor_request::Result::Failure(failure)),
        }
    }

    pub(crate) fn into_std(
        self,
    ) -> Result<crate::proto::exec_ipc_inform_executor_request::Ready, crate::Error> {
        if self.version == 0 {
            return Err(crate::Error::SidecarError(
                "Invalid data from sidecar; version==0, sidecar may be unexpectedly died?"
                    .to_string(),
            ));
        }
        if self.version != EXEC_IPC_VERSION {
            return Err(crate::Error::SidecarError(
                "Invalid data from sidecar; wrong version, sidecar may be unexpectedly died?"
                    .to_string(),
            ));
        }
        match self.result {
            None => Err(crate::Error::SidecarError(
                "Invalid data from sidecar; missing result, sidecar may be unexpectedly died?"
                    .to_string(),
            )),
            Some(crate::proto::exec_ipc_inform_executor_request::Result::Failure(f)) => Err(
                crate::Error::SidecarError(format!("Error in Sidecar: {}", f.error_message)),
            ),
            Some(crate::proto::exec_ipc_inform_executor_request::Result::Ready(info)) => Ok(info),
        }
    }
}
