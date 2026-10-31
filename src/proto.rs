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
            | Reason::CheckPending => tonic::Code::FailedPrecondition,
            Reason::Unspecified
            | Reason::UnverifiedPeer
            | Reason::Denied
            | Reason::Forbidden
            | Reason::NotPermitted => tonic::Code::PermissionDenied,
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
