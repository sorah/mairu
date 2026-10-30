tonic::include_proto!("mairu");

pub mod platform {
    tonic::include_proto!("mairu.platform");
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

impl AuthorizationError {
    pub fn unverified_peer(detail: impl Into<String>) -> Self {
        Self {
            reason: authorization_error::Reason::UnverifiedPeer.into(),
            detail: detail.into(),
        }
    }

    /// A non-OK status carrying this error in its binary details. The message repeats the detail for clients that
    /// do not decode details.
    pub fn into_status(self) -> tonic::Status {
        use prost::Message;
        let code = match self.reason() {
            authorization_error::Reason::UnverifiedPeer => tonic::Code::PermissionDenied,
            authorization_error::Reason::Unspecified => tonic::Code::PermissionDenied,
        };
        let message = self.detail.clone();
        tonic::Status::with_details(code, message, self.encode_to_vec().into())
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
