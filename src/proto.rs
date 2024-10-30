tonic::include_proto!("mairu");

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

impl ExecEnvironment {
    pub(crate) fn apply(&self) {
        for name in self.remove_vars.iter() {
            std::env::remove_var(name);
        }
        for ExecEnvVar { name, value } in self.set_vars.iter() {
            std::env::set_var(name, value);
        }
    }
}

#[derive(zeroize::ZeroizeOnDrop)]
pub(crate) enum ExecEnvironmentAction {
    Set(#[zeroize(skip)] &'static str, String),
    Remove(#[zeroize(skip)] &'static str),
}

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

static EXEC_IPC_VERSION: u32 = 100u32;

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
