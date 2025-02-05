pub(crate) trait CredentialVendor {
    fn assume_role(
        &self,
        role: &str,
    ) -> impl std::future::Future<Output = crate::Result<crate::client::AssumeRoleResponse>> + Send;

    fn list_roles(
        &self,
    ) -> impl std::future::Future<Output = crate::Result<crate::client::ListRolesResponse>> + Send;
}

pub(crate) enum CredentialClient {
    Api(crate::api_client::Client),
    AwsSso(crate::awssso_client::Client),
}

impl CredentialVendor for CredentialClient {
    async fn assume_role(&self, role: &str) -> crate::Result<crate::client::AssumeRoleResponse> {
        match self {
            CredentialClient::Api(c) => c.assume_role(role).await,
            CredentialClient::AwsSso(c) => c.assume_role(role).await,
        }
    }

    async fn list_roles(&self) -> crate::Result<crate::client::ListRolesResponse> {
        match self {
            CredentialClient::Api(c) => c.list_roles().await,
            CredentialClient::AwsSso(c) => c.list_roles().await,
        }
    }
}

pub(crate) fn make_credential_vendor(
    session: &crate::session_manager::Session,
) -> crate::Result<CredentialClient> {
    if session.token.server.aws_sso.is_some() {
        Ok(CredentialClient::AwsSso(
            crate::awssso_client::Client::try_from(session.token.as_ref())?,
        ))
    } else {
        Ok(CredentialClient::Api(crate::api_client::Client::from(
            session.token.as_ref(),
        )))
    }
}

/// https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AssumeRoleResponse {
    pub version: i64,
    pub access_key_id: String,
    pub secret_access_key: secrecy::SecretString,
    pub session_token: Option<String>,
    pub expiration: chrono::DateTime<chrono::Utc>,

    #[serde(default)]
    pub mairu: AssumeRoleResponseMairuExt,
}

impl From<&AssumeRoleResponse> for crate::proto::AssumeRoleResponse {
    fn from(aws: &AssumeRoleResponse) -> crate::proto::AssumeRoleResponse {
        use secrecy::ExposeSecret;
        crate::proto::AssumeRoleResponse {
            credentials: Some(crate::proto::Credentials {
                version: aws.version,
                access_key_id: aws.access_key_id.clone(),
                secret_access_key: aws.secret_access_key.expose_secret().to_owned(),
                session_token: aws.session_token.clone().unwrap_or_default(),
                expiration: Some(std::time::SystemTime::from(aws.expiration).into()),
            }),
        }
    }
}

#[derive(Clone, Default, Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AssumeRoleResponseMairuExt {
    #[serde(default)]
    pub no_cache: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ListRolesResponse {
    pub roles: Vec<ListRolesItem>,
}

impl ListRolesResponse {
    pub fn to_proto(
        &self,
        server: &crate::config::Server,
    ) -> crate::proto::list_roles_response::Item {
        crate::proto::list_roles_response::Item {
            server_id: server.id().to_owned(),
            server_url: server.url.to_string(),
            logged_in: true,
            roles: self
                .roles
                .iter()
                .map(crate::proto::list_roles_response::item::Role::from)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ListRolesItem {
    pub name: String,
    pub description: Option<String>,
}

impl From<&ListRolesItem> for crate::proto::list_roles_response::item::Role {
    fn from(role: &ListRolesItem) -> crate::proto::list_roles_response::item::Role {
        crate::proto::list_roles_response::item::Role {
            name: role.name.clone(),
            description: role.description.clone().unwrap_or_default(),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid Argument: {0}")]
    InvalidArgument(String, #[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("Unauthenticated: {0}")]
    Unauthenticated(String, #[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("Permission denied: {0}")]
    PermissionDenied(String, #[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String, #[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("Not found: {0}")]
    NotFound(String, #[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("Unknown: {0} ({1})")]
    Unknown(String, #[source] Box<dyn std::error::Error + Send + Sync>),
}

pub(crate) fn http() -> reqwest::Client {
    static HTTP: once_cell::sync::OnceCell<reqwest::Client> = once_cell::sync::OnceCell::new();
    HTTP.get_or_init(|| {
        reqwest::ClientBuilder::new()
            .user_agent(format!(
                "{}/{}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            ))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    })
    .clone()
}
