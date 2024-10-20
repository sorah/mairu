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
