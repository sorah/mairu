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
