pub fn config_dir() -> std::path::PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map(|x| x.into())
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(
                std::env::var("HOME").expect("No $HOME environment variable present"),
            )
            .join(".config")
        })
        .join(env!("CARGO_PKG_NAME"))
}

pub fn state_dir() -> std::path::PathBuf {
    match std::env::var("XDG_STATE_HOME") {
        Ok(d) => std::path::PathBuf::from(d),
        Err(_) => std::path::PathBuf::from(
            std::env::var("HOME").expect("No $HOME environment variable present"),
        )
        .join(".local")
        .join("state"),
    }
    .join(env!("CARGO_PKG_NAME"))
}

pub fn log_dir() -> std::path::PathBuf {
    state_dir().join("log")
}

pub fn cache_dir() -> std::path::PathBuf {
    state_dir().join("cache")
}

pub fn trust_dir() -> std::path::PathBuf {
    state_dir().join("trust")
}

pub fn log_dir_mkpath() -> std::io::Result<std::path::PathBuf> {
    let dir = log_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn cache_dir_mkpath() -> std::io::Result<std::path::PathBuf> {
    let dir = cache_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn trust_dir_mkpath() -> std::io::Result<std::path::PathBuf> {
    let dir = trust_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn runtime_dir() -> std::path::PathBuf {
    match std::env::var("XDG_RUNTIME_DIR") {
        Ok(d) => std::path::PathBuf::from(d).join(env!("CARGO_PKG_NAME")),
        Err(_) => config_dir().join("run"),
    }
}
pub fn runtime_dir_mkpath() -> std::io::Result<std::path::PathBuf> {
    let dir = runtime_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn socket_path() -> std::path::PathBuf {
    std::env::var("MAIRU_AGENT_SOCK")
        .map(|x| x.into())
        .unwrap_or_else(|_| {
            runtime_dir_mkpath()
                .unwrap()
                .join(format!("{}-agent.sock", env!("CARGO_PKG_NAME")))
        })
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Server {
    #[serde(skip)]
    pub config_path: std::path::PathBuf,

    pub url: url::Url,
    pub(crate) id: Option<String>,
    pub oauth: Option<ServerOAuth>,
    pub aws_sso: Option<ServerAwsSso>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("id", &self.id)
            .field("url", &self.url.as_str())
            .field("config_path", &self.config_path)
            .finish()
    }
}

impl Server {
    pub async fn find_from_fs(query: &str) -> crate::Result<Self> {
        let mut d = match tokio::fs::read_dir(config_dir().join("servers.d")).await {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(err = ?e, "servers.d not found");
                return Err(crate::Error::UserError(format!(
                    "No server configuration found for: {}",
                    query
                )));
            }
            Err(e) => {
                return Err(crate::Error::ConfigError(format!(
                    "Can't list servers.d: {}",
                    e
                )));
            }
        };
        let mut id_result = None;
        let mut url_result = vec![];
        while let Some(entry) = d.next_entry().await? {
            match Self::read_from_file(&entry.path()).await {
                Ok(c) => {
                    if c.id.as_deref() == Some(query) {
                        if id_result.is_some() {
                            return Err(crate::Error::ConfigError(format!(
                                "server id is duplicated: {}",
                                query
                            )));
                        }
                        id_result = Some(c);
                    } else if c.url.to_string() == query {
                        url_result.push(c);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        path = %entry.path().display(),
                        error = ?e,
                        "Error while enumerating server configuration",
                    );
                }
            }
        }
        if let Some(s) = id_result {
            return Ok(s);
        }
        match url_result.len().cmp(&1) {
            std::cmp::Ordering::Equal => {
                return Ok(url_result.pop().unwrap());
            }
            std::cmp::Ordering::Greater => {
                return Err(crate::Error::UserError(format!(
                "server is ambiguous (multiple configuration for the same URL found, use .id to specify): {}",
                query
            )));
            }
            std::cmp::Ordering::Less => {}
        }
        Err(crate::Error::UserError(format!(
            "No server configuration found for: {}",
            query
        )))
    }

    pub async fn read_from_file(path: impl AsRef<std::path::Path>) -> crate::Result<Self> {
        let data = tokio::fs::read(&path).await?;
        let mut parsed: Self = serde_json::from_slice(&data)?;
        parsed.config_path = path.as_ref().into();

        // Load client cache as .oauth when aws_sso
        if parsed.oauth.is_none() && parsed.aws_sso.is_some() {
            // TODO: ignore parse failure (treat as cache miss)
            match AwsSsoClientRegistrationCache::read_from_file(
                &parsed.aws_sso_client_registration_cache_key()?,
            )
            .await?
            {
                Some(cache) if !cache.is_expired() => {
                    parsed.oauth = Some(cache.into_server_oauth(parsed.aws_sso.as_ref().unwrap()));
                }
                Some(_) => {
                    tracing::debug!(server = ?parsed, "AwsSsoClientRegistrationCache is expired");
                }
                None => {
                    tracing::debug!(server = ?parsed, "AwsSsoClientRegistrationCache is missing");
                }
            }
        }

        Ok(parsed)
    }

    // pub fn from_json_str(data: &str) -> serde_json::Result<Self> {
    //     serde_json::from_str(data)
    // }

    pub fn validate(&self) -> crate::Result<()> {
        if self.oauth.is_none() {
            return Err(crate::Error::ConfigError(
                "oauth configuration is missing".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn try_oauth_code_grant(&self) -> crate::Result<(&ServerOAuth, &ServerCodeGrant)> {
        let Some(oauth) = self.oauth.as_ref() else {
            return Err(crate::Error::ConfigError(format!(
                "Server '{}' is missing OAuth 2.0 client configuration",
                self.id()
            )));
        };
        let Some(code_grant) = oauth.code_grant.as_ref() else {
            return Err(crate::Error::ConfigError(format!(
                "Server '{}' is missing OAuth 2.0 Authorization Code Grant configuration",
                self.id()
            )));
        };
        Ok((oauth, code_grant))
    }

    pub fn try_oauth_device_code_grant(
        &self,
    ) -> crate::Result<(&ServerOAuth, &ServerDeviceCodeGrant)> {
        let Some(oauth) = self.oauth.as_ref() else {
            return Err(crate::Error::ConfigError(format!(
                "Server '{}' is missing OAuth 2.0 client configuration",
                self.id()
            )));
        };
        match oauth.device_code_grant {
            Some(ref grant) => Ok((oauth, grant)),
            None => Err(crate::Error::ConfigError(format!(
                "Server '{}' is missing OAuth 2.0 Device Code Grant configuration",
                self.id()
            ))),
        }
    }

    pub fn try_oauth_awssso(&self) -> crate::Result<&ServerOAuth> {
        if self.aws_sso.is_none() {
            return Err(crate::Error::ConfigError(format!(
                "Server '{}' is not aws_sso",
                self.id()
            )));
        }
        let Some(oauth) = self.oauth.as_ref() else {
            return Err(crate::Error::ConfigError(format!(
                "Server '{}' is missing OAuth 2.0 client registration",
                self.id()
            )));
        };
        if !matches!(oauth.default_grant_type, Some(OAuthGrantType::DeviceCode)) {
            return Err(crate::Error::ConfigError(format!(
                "Server '{}' client registration is not default_grant_type=aws_sso_device_code",
                self.id()
            )));
        }
        Ok(oauth)
    }

    #[inline]
    pub fn id(&self) -> &str {
        self.id.as_deref().unwrap_or_else(|| self.url.as_str())
    }

    pub(crate) fn aws_sso_client_registration_cache_key(&self) -> crate::Result<String> {
        use base64::Engine;
        use sha2::Digest;

        let sso = self.aws_sso.as_ref().ok_or_else(|| {
            crate::Error::ConfigError(format!(
                "Server '{}' is missing AWS IAM Identity Center (aws_sso) configuration",
                self.id()
            ))
        })?;
        let hash = sha2::Sha256::new()
            .chain_update(b"v0\0\0")
            .chain_update(self.id())
            .chain_update(b"\0\0")
            .chain_update(self.url.to_string())
            .chain_update(b"\0\0")
            .chain_update(&sso.region)
            .chain_update(b"\0\0")
            .chain_update(sso.scope.join(" "))
            .finalize();
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash))
    }

    pub async fn ensure_aws_sso_oauth_client_registration(
        &mut self,
        refresh: bool,
    ) -> crate::Result<()> {
        if self.aws_sso.is_none() {
            return Err(crate::Error::ConfigError(format!(
                "Server '{}' is not aws_sso",
                self.id()
            )));
        }
        if self.oauth.is_some() && !refresh {
            return Ok(());
        }
        tracing::info!(server_id = ?self.id(), server_url = %self.url, refresh = ?refresh, "performing AWS SSO Client registration");
        let registration = crate::ext_awssso::register_client(self).await.map_err(|e| {
            tracing::error!(err = ?e, server_id = self.id(), "error while sso-oidc:RegisterClient");
            e
        })?;
        registration
            .save_to_file(self.aws_sso_client_registration_cache_key().unwrap().as_ref())
            .await.map_err(|e| {
            tracing::error!(err = ?e, server_id = self.id(), "error while saving AwsSsoClientRegistrationCache file");
            e
        })?;
        self.oauth = Some(registration.into_server_oauth(self.aws_sso.as_ref().unwrap()));
        Ok(())
    }
}

impl TryFrom<crate::proto::GetServerResponse> for Server {
    type Error = serde_json::Error;
    fn try_from(resp: crate::proto::GetServerResponse) -> Result<Server, serde_json::Error> {
        serde_json::from_str(&resp.json)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum OAuthGrantType {
    Code,
    DeviceCode,
}

impl std::str::FromStr for OAuthGrantType {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<OAuthGrantType, crate::Error> {
        match s {
            "code" => Ok(OAuthGrantType::Code),
            "device_code" => Ok(OAuthGrantType::DeviceCode),
            "aws_sso" => Ok(OAuthGrantType::DeviceCode),
            _ => Err(crate::Error::UserError(
                "unknown oauth_grant_type".to_owned(),
            )),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ServerOAuth {
    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret: Option<String>,
    pub token_endpoint: Option<url::Url>,
    #[serde(default = "default_oauth_scope")]
    pub scope: Vec<String>,
    default_grant_type: Option<OAuthGrantType>,
    pub code_grant: Option<ServerCodeGrant>,
    pub device_code_grant: Option<ServerDeviceCodeGrant>,

    /// Expiration time of dynamically registered OAuth2 client registration, such as AWS SSO
    /// clients.
    pub client_expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn default_oauth_scope() -> Vec<String> {
    vec!["profile".to_owned()]
}

impl ServerOAuth {
    pub(crate) fn validate(&self) -> Result<(), crate::Error> {
        if self.code_grant.is_none() && self.device_code_grant.is_none() {
            return Err(crate::Error::ConfigError(
                "Either oauth.code_grant or oauth.device_code_grant must be provided, but absent"
                    .to_owned(),
            ));
        }
        if match self.default_grant_type {
            None => false,
            Some(OAuthGrantType::DeviceCode) => self.device_code_grant.is_none(),
            Some(OAuthGrantType::Code) => self.code_grant.is_none(),
        } {
            return Err(crate::Error::ConfigError(
                "default_grant_type is specified but its configuration is not given".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn default_grant_type(&self) -> Result<OAuthGrantType, crate::Error> {
        match self.default_grant_type {
            Some(x) => Ok(x),
            None => {
                if self.code_grant.is_some() {
                    return Ok(OAuthGrantType::Code);
                }
                if self.device_code_grant.is_some() {
                    return Ok(OAuthGrantType::DeviceCode);
                }
                Err(crate::Error::ConfigError(
                    "cannot determine default grant_type".to_string(),
                ))
            }
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ServerCodeGrant {
    pub authorization_endpoint: Option<url::Url>,
    pub local_port: Option<u16>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ServerDeviceCodeGrant {
    pub device_authorization_endpoint: Option<url::Url>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMode {
    Ecs,
    Static,
}

impl std::str::FromStr for ProviderMode {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<ProviderMode, crate::Error> {
        match s {
            "ecs" => Ok(ProviderMode::Ecs),
            "static" => Ok(ProviderMode::Static),
            _ => Err(crate::Error::UserError("unknown mode".to_owned())),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ServerAwsSso {
    pub region: String,
    #[serde(default = "default_aws_sso_scope")]
    pub scope: Vec<String>,
}

fn default_aws_sso_scope() -> Vec<String> {
    vec!["sso:account:access".to_owned()]
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct AwsSsoClientRegistrationCache {
    pub id: String,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub client_id: String,
    pub client_secret: String,
}

impl AwsSsoClientRegistrationCache {
    fn into_server_oauth(self, sso: &ServerAwsSso) -> ServerOAuth {
        ServerOAuth {
            default_grant_type: Some(crate::config::OAuthGrantType::DeviceCode),
            client_id: self.client_id,
            client_secret: Some(self.client_secret),
            token_endpoint: None,
            scope: sso.scope.clone(),
            code_grant: None,
            device_code_grant: None,
            client_expires_at: Some(self.expires_at),
        }
    }
}

impl AwsSsoClientRegistrationCache {
    pub async fn read_from_file(key: &str) -> crate::Result<Option<Self>> {
        let path = cache_dir().join(format!("awssso_c.{key}.json"));
        if !tokio::fs::try_exists(&path).await? {
            return Ok(None);
        }
        let data = tokio::fs::read(&path).await?;
        let parsed: Self = serde_json::from_slice(&data)?;
        Ok(Some(parsed))
    }

    pub async fn save_to_file(&self, key: &str) -> crate::Result<()> {
        use tokio::io::AsyncWriteExt;
        let path = cache_dir().join(format!("awssso_c.{key}.json"));
        tracing::debug!(path = %path.display(), "saving AwsSsoClientRegistrationCache");

        let data = serde_json::to_string_pretty(&self)?;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .await?;
        file.write_all(data.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        Ok(())
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at <= chrono::Utc::now()
    }

    pub fn from_aws_sso(
        server: &Server,
        resp: &aws_sdk_ssooidc::operation::register_client::RegisterClientOutput,
    ) -> crate::Result<Self> {
        Ok(AwsSsoClientRegistrationCache {
            id: server.id().to_owned(),
            issued_at: chrono::DateTime::from_timestamp(resp.client_id_issued_at, 0)
                .ok_or_else(|| crate::Error::UserError("invalid client_id_issued_at".to_owned()))?,
            expires_at: chrono::DateTime::from_timestamp(resp.client_secret_expires_at, 0)
                .ok_or_else(|| {
                    crate::Error::UserError("invalid client_secret_issued_at".to_owned())
                })?,
            client_id: resp
                .client_id
                .clone()
                .ok_or_else(|| crate::Error::UserError("missing client_id".to_owned()))?,
            client_secret: resp
                .client_secret
                .clone()
                .ok_or_else(|| crate::Error::UserError("missing client_secret".to_owned()))?,
        })
    }
}
