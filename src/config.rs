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

pub fn log_dir() -> std::path::PathBuf {
    match std::env::var("XDG_STATE_HOME") {
        Ok(d) => std::path::PathBuf::from(d),
        Err(_) => std::path::PathBuf::from(
            std::env::var("HOME").expect("No $HOME environment variable present"),
        )
        .join(".local")
        .join("state"),
    }
    .join(env!("CARGO_PKG_NAME"))
    .join("log")
}

pub fn log_dir_mkpath() -> std::io::Result<std::path::PathBuf> {
    let dir = log_dir();
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
    id: Option<String>,
    pub oauth: Option<ServerOAuth>,
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
        let mut d = tokio::fs::read_dir(config_dir().join("servers.d"))
            .await
            .map_err(|e| crate::Error::ConfigError(format!("Can't list servers.d: {}", e)))?;
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

    #[inline]
    pub fn id(&self) -> &str {
        self.id.as_deref().unwrap_or_else(|| self.url.as_str())
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
}

impl std::str::FromStr for OAuthGrantType {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<OAuthGrantType, crate::Error> {
        match s {
            "code" => Ok(OAuthGrantType::Code),
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
    pub device_grant: Option<ServerDeviceGrant>,
}

fn default_oauth_scope() -> Vec<String> {
    vec!["profile".to_owned()]
}

impl ServerOAuth {
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.code_grant.is_none() && self.device_grant.is_none() {
            return Err(crate::Error::ConfigError(
                "Either oauth.code_grant or oauth.device_grant must be provided, but absent"
                    .to_owned(),
            ));
        }
        if match self.default_grant_type {
            None => false,
            Some(OAuthGrantType::Code) => self.code_grant.is_none(),
        } {
            return Err(crate::Error::ConfigError(
                "default_grant_type is specified but its configuration is not given".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn default_grant_type(&self) -> OAuthGrantType {
        self.default_grant_type.unwrap_or_else(|| {
            if self.code_grant.is_some() {
                return OAuthGrantType::Code;
            }
            if self.device_grant.is_some() {
                // TODO: implement
            }
            unreachable!();
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ServerCodeGrant {
    pub authorization_endpoint: Option<url::Url>,
    pub local_port: Option<u16>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ServerDeviceGrant {
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
