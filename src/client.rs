/// Client for Mairu API (Credentials Vendor HTTP API)
///
/// Note: See agent.rs for mairu agent client
pub struct Client {
    pub server_id: String,
    pub url: url::Url,
    bearer_token: secrecy::SecretString,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("url", &self.url.as_str())
            .finish()
    }
}

impl From<crate::token::ServerToken> for Client {
    fn from(token: crate::token::ServerToken) -> Client {
        Client::from(&token)
    }
}

impl From<&crate::token::ServerToken> for Client {
    fn from(token: &crate::token::ServerToken) -> Client {
        Client {
            server_id: token.server.id().to_owned(),
            url: token.server.url.clone(),
            bearer_token: token.access_token.clone(),
        }
    }
}

impl Client {
    #[tracing::instrument]
    pub async fn assume_role(&self, role: &str) -> crate::Result<AssumeRoleResponse> {
        use secrecy::ExposeSecret;
        let req = AssumeRoleRequest { role };
        let url = self.url.join("assume-role")?;

        tracing::debug!(req = ?req, url = %url, server_id = &self.server_id, "requesting");
        let resp = http()
            .post(url.clone())
            .bearer_auth(self.bearer_token.expose_secret())
            .header(reqwest::header::ACCEPT, "application/json")
            .body(serde_json::to_vec(&req)?)
            .send()
            .await?;

        if let Err(e) = resp.error_for_status_ref() {
            let e1 = crate::Error::ApiError {
                url: url.clone(),
                status_code: e.status().unwrap(),
                message: resp.text().await.unwrap_or_default(),
            };
            tracing::error!(req = ?req, url = %url, server_id = &self.server_id, err0 = ?e, err = %e1, "assume-role response was not ok");
            return Err(e1);
        }

        let credentials = resp.json::<AssumeRoleResponse>().await?;
        tracing::debug!(req = ?req, url = %url, server_id = &self.server_id, credentials = ?credentials, "response");
        Ok(credentials)
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
struct AssumeRoleRequest<'a> {
    role: &'a str,
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

fn http() -> reqwest::Client {
    static HTTP: once_cell::sync::OnceCell<reqwest::Client> = once_cell::sync::OnceCell::new();
    HTTP.get_or_init(|| {
        reqwest::ClientBuilder::new()
            .user_agent(format!(
                "{}/{}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .unwrap()
    })
    .clone()
}
