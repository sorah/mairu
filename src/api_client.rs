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

impl crate::client::CredentialVendor for Client {
    #[tracing::instrument]
    async fn assume_role(&self, role: &str) -> crate::Result<crate::client::AssumeRoleResponse> {
        use secrecy::ExposeSecret;
        let req = AssumeRoleRequest { role };
        let url = self.url.join("assume-role")?;

        tracing::debug!(req = ?req, url = %url, server_id = &self.server_id, "requesting");
        let resp = crate::client::http()
            .post(url.clone())
            .bearer_auth(self.bearer_token.expose_secret())
            .header(reqwest::header::ACCEPT, "application/json")
            .body(serde_json::to_vec(&req)?)
            .send()
            .await?;

        if let Err(e) = resp.error_for_status_ref() {
            let status_code = e.status().unwrap();
            let message = resp.text().await.unwrap_or_default();
            tracing::error!(req = ?req, url = %url, server_id = &self.server_id, err0 = ?e, status_code  = ?status_code,  "assume-role response was not ok");
            let e1 = match status_code {
                reqwest::StatusCode::BAD_REQUEST => {
                    crate::client::Error::InvalidArgument(message, Box::new(e))
                }
                reqwest::StatusCode::UNAUTHORIZED => {
                    crate::client::Error::Unauthenticated(message, Box::new(e))
                }
                reqwest::StatusCode::FORBIDDEN => {
                    crate::client::Error::PermissionDenied(message, Box::new(e))
                }
                reqwest::StatusCode::TOO_MANY_REQUESTS => {
                    crate::client::Error::ResourceExhausted(message, Box::new(e))
                }
                reqwest::StatusCode::NOT_FOUND => {
                    crate::client::Error::NotFound(message, Box::new(e))
                }
                _ => crate::client::Error::Unknown(
                    format!("[{}] {}", status_code, message),
                    Box::new(e),
                ),
            };

            return Err(e1.into());
        }

        let credentials = resp.json::<crate::client::AssumeRoleResponse>().await?;
        //credentials.expiration = chrono::Utc::now() + chrono::TimeDelta::seconds(915);
        tracing::debug!(req = ?req, url = %url, server_id = &self.server_id, credentials = ?credentials, "response");
        Ok(credentials)
    }

    #[tracing::instrument]
    async fn list_roles(&self) -> crate::Result<crate::client::ListRolesResponse> {
        use secrecy::ExposeSecret;
        let url = self.url.join("roles")?;

        tracing::debug!(url = %url, server_id = &self.server_id, "requesting");
        let resp = crate::client::http()
            .get(url.clone())
            .bearer_auth(self.bearer_token.expose_secret())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;

        if let Err(e) = resp.error_for_status_ref() {
            let status_code = e.status().unwrap();
            let message = resp.text().await.unwrap_or_default();
            tracing::error!(url = %url, server_id = &self.server_id, err0 = ?e, status_code  = ?status_code,  "list_roles response was not ok");
            let e1 = match status_code {
                reqwest::StatusCode::BAD_REQUEST => {
                    crate::client::Error::InvalidArgument(message, Box::new(e))
                }
                reqwest::StatusCode::UNAUTHORIZED => {
                    crate::client::Error::Unauthenticated(message, Box::new(e))
                }
                reqwest::StatusCode::FORBIDDEN => {
                    crate::client::Error::PermissionDenied(message, Box::new(e))
                }
                reqwest::StatusCode::TOO_MANY_REQUESTS => {
                    crate::client::Error::ResourceExhausted(message, Box::new(e))
                }
                reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::METHOD_NOT_ALLOWED => {
                    return Ok(crate::client::ListRolesResponse { roles: vec![] });
                }
                _ => crate::client::Error::Unknown(
                    format!("[{}] {}", status_code, message),
                    Box::new(e),
                ),
            };

            return Err(e1.into());
        }

        let roles = resp.json::<crate::client::ListRolesResponse>().await?;
        tracing::debug!(url = %url, server_id = &self.server_id, roles = ?roles, "response");
        Ok(roles)
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
struct AssumeRoleRequest<'a> {
    role: &'a str,
}
