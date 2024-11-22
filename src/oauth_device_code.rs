#[derive(Debug)]
pub struct OAuthDeviceCodeFlow {
    pub handle: String,
    server: crate::config::Server,
    pub user_code: secrecy::SecretString,
    device_code: secrecy::SecretString,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub verification_uri: String,
    pub verification_uri_complete: Option<secrecy::SecretString>,
    pub interval: i32,
    //response: oauth2::StandardDeviceAuthorizationResponse,
}

impl From<&OAuthDeviceCodeFlow> for crate::proto::InitiateOAuthDeviceCodeResponse {
    fn from(flow: &OAuthDeviceCodeFlow) -> crate::proto::InitiateOAuthDeviceCodeResponse {
        use secrecy::ExposeSecret;
        crate::proto::InitiateOAuthDeviceCodeResponse {
            handle: flow.handle.clone(),
            user_code: flow.user_code.expose_secret().to_owned(),
            verification_uri: flow.verification_uri.clone(),
            verification_uri_complete: flow
                .verification_uri_complete
                .as_ref()
                .map(|x| x.expose_secret().to_owned())
                .unwrap_or_default(),
            interval: flow.interval,
            expires_at: Some(std::time::SystemTime::from(flow.expires_at).into()),
        }
    }
}

impl OAuthDeviceCodeFlow {
    pub async fn initiate(server: &crate::config::Server) -> crate::Result<Self> {
        let (oauth, grant) = server.try_oauth_device_code_grant()?;
        let handle = crate::utils::generate_flow_handle();
        tracing::info!(server = ?server, handle = ?handle, "Initiating OAuth 2.0 Device Code flow");

        // oauth2 crate doesn't allow non-standard response type
        let scopes = oauth.scope.join(" ");
        let resp = crate::client::http()
            .post(grant.device_authorization_endpoint.clone().ok_or_else(|| {
                crate::Error::ConfigError(format!(
                    "{} is missing device_authorization_endpoint",
                    server.id()
                ))
            })?)
            .header(reqwest::header::ACCEPT, "application/json")
            .basic_auth(&oauth.client_id, oauth.client_secret.as_ref())
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("scope", &scopes),
            ])
            .send()
            .await?;

        let status = resp.status();
        if status != reqwest::StatusCode::OK {
            let body = resp.bytes().await?;
            if body.is_empty() {
                return Err(crate::Error::AuthError(format!(
                    "server returned empty error; {status}"
                )));
            } else {
                let er: oauth2::basic::BasicErrorResponse = serde_json::from_slice(&body)?;
                tracing::debug!(response = ?er, "DeviceCodeErrorResponse");
                let be = er.error();
                return Err(crate::Error::AuthError(format!(
                    "oauth2 error {be}: {er:?}"
                )));
            }
        }
        let body: crate::ext_oauth2::CustomDeviceAuthorizationResponse = resp.json().await?;

        Ok(Self {
            handle,
            server: server.to_owned(),
            user_code: body.user_code,
            device_code: body.device_code,
            verification_uri: body.verification_uri,
            verification_uri_complete: body.verification_uri_complete,
            expires_at: chrono::Utc::now() + chrono::TimeDelta::seconds(body.expires_in as i64),
            interval: body
                .interval
                .max(crate::ext_oauth2::DEVICE_CODE_AUTH_INTERVAL_MIN),
        })
    }

    pub async fn complete(&self) -> crate::Result<crate::token::ServerToken> {
        use secrecy::ExposeSecret;
        let (oauth, _) = self.server.try_oauth_device_code_grant()?;
        tracing::info!(flow = ?self, "Completing OAuth 2.0 Device Code flow");

        // oauth2 crate doesn't allow sending request only once

        let req = crate::client::http()
            .post(oauth.token_endpoint.clone().ok_or_else(|| {
                crate::Error::ConfigError(format!("{} is missing token_endpoint", self.server.id()))
            })?)
            .header(reqwest::header::ACCEPT, "application/json")
            .basic_auth(&oauth.client_id, oauth.client_secret.as_ref())
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", self.device_code.expose_secret()),
            ])
            .build()?;
        tracing::debug!(req = ?req, "complete req");
        let resp = crate::client::http().execute(req).await?;

        let status = resp.status();
        if status != reqwest::StatusCode::OK {
            let body = resp.bytes().await?;
            if body.is_empty() {
                return Err(crate::Error::AuthError(format!(
                    "server returned empty error; {status}"
                )));
            } else {
                let er: oauth2::DeviceCodeErrorResponse = serde_json::from_slice(&body)?;
                tracing::debug!(response = ?er, "DeviceCodeErrorResponse");
                return match er.error() {
                    oauth2::DeviceCodeErrorResponseType::AuthorizationPending => {
                        Err(crate::Error::AuthNotReadyError { slow_down: false })
                    }
                    oauth2::DeviceCodeErrorResponseType::SlowDown => {
                        Err(crate::Error::AuthNotReadyError { slow_down: true })
                    }
                    oauth2::DeviceCodeErrorResponseType::AccessDenied => {
                        Err(crate::Error::AuthError(format!("access_denied: {er:?}")))
                    }
                    oauth2::DeviceCodeErrorResponseType::ExpiredToken => {
                        Err(crate::Error::AuthError(format!(
                            "authorization timed out (device token expired): {er:?}"
                        )))
                    }
                    oauth2::DeviceCodeErrorResponseType::Basic(be) => Err(crate::Error::AuthError(
                        format!("oauth2 error {be}: {er:?}"),
                    )),
                };
            }
        }
        let body: crate::ext_oauth2::SecrecyTokenResponse = resp.json().await?;

        Ok(crate::token::ServerToken::from_token_response(
            self.server.clone(),
            body,
        ))
    }
}
