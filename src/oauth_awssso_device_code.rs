#[derive(Debug)]
pub struct AwsSsoDeviceFlow {
    pub handle: String,
    server: crate::config::Server,
    pub user_code: String,
    device_code: secrecy::SecretString,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub interval: i32,
}

impl From<&AwsSsoDeviceFlow> for crate::proto::InitiateOAuthDeviceCodeResponse {
    fn from(flow: &AwsSsoDeviceFlow) -> crate::proto::InitiateOAuthDeviceCodeResponse {
        crate::proto::InitiateOAuthDeviceCodeResponse {
            handle: flow.handle.clone(),
            user_code: flow.user_code.clone(),
            verification_uri: flow.verification_uri.clone(),
            verification_uri_complete: flow.verification_uri_complete.clone(),
            interval: flow.interval,
            expires_at: Some(std::time::SystemTime::from(flow.expires_at).into()),
        }
    }
}

impl AwsSsoDeviceFlow {
    pub async fn initiate(server: &crate::config::Server) -> crate::Result<Self> {
        let (aws_sso, oauth) =
            server.try_oauth_awssso(crate::config::OAuthGrantType::DeviceCode)?;
        let handle = crate::utils::generate_flow_handle();
        tracing::info!(server = ?server, handle = ?handle, "Initiating AWS SSO Device Grant flow");
        let ssooidc = crate::ext_awssso::sso_config_to_ssooidc(aws_sso).await;
        let resp = ssooidc
            .start_device_authorization()
            .client_id(oauth.client_id.clone())
            .client_secret(oauth.client_secret.clone().unwrap()) // XXX:
            .start_url(server.url.to_string())
            .send()
            .await
            .map_err(|e| Box::new(aws_sdk_ssooidc::Error::from(e)))?;
        Ok(Self {
            handle,
            server: server.to_owned(),
            user_code: resp.user_code.ok_or_else(|| {
                crate::Error::UserError(format!(
                    "Server '{}': AWS returned no user_code",
                    server.id(),
                ))
            })?,
            device_code: resp
                .device_code
                .ok_or_else(|| {
                    crate::Error::UserError(format!(
                        "Server '{}': AWS returned no device_cod",
                        server.id(),
                    ))
                })?
                .into(),
            verification_uri: resp.verification_uri.ok_or_else(|| {
                crate::Error::UserError(format!(
                    "Server '{}': AWS returned no verification_uri",
                    server.id(),
                ))
            })?,
            verification_uri_complete: resp.verification_uri_complete.ok_or_else(|| {
                crate::Error::UserError(format!(
                    "Server '{}': AWS returned no verification_uri_complete",
                    server.id(),
                ))
            })?,

            expires_at: chrono::Utc::now() + std::time::Duration::from_secs(resp.expires_in as u64),
            interval: if resp.interval <= 0 { 5 } else { resp.interval },
        })
    }

    pub async fn complete(&self) -> crate::Result<crate::token::ServerToken> {
        let (aws_sso, oauth) = self
            .server
            .try_oauth_awssso(crate::config::OAuthGrantType::DeviceCode)?;
        tracing::debug!(server = ?self.server, handle = ?self.handle, "Checking AWS SSO Device Grant flow");
        let ssooidc = crate::ext_awssso::sso_config_to_ssooidc(aws_sso).await;

        let resp = {
            use secrecy::ExposeSecret;
            ssooidc
                .create_token()
                .client_id(oauth.client_id.clone())
                .client_secret(oauth.client_secret.clone().unwrap())
                .grant_type("urn:ietf:params:oauth:grant-type:device_code")
                .device_code(self.device_code.expose_secret().to_string())
                .set_scope(Some(aws_sso.scope.clone()))
                .send()
                .await
        };
        match resp {
            Ok(r) => {
                tracing::info!(server = ?self.server, handle = ?self.handle, "Completing AWS SSO Device Grant flow");
                crate::ext_awssso::create_token_output_to_token(&self.server, r)
            }
            Err(aws_sdk_ssooidc::error::SdkError::ServiceError(e))
                if e.err().is_authorization_pending_exception() =>
            {
                Err(crate::Error::AuthNotReadyError { slow_down: false })
            }
            Err(e) => Err(Box::new(aws_sdk_ssooidc::Error::from(e)).into()),
        }
    }
}
