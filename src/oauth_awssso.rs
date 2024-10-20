async fn sso_config_to_ssooidc(sso: &crate::config::ServerAwsSso) -> aws_sdk_ssooidc::Client {
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest())
        .await
        .to_builder()
        .region(Some(aws_config::Region::new(sso.region.clone())))
        .identity_cache(aws_config::identity::IdentityCache::no_cache())
        .build();
    aws_sdk_ssooidc::Client::new(&config)
}

pub async fn register_client(
    server: &crate::config::Server,
) -> crate::Result<crate::config::AwsSsoClientRegistrationCache> {
    let sso = server.aws_sso.as_ref().ok_or_else(|| {
        crate::Error::UserError(format!("Server '{}' is not an aws_sso server", server.id(),))
    })?;

    let ssooidc = sso_config_to_ssooidc(&sso).await;

    let product = env!("CARGO_PKG_NAME");
    let mut req = ssooidc
        .register_client()
        .client_name(format!("{} ({})", product, server.id()))
        .client_type("public");
    if !sso.scope.is_empty() {
        req = req.scopes(sso.scope.join(" "))
    }
    let resp = req.send().await.map_err(aws_sdk_ssooidc::Error::from)?;

    crate::config::AwsSsoClientRegistrationCache::from_aws_sso(&server, &resp)
}

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

impl From<&AwsSsoDeviceFlow> for crate::proto::InitiateAwsSsoDeviceResponse {
    fn from(flow: &AwsSsoDeviceFlow) -> crate::proto::InitiateAwsSsoDeviceResponse {
        crate::proto::InitiateAwsSsoDeviceResponse {
            handle: flow.handle.clone(),
            user_code: flow.user_code.clone(),
            verification_uri: flow.verification_uri.clone(),
            verification_uri_complete: flow.verification_uri_complete.clone(),
            interval: flow.interval,
            expires_at: Some(std::time::SystemTime::from(flow.expires_at.clone()).into()),
        }
    }
}

impl AwsSsoDeviceFlow {
    pub async fn initiate(server: &crate::config::Server) -> crate::Result<Self> {
        let aws_sso = server.aws_sso.as_ref().ok_or_else(|| {
            crate::Error::ConfigError(format!("Server '{}' is not an aws_sso server", server.id()))
        })?;
        let oauth = server.oauth.as_ref().ok_or_else(|| {
            crate::Error::ConfigError(format!(
                "Server '{}' is missing an OAuth 2.0 client registration",
                server.id()
            ))
        })?;
        let handle = crate::utils::generate_flow_handle();
        tracing::info!(server = ?server, handle = ?handle, "Initiating AWS SSO Device Grant flow");
        let ssooidc = sso_config_to_ssooidc(aws_sso).await;
        let resp = ssooidc
            .start_device_authorization()
            .client_id(oauth.client_id.clone())
            .client_secret(oauth.client_secret.clone().unwrap()) // XXX:
            .start_url(server.url.to_string())
            .send()
            .await
            .map_err(aws_sdk_ssooidc::Error::from)?;
        Ok(Self {
            handle,
            server: server.to_owned(),
            user_code: resp
                .user_code
                .ok_or_else(|| {
                    crate::Error::UserError(format!(
                        "Server '{}': AWS returned no user_code",
                        server.id(),
                    ))
                })?
                .into(),
            device_code: resp
                .device_code
                .ok_or_else(|| {
                    crate::Error::UserError(format!(
                        "Server '{}': AWS returned no device_cod",
                        server.id(),
                    ))
                })?
                .into(),
            verification_uri: resp
                .verification_uri
                .ok_or_else(|| {
                    crate::Error::UserError(format!(
                        "Server '{}': AWS returned no verification_uri",
                        server.id(),
                    ))
                })?
                .into(),
            verification_uri_complete: resp
                .verification_uri_complete
                .ok_or_else(|| {
                    crate::Error::UserError(format!(
                        "Server '{}': AWS returned no verification_uri_complete",
                        server.id(),
                    ))
                })?
                .into(),

            expires_at: chrono::Utc::now() + std::time::Duration::from_secs(resp.expires_in as u64),
            interval: if resp.interval <= 0 { 5 } else { resp.interval },
        })
    }

    pub async fn complete(&self) -> crate::Result<crate::token::ServerToken> {
        let aws_sso = self.server.aws_sso.as_ref().ok_or_else(|| {
            crate::Error::ConfigError(format!(
                "Server '{}' is not an aws_sso server",
                self.server.id(),
            ))
        })?;
        let oauth = self.server.oauth.as_ref().ok_or_else(|| {
            crate::Error::ConfigError(format!(
                "Server '{}' is missing an OAuth 2.0 client registration",
                self.server.id(),
            ))
        })?;
        tracing::debug!(server = ?self.server, handle = ?self.handle, "Checking AWS SSO Device Grant flow");
        let ssooidc = sso_config_to_ssooidc(aws_sso).await;

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
                Ok(crate::token::ServerToken {
                    server: self.server.clone(),
                    expires_at: Some(
                        chrono::Utc::now() + std::time::Duration::from_secs(r.expires_in as u64),
                    ),
                    access_token: r
                        .access_token
                        .ok_or_else(|| {
                            crate::Error::UserError(format!(
                                "Server '{}': AWS returned no access token",
                                self.server.id(),
                            ))
                        })?
                        .into(),
                })
            }
            Err(aws_sdk_ssooidc::error::SdkError::ServiceError(e))
                if e.err().is_authorization_pending_exception() =>
            {
                Err(crate::Error::AuthNotReadyError)
            }
            Err(e) => Err(aws_sdk_ssooidc::Error::from(e).into()),
        }
    }
}
