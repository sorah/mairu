use aws_smithy_runtime_api::client::endpoint::ResolveEndpoint;

pub async fn sso_config_to_ssooidc(sso: &crate::config::ServerAwsSso) -> aws_sdk_ssooidc::Client {
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
    purpose: crate::config::OAuthGrantType,
) -> crate::Result<crate::config::AwsSsoClientRegistrationCache> {
    let sso = server.aws_sso.as_ref().ok_or_else(|| {
        crate::Error::UserError(format!("Server '{}' is not an aws_sso server", server.id(),))
    })?;

    let ssooidc = sso_config_to_ssooidc(sso).await;

    // XXX: We need to maintain separate client registrations per grant_type (`purpose`).
    // A client must be registered with grant_types parameter to opt-in to authorization_code grant
    // (in addition to device_code type, which was grant_type only supported in AWS SSO),
    // but AWS SSO returns internal exception with HTTP 500 status code when a client registration
    // has both grant_types("urn:ietf:params:oauth:grant-type:device_code") and grant_types("authorization_code").

    let product = env!("CARGO_PKG_NAME");
    let hostname = nix::unistd::gethostname()
        .ok()
        .and_then(|x| x.into_string().ok())
        .unwrap_or_else(|| "?".to_string());
    let mut req = ssooidc
        .register_client()
        .client_name(format!("{} ({}@{})", product, server.id(), hostname))
        .client_type("public")
        .issuer_url(server.url.to_string())
        .redirect_uris("http://127.0.0.1/oauth/callback"); // [::1] is refused by AWS
    if matches!(purpose, crate::config::OAuthGrantType::Code) {
        req = req
            .grant_types("authorization_code")
            .grant_types("refresh_token");
    }
    if !sso.scope.is_empty() {
        req = req.scopes(sso.scope.join(" "))
    }
    let resp = req
        .send()
        .await
        .map_err(|e| Box::new(aws_sdk_ssooidc::Error::from(e)))?;

    crate::config::AwsSsoClientRegistrationCache::from_aws_sso(server, &resp)
}

pub async fn refresh_token(
    token: &crate::token::ServerToken,
) -> crate::Result<crate::token::ServerToken> {
    let sso = token.server.aws_sso.as_ref().ok_or_else(|| {
        crate::Error::UserError(format!(
            "Server '{}' is not an aws_sso server",
            token.server.id(),
        ))
    })?;
    let oauth = token.server.oauth.as_ref().ok_or_else(|| {
        crate::Error::ConfigError(format!(
            "Server '{}' is missing client registration",
            token.server.id(),
        ))
    })?;
    let refresh_token = token.refresh_token.as_ref().ok_or_else(|| {
        crate::Error::ConfigError(format!(
            "Server '{}' session has no refresh_token",
            token.server.id(),
        ))
    })?;

    let ssooidc = sso_config_to_ssooidc(sso).await;

    let r = {
        use secrecy::ExposeSecret;
        ssooidc
            .create_token()
            .client_id(oauth.client_id.clone())
            .client_secret(oauth.client_secret.clone().unwrap())
            .grant_type("refresh_token")
            .refresh_token(refresh_token.expose_secret())
            .send()
            .await
            .map_err(|e| Box::new(aws_sdk_ssooidc::Error::from(e)))?
    };
    tracing::info!(server = ?token.server, "access_token refreshed using refresh_token");
    create_token_output_to_token(&token.server, r)
}

pub fn create_token_output_to_token(
    server: &crate::config::Server,
    r: aws_sdk_ssooidc::operation::create_token::CreateTokenOutput,
) -> crate::Result<crate::token::ServerToken> {
    Ok(crate::token::ServerToken {
        server: server.clone(),
        expires_at: Some(chrono::Utc::now() + std::time::Duration::from_secs(r.expires_in as u64)),
        access_token: r
            .access_token
            .ok_or_else(|| {
                crate::Error::UserError(format!(
                    "Server '{}': AWS returned no access token",
                    server.id(),
                ))
            })?
            .into(),
        refresh_token: r.refresh_token.map(|x| x.into()),
    })
}

pub async fn ssooidc_authorize_url(sso: &crate::config::ServerAwsSso) -> url::Url {
    let interceptor = EndpointStealingInterceptor::new();
    let interceptor_cell = interceptor.inner.clone();
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest())
        .await
        .to_builder()
        .region(Some(aws_config::Region::new(sso.region.clone())))
        .identity_cache(aws_config::identity::IdentityCache::no_cache())
        .build();
    let sconfig = aws_sdk_ssooidc::config::Builder::from(&config)
        .interceptor(interceptor)
        .build();
    let client = aws_sdk_ssooidc::Client::from_conf(sconfig);

    // https://raw.githubusercontent.com/aws/aws-cli/v2/awscli/botocore/utils.py
    let r = client
        .register_client()
        .client_type("public")
        .client_name("temp")
        .send()
        .await;
    if r.is_ok() {
        panic!("ssooidc_authorize_url RegisterClient must fail");
    }

    let endpoint = interceptor_cell
        .get()
        .expect("interceptor must set endpoint value")
        .clone();
    let u = url::Url::parse(endpoint.url()).unwrap();
    u.join("/authorize").unwrap()
}

#[derive(Debug)]
struct EndpointStealingInterceptor {
    inner: std::sync::Arc<std::sync::OnceLock<aws_smithy_types::endpoint::Endpoint>>,
}

impl EndpointStealingInterceptor {
    fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::OnceLock::new()),
        }
    }
}

impl aws_smithy_runtime_api::client::interceptors::Intercept for EndpointStealingInterceptor {
    fn name(&self) -> &'static str {
        "EndpointStealingInterceptor"
    }

    fn read_before_serialization(
        &self,
        _context: &aws_smithy_runtime_api::client::interceptors::context::BeforeSerializationInterceptorContextRef<
        '_,
        aws_smithy_runtime_api::client::interceptors::context::Input,
        aws_smithy_runtime_api::client::interceptors::context::Output,
        aws_smithy_runtime_api::client::interceptors::context::Error,
        >,
        runtime_components: &aws_smithy_runtime_api::client::runtime_components::RuntimeComponents,
        cfg: &mut aws_smithy_types::config_bag::ConfigBag,
    ) -> ::std::result::Result<(), ::aws_smithy_runtime_api::box_error::BoxError> {
        use core::future::Future;
        let params = cfg
            .load::<aws_smithy_runtime_api::client::endpoint::EndpointResolverParams>()
            .ok_or_else(|| {
                crate::Error::UnknownError("could not load EndpointResolverParams".to_string())
            })?;
        let epr = runtime_components.endpoint_resolver();
        let fut = epr.resolve_endpoint(params);
        let waker = futures::task::noop_waker();
        let mut ctx = futures::task::Context::from_waker(&waker);
        tokio::pin!(fut);
        match fut.poll(&mut ctx) {
            core::task::Poll::Ready(Ok(x)) => {
                if self.inner.set(x.clone()).is_err() {
                    tracing::warn!(
                        "EndpointStealingInterceptor could not set endpoint (it was occupied)"
                    );
                }
            }
            _ => {
                return Err(Box::new(crate::Error::UnknownError(
                    "error during aws-ssooidc endpoint resolution; it was not instantly Ready"
                        .to_string(),
                )))
            }
        }
        Err(Box::new(crate::Error::UnknownError(
            "intentional failure".to_string(),
        )))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    mod ssooidc_authorize_url {
        use super::*;

        #[tokio::test]
        async fn test_ap_northeast_1() {
            let u = ssooidc_authorize_url(&crate::config::ServerAwsSso {
                region: "ap-northeast-1".to_owned(),
                scope: vec![],
                local_port: Some(0),
            })
            .await;
            assert_eq!(
                u.as_str(),
                "https://oidc.ap-northeast-1.amazonaws.com/authorize"
            )
        }
    }
}
