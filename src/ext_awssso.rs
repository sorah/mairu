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
) -> crate::Result<crate::config::AwsSsoClientRegistrationCache> {
    let sso = server.aws_sso.as_ref().ok_or_else(|| {
        crate::Error::UserError(format!("Server '{}' is not an aws_sso server", server.id(),))
    })?;

    let ssooidc = sso_config_to_ssooidc(sso).await;

    let product = env!("CARGO_PKG_NAME");
    let mut req = ssooidc
        .register_client()
        .client_name(format!("{} ({})", product, server.id()))
        .client_type("public");
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
