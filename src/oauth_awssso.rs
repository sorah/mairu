use crate::config::AwsSsoClientRegistrationCache;

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
) -> crate::Result<AwsSsoClientRegistrationCache> {
    let sso = server.aws_sso.as_ref().ok_or_else(|| {
        crate::Error::UserError(format!("Server '{}' is not an aws_sso server", server.id(),))
    })?;

    let ssooidc = sso_config_to_ssooidc(&sso).await;

    let mut req = ssooidc
        .register_client()
        .client_name(server.id())
        .client_type("public");
    if !sso.scope.is_empty() {
        req = req.scopes(sso.scope.join(" "))
    }
    let resp = req.send().await.map_err(aws_sdk_ssooidc::Error::from)?;

    crate::config::AwsSsoClientRegistrationCache::from_aws_sso(&server, &resp)
}
