pub(crate) async fn refresh_token(
    token: &crate::token::ServerToken,
) -> crate::Result<crate::token::ServerToken> {
    let flow = OAuthRefreshTokenFlow::try_from(token)?;
    flow.perform().await
}

#[derive(Debug)]
pub struct OAuthRefreshTokenFlow {
    server: crate::config::Server,
    refresh_token: secrecy::SecretString,
}

impl TryFrom<&crate::token::ServerToken> for OAuthRefreshTokenFlow {
    type Error = crate::Error;
    fn try_from(value: &crate::token::ServerToken) -> Result<Self, Self::Error> {
        let sid = value.server.id();
        if !value.has_active_refresh_token() {
            return Err(crate::Error::ConfigError(format!(
                "{sid} token does not have refresh_token"
            )));
        }
        Ok(Self {
            refresh_token: value.refresh_token.clone().unwrap(),
            server: value.server.clone(),
        })
    }
}

impl OAuthRefreshTokenFlow {
    pub async fn perform(&self) -> crate::Result<crate::token::ServerToken> {
        use secrecy::ExposeSecret;
        tracing::info!(flow = ?self, "Refreshing access token");
        let client = oauth2_client_from_server(&self.server)?;
        let rt = oauth2::RefreshToken::new(self.refresh_token.expose_secret().to_string());
        let req = client.exchange_refresh_token(&rt).add_scopes(
            // scope is not mandatory on the standard, however some AS refuses to refresh access tokens when omit (e.g. Microsoft)
            self.server
                .oauth
                .as_ref()
                .unwrap() // XXX: unwrap(), ensured by oauth2_client_from_server
                .scope
                .iter()
                .map(|x| oauth2::Scope::new(x.to_owned())),
        );
        let resp = req.request_async(&crate::client::http()).await?;
        Ok(crate::token::ServerToken::from_token_response(
            self.server.clone(),
            resp,
        ))
    }
}

fn oauth2_client_from_server(
    server: &crate::config::Server,
) -> crate::Result<
    crate::ext_oauth2::SecrecyClient<
        oauth2::EndpointNotSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointSet,
    >,
> {
    let oauth = server.oauth.as_ref().ok_or_else(|| {
        crate::Error::ConfigError(format!(
            "Server '{}' is missing OAuth 2.0 client configuration",
            server.id()
        ))
    })?;

    let mut client =
        crate::ext_oauth2::SecrecyClient::new(oauth2::ClientId::new(oauth.client_id.clone()))
            .set_token_uri(oauth2::TokenUrl::from_url(
                oauth
                    .token_endpoint
                    .clone()
                    .map(Ok)
                    .unwrap_or_else(|| server.url.join("oauth/token"))?,
            ));
    if let Some(ref secret) = oauth.client_secret {
        client = client.set_client_secret(oauth2::ClientSecret::new(secret.to_owned()));
    }
    Ok(client)
}
