#[derive(Debug)]
pub struct AwsSsoCodeFlow {
    pub handle: String,
    server: crate::config::Server,
    pub user_code: String,
    device_code: secrecy::SecretString,

    redirect_url: url::Url,
    authorize_url: url::Url,
    csrf_token: String,
    pkce_verifier: secrecy::SecretString, // oauth2::PkceCodeVerifier,
}

impl From<&AwsSsoCodeFlow> for crate::proto::InitiateOAuthCodeResponse {
    fn from(flow: &AwsSsoCodeFlow) -> crate::proto::InitiateOAuthCodeResponse {
        crate::proto::InitiateOAuthCodeResponse {
            handle: flow.handle.clone(),
            authorize_url: flow.authorize_url.to_string(),
        }
    }
}

//impl AwsSsoCodeFlow {
//    pub fn initiate(
//        server: &crate::config::Server,
//        redirect_url: &url::Url,
//    ) -> crate::Result<Self> {
//        // TODO: try_aws_sso?
//        let aws_sso = server.aws_sso.as_ref().ok_or_else(|| {
//            crate::Error::ConfigError(format!("Server '{}' is not an aws_sso server", server.id()))
//        })?;
//        let oauth = server.oauth.as_ref().ok_or_else(|| {
//            crate::Error::ConfigError(format!(
//                "Server '{}' is missing an OAuth 2.0 client registration",
//                server.id()
//            ))
//        })?;
//
//        let client = oauth2_client_from_server(server)?
//            .set_redirect_uri(oauth2::RedirectUrl::from_url(redirect_url.clone()));
//        let (oauth, _) = server.try_oauth_code_grant()?;
//        let (pkce_challenge, pkce_verifier) = generate_pkce_challenge();
//        let request = client
//            .authorize_url(oauth2::CsrfToken::new_random)
//            .add_scopes(oauth.scope.iter().map(|x| oauth2::Scope::new(x.to_owned())))
//            .set_pkce_challenge(pkce_challenge);
//        let (authorize_url, csrf_token) = request.url();
//        let handle = crate::utils::generate_flow_handle();
//        tracing::info!(server = ?server, handle = ?handle, "Initiating OAuth 2.0 Authorization Code flow");
//        let ssooidc = crate::ext_awssso::sso_config_to_ssooidc(aws_sso).await;
//        Ok(Self {
//            handle,
//            server: server.to_owned(),
//            redirect_url: redirect_url.clone(),
//            authorize_url,
//            csrf_token,
//            pkce_verifier,
//        })
//    }
//
//    pub async fn complete(
//        &self,
//        completion: crate::proto::CompleteOAuthCodeRequest,
//    ) -> crate::Result<crate::token::ServerToken> {
//        use secrecy::ExposeSecret;
//        tracing::info!(flow = ?self, "Completing OAuth 2.0 Authorization Code flow");
//
//        let client = oauth2_client_from_server(&self.server)?
//            .set_redirect_uri(oauth2::RedirectUrl::from_url(self.redirect_url.clone()));
//        if self.csrf_token.secret() != &completion.state {
//            return Err(crate::Error::AuthError("csrf detected".to_owned()));
//        }
//        let req = client
//            .exchange_code(oauth2::AuthorizationCode::new(completion.code))
//            .set_pkce_verifier(oauth2::PkceCodeVerifier::new(
//                self.pkce_verifier.expose_secret().to_owned(),
//            ));
//        let resp = req.request_async(&crate::client::http()).await?;
//        Ok(crate::token::ServerToken::from_token_response(
//            self.server.clone(),
//            resp,
//        ))
//    }
//}
