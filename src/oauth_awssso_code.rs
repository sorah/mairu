#[derive(Debug)]
pub struct AwsSsoCodeFlow {
    pub handle: String,
    server: crate::config::Server,

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

impl AwsSsoCodeFlow {
    pub async fn initiate(
        server: &crate::config::Server,
        redirect_url: &url::Url,
    ) -> crate::Result<Self> {
        let (aws_sso, oauth) = server.try_oauth_awssso(crate::config::OAuthGrantType::Code)?;
        let mut authorize_url = crate::ext_awssso::ssooidc_authorize_url(aws_sso).await;
        let (pkce_challenge, pkce_verifier) = crate::ext_oauth2::generate_pkce_challenge();
        let csrf_token = oauth2::CsrfToken::new_random();

        authorize_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &oauth.client_id)
            .append_pair("redirect_uri", redirect_url.as_str())
            .append_pair("state", csrf_token.secret())
            .append_pair("code_challenge", pkce_challenge.as_str())
            .append_pair("code_challenge_method", pkce_challenge.method())
            .append_pair("scopes", &oauth.scope.join(" "));

        // let request = client
        //     .authorize_url(oauth2::CsrfToken::new_random)
        //     .add_scopes(oauth.scope.iter().map(|x| oauth2::Scope::new(x.to_owned())))
        //     .set_pkce_challenge(pkce_challenge);
        // let (authorize_url, csrf_token) = request.url();
        let handle = crate::utils::generate_flow_handle();
        tracing::info!(server = ?server, handle = ?handle, "Initiating OAuth 2.0 Authorization Code flow (AWS SSO)");

        Ok(Self {
            handle,
            server: server.to_owned(),
            redirect_url: redirect_url.clone(),
            authorize_url,
            csrf_token: csrf_token.secret().clone(),
            pkce_verifier,
        })
    }

    pub async fn complete(
        &self,
        completion: crate::proto::CompleteOAuthCodeRequest,
    ) -> crate::Result<crate::token::ServerToken> {
        tracing::info!(flow = ?self, "Completing OAuth 2.0 Authorization Code flow (AWS SSO)");
        let (aws_sso, oauth) = self
            .server
            .try_oauth_awssso(crate::config::OAuthGrantType::Code)?;

        if self.csrf_token != completion.state {
            return Err(crate::Error::AuthError("csrf detected".to_owned()));
        }
        let ssooidc = crate::ext_awssso::sso_config_to_ssooidc(aws_sso).await;
        let resp = {
            use secrecy::ExposeSecret;
            ssooidc
                .create_token()
                .client_id(oauth.client_id.clone())
                .client_secret(oauth.client_secret.clone().unwrap())
                .grant_type("authorization_code")
                .code_verifier(self.pkce_verifier.expose_secret())
                .code(completion.code)
                .redirect_uri(self.redirect_url.clone())
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
