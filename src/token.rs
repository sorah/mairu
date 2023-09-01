#[derive(Debug)]
pub struct ServerToken {
    pub server: crate::config::Server,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub access_token: secrecy::SecretString,
}

impl ServerToken {
    pub(crate) fn from_token_response(
        server: crate::config::Server,
        resp: crate::ext_oauth2::SecrecyTokenResponse,
    ) -> Self {
        use oauth2::TokenResponse;

        let expires_at = resp
            .expires_in()
            .and_then(|d| chrono::Duration::from_std(d).ok())
            .and_then(|d| chrono::Utc::now().checked_add_signed(d));
        let access_token = resp.access_token;
        Self {
            server,
            expires_at,
            access_token,
        }
    }
}
