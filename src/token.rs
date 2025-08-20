#[derive(Debug)]
pub struct ServerToken {
    pub server: crate::config::Server,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub access_token: secrecy::SecretString,
    pub refresh_token: Option<secrecy::SecretString>,
}

const NEAR_EXPIRATION_DELTA: chrono::TimeDelta = chrono::TimeDelta::minutes(5);

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
        let refresh_token = resp.refresh_token;
        Self {
            server,
            expires_at,
            access_token,
            refresh_token,
        }
    }

    pub fn is_access_token_near_expiration(&self) -> bool {
        if let Some(ref expiry) = self.expires_at {
            let Some(thres) = expiry.checked_sub_signed(NEAR_EXPIRATION_DELTA) else {
                return true;
            };
            return thres <= chrono::Utc::now();
        }
        false
    }

    pub fn has_active_refresh_token(&self) -> bool {
        if self.refresh_token.is_none() {
            return false;
        }
        if let Some(crate::config::ServerOAuth {
            client_expires_at: Some(ref expiry),
            ..
        }) = self.server.oauth
            && *expiry <= chrono::Utc::now()
        {
            return false;
        }
        true
    }
}
