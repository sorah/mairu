pub type SecrecyClient = oauth2::Client<
    oauth2::basic::BasicErrorResponse,
    SecrecyTokenResponse,
    oauth2::basic::BasicTokenType,
    oauth2::basic::BasicTokenIntrospectionResponse,
    oauth2::StandardRevocableToken,
    oauth2::basic::BasicRevocationErrorResponse,
>;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SecrecyTokenResponse {
    #[serde(skip_serializing)]
    pub access_token: secrecy::SecretString,
    #[serde(deserialize_with = "oauth2::helpers::deserialize_untagged_enum_case_insensitive")]
    pub token_type: oauth2::basic::BasicTokenType,
    pub expires_in: Option<u64>,
    #[serde(skip_serializing)]
    pub refresh_token: Option<secrecy::SecretString>,

    #[serde(default = "default_dummy_at")]
    dummy_at: oauth2::AccessToken,
}

fn default_dummy_at() -> oauth2::AccessToken {
    oauth2::AccessToken::new("dummyaccesstokendummy".to_owned())
}

impl oauth2::TokenResponse<oauth2::basic::BasicTokenType> for SecrecyTokenResponse {
    fn access_token(&self) -> &oauth2::AccessToken {
        &self.dummy_at
    }

    fn token_type(&self) -> &oauth2::basic::BasicTokenType {
        &self.token_type
    }

    fn expires_in(&self) -> Option<std::time::Duration> {
        self.expires_in.map(std::time::Duration::from_secs)
    }

    fn refresh_token(&self) -> Option<&oauth2::RefreshToken> {
        None
    }

    fn scopes(&self) -> Option<&Vec<oauth2::Scope>> {
        None
    }
}
