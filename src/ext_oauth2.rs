pub type SecrecyClient<
    HasAuthUrl = oauth2::EndpointNotSet,
    HasDeviceAuthUrl = oauth2::EndpointNotSet,
    HasIntrospectionUrl = oauth2::EndpointNotSet,
    HasRevocationUrl = oauth2::EndpointNotSet,
    HasTokenUrl = oauth2::EndpointNotSet,
> = oauth2::Client<
    oauth2::basic::BasicErrorResponse,
    SecrecyTokenResponse,
    oauth2::basic::BasicTokenIntrospectionResponse,
    oauth2::StandardRevocableToken,
    oauth2::basic::BasicRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
>;

#[serde_with::serde_as]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SecrecyTokenResponse {
    #[serde(skip_serializing)]
    pub access_token: secrecy::SecretString,
    #[serde(deserialize_with = "oauth2::helpers::deserialize_untagged_enum_case_insensitive")]
    pub token_type: oauth2::basic::BasicTokenType,

    // Non-compliant servers (e.g. Microsoft) may return this in string
    #[serde_as(deserialize_as = "Option<serde_with::PickFirst<(_, serde_with::DisplayFromStr)>>")]
    pub expires_in: Option<u64>,

    #[serde(skip_serializing)]
    pub refresh_token: Option<secrecy::SecretString>,

    #[serde(default = "default_dummy_at")]
    dummy_at: oauth2::AccessToken,
}

fn default_dummy_at() -> oauth2::AccessToken {
    oauth2::AccessToken::new("dummyaccesstokendummy".to_owned())
}

impl oauth2::TokenResponse for SecrecyTokenResponse {
    type TokenType = oauth2::basic::BasicTokenType;
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

#[serde_with::serde_as]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CustomDeviceAuthorizationResponse {
    #[serde(skip_serializing)]
    pub device_code: secrecy::SecretString,
    #[serde(skip_serializing)]
    pub user_code: secrecy::SecretString,

    #[serde(alias = "verification_url")]
    pub verification_uri: String,

    #[serde(skip_serializing)]
    pub verification_uri_complete: Option<secrecy::SecretString>,

    // Non-compliant servers (e.g. Microsoft OAuth 2 v1 endpoint) may return in string
    #[serde_as(deserialize_as = "serde_with::PickFirst<(_, serde_with::DisplayFromStr)>")]
    pub expires_in: u64,

    #[serde_as(
        deserialize_as = "DeviceCodeAuthMinimum<serde_with::PickFirst<(_, serde_with::DisplayFromStr, serde_with::DefaultOnNull)>>"
    )]
    #[serde(default = "default_device_auth_interval")]
    pub interval: i32,
}

// https://datatracker.ietf.org/doc/html/rfc8628#section-3.2
pub static DEVICE_CODE_AUTH_INTERVAL_MIN: i32 = 5;

fn default_device_auth_interval() -> i32 {
    DEVICE_CODE_AUTH_INTERVAL_MIN
}

struct DeviceCodeAuthMinimum<T>(std::marker::PhantomData<T>);

impl<'de, TAs> serde_with::DeserializeAs<'de, i32> for DeviceCodeAuthMinimum<TAs>
where
    TAs: serde_with::DeserializeAs<'de, i32>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<i32, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::Deserialize;
        let content =
            <serde_with::de::DeserializeAsWrap<i32, TAs>>::deserialize(deserializer)?.into_inner();
        Ok(content.max(DEVICE_CODE_AUTH_INTERVAL_MIN))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod custom_device_authorization_response {
        use super::*;

        #[test]
        fn test_parse_minimal() {
            let j = r#"{"device_code": "DEVICE", "user_code": "USER", "verification_uri": "http://test.invalid", "expires_in": 1234}"#;
            let d: CustomDeviceAuthorizationResponse = serde_json::from_str(j).unwrap();
            assert_eq!(d.expires_in, 1234);
            assert_eq!(d.interval, 5);
        }
        #[test]
        fn test_parse_expires_in_str() {
            let j = r#"{"device_code": "DEVICE", "user_code": "USER", "verification_uri": "http://test.invalid", "expires_in": "2345"}"#;
            let d: CustomDeviceAuthorizationResponse = serde_json::from_str(j).unwrap();
            assert_eq!(d.expires_in, 2345);
        }
        #[test]
        fn test_parse_interval() {
            let j = r#"{"device_code": "DEVICE", "user_code": "USER", "verification_uri": "http://test.invalid", "expires_in": 1234, "interval": 10}"#;
            let d: CustomDeviceAuthorizationResponse = serde_json::from_str(j).unwrap();
            assert_eq!(d.interval, 10);
        }
        #[test]
        fn test_parse_interval_str() {
            let j = r#"{"device_code": "DEVICE", "user_code": "USER", "verification_uri": "http://test.invalid", "expires_in": 1234, "interval": "20"}"#;
            let d: CustomDeviceAuthorizationResponse = serde_json::from_str(j).unwrap();
            assert_eq!(d.interval, 20);
        }
        #[test]
        fn test_parse_interval_null() {
            let j = r#"{"device_code": "DEVICE", "user_code": "USER", "verification_uri": "http://test.invalid", "expires_in": 1234, "interval": null}"#;
            let d: CustomDeviceAuthorizationResponse = serde_json::from_str(j).unwrap();
            assert_eq!(d.interval, 5);
        }
        #[test]
        fn test_parse_interval_zero() {
            let j = r#"{"device_code": "DEVICE", "user_code": "USER", "verification_uri": "http://test.invalid", "expires_in": 1234, "interval": 0}"#;
            let d: CustomDeviceAuthorizationResponse = serde_json::from_str(j).unwrap();
            assert_eq!(d.interval, 5);
        }
        #[test]
        fn test_parse_interval_negative() {
            let j = r#"{"device_code": "DEVICE", "user_code": "USER", "verification_uri": "http://test.invalid", "expires_in": 1234, "interval": -10}"#;
            let d: CustomDeviceAuthorizationResponse = serde_json::from_str(j).unwrap();
            assert_eq!(d.interval, 5);
        }
    }
}
