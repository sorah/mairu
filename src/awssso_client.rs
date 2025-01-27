async fn sso_config_to_sso(sso: &crate::config::ServerAwsSso) -> aws_sdk_sso::Client {
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest())
        .await
        .to_builder()
        .region(Some(aws_config::Region::new(sso.region.clone())))
        .identity_cache(aws_config::identity::IdentityCache::no_cache())
        .build();
    aws_sdk_sso::Client::new(&config)
}

pub struct Client {
    pub server_id: String,
    pub sso: crate::config::ServerAwsSso,
    access_token: secrecy::SecretString,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("server_id", &self.server_id.as_str())
            .field("sso", &self.sso)
            .finish()
    }
}

impl TryFrom<crate::token::ServerToken> for Client {
    type Error = crate::Error;
    fn try_from(token: crate::token::ServerToken) -> crate::Result<Client> {
        Client::try_from(&token)
    }
}

impl TryFrom<&crate::token::ServerToken> for Client {
    type Error = crate::Error;
    fn try_from(token: &crate::token::ServerToken) -> crate::Result<Client> {
        let Some(aws_sso) = token.server.aws_sso.as_ref() else {
            return Err(crate::Error::ConfigError(format!(
                "Server '{}' is not an aws_sso server",
                token.server.id(),
            )));
        };
        Ok(Client {
            server_id: token.server.id().to_owned(),
            sso: aws_sso.clone(),
            access_token: token.access_token.clone(),
        })
    }
}

impl crate::client::CredentialVendor for Client {
    #[tracing::instrument]
    async fn assume_role(
        &self,
        rolespec: &str,
    ) -> crate::Result<crate::client::AssumeRoleResponse> {
        use secrecy::ExposeSecret;

        let (account_id, role_name) = parse_rolespec(rolespec)?;
        let sso = sso_config_to_sso(&self.sso).await;

        tracing::debug!(
            account_id = account_id,
            role_name = role_name,
            server_id = &self.server_id,
            "requesting"
        );

        let resp = sso
            .get_role_credentials()
            .account_id(account_id.to_owned())
            .role_name(role_name.to_owned())
            .access_token(self.access_token.expose_secret().to_owned())
            .send()
            .await;

        match resp {
            Ok(aws_sdk_sso::operation::get_role_credentials::GetRoleCredentialsOutput {
                role_credentials: Some(cred),
                ..
            }) => {
                let makeerr = || {
                    crate::Error::RemoteError(crate::client::Error::Unknown(
                        format!("sso:GetRoleCredentials returned invalid result for '{rolespec}'"),
                        Box::new(crate::Error::UserError("".to_string())), // XXX:
                    ))
                };
                let credentials = crate::client::AssumeRoleResponse {
                    version: 1,
                    access_key_id: cred.access_key_id().ok_or_else(makeerr)?.to_owned(),
                    secret_access_key: cred.secret_access_key().ok_or_else(makeerr)?.into(),
                    session_token: cred.session_token().map(|s| s.to_owned()),
                    expiration: chrono::DateTime::from_timestamp_millis(cred.expiration())
                        .ok_or_else(makeerr)?,
                    mairu: crate::client::AssumeRoleResponseMairuExt::default(),
                };
                tracing::debug!(account_id = account_id, role_name = role_name, server_id = &self.server_id, credentials = ?credentials, "response");
                return Ok(credentials);
                //        let credentials = resp.json::<crate::client::AssumeRoleResponse>().await?;
            }
            Ok(_) => {
                tracing::error!(
                    account_id = account_id,
                    role_name = role_name,
                    server_id = &self.server_id,
                    "sso:GetRoleCredentials returned empty result"
                );
                return Err(crate::Error::RemoteError(crate::client::Error::Unknown(
                    format!("sso:GetRoleCredentials returned empty result for '{rolespec}'"),
                    Box::new(crate::Error::UserError("".to_string())), // XXX:
                )));
            }
            Err(e) => {
                tracing::error!(
                    account_id = account_id,
                    role_name = role_name,
                    server_id = &self.server_id,
                    err = ?e,
                    "sso:GetRoleCredentials failed"
                );
                return Err(sdk_error_to_crate_error("GetRoleCredentials", e));
            }
        }
    }

}

fn sdk_error_to_crate_error<E, R>(
    context: &str,
    err: aws_sdk_sso::error::SdkError<E, R>,
) -> crate::Error
where
    E: std::marker::Send
        + std::marker::Sync
        + std::error::Error
        + aws_sdk_sso::error::ProvideErrorMetadata
        + 'static,
    R: std::marker::Send + std::marker::Sync + std::fmt::Debug + 'static,
{
    use aws_sdk_sso::error::ProvideErrorMetadata;
    macro_rules! match_map_error {
        (
            $e:expr,
             $(
                $c:literal => $t:ident,
             )*
        ) => {
            match $e {
                $(
                    e1 if err.code() == Some($c) => {
                        crate::Error::RemoteError(crate::client::Error::$t(
                            format!("AWS SSO says {code} for {context}: {message:?}", code=e1.code().unwrap(), message=e1.message(), ),
                            Box::new(e1),
                        ))
                    }
                )*
                e => {
                    crate::Error::RemoteError(crate::client::Error::Unknown(
                        format!("AWS SSO says {code:?} for {context}: {message:?}", code=e.code(), message=e.message(), ),
                        Box::new(e),
                    ))
                }
            }
        }
    }
    match_map_error! {
        err,
        "ResourceNotFoundException" => NotFound,
        "InvalidRequestException" => InvalidArgument,
        "UnauthorizedException" => Unauthenticated,
        "TooManyRequestsException" => ResourceExhausted,
        "ForbiddenException" => PermissionDenied,
    }
}

fn parse_rolespec(rolespec: &str) -> crate::Result<(&str, &str)> {
    let parts: Vec<&str> = rolespec.splitn(2, '/').collect();
    if parts.len() != 2 {
        return Err(crate::Error::UserError(format!(
            "rolespec '{rolespec}' is invalid"
        )));
    }
    Ok((parts[0], parts[1]))
}

#[cfg(test)]
mod tests {
    use super::*;

    mod parse_rolespec {
        use super::*;

        #[test]
        fn simple_valid() {
            let (a, b) = parse_rolespec("123456781234/MyRole").unwrap();
            assert_eq!("123456781234", a);
            assert_eq!("MyRole", b);
        }
        #[test]
        fn simple_valid_with_path() {
            let (a, b) = parse_rolespec("123456781234/service-role/MyRole").unwrap();
            assert_eq!("123456781234", a);
            assert_eq!("service-role/MyRole", b);
        }

        #[test]
        fn simple_invalid() {
            assert!(parse_rolespec("123456781234").is_err());
        }
    }
}
