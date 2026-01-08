//! STS AssumeRole chain for cross-account access or privilege escalation.

/// Perform sts:AssumeRole using base credentials to obtain credentials for a target role.
pub(crate) async fn perform_assume_role_chain(
    region: &str,
    base_credentials: crate::client::AssumeRoleResponse,
    target_role_arn: &str,
) -> crate::Result<crate::client::AssumeRoleResponse> {
    let sts = create_sts_client(region, &base_credentials).await;
    let session_name = generate_session_name();

    tracing::debug!(
        region = region,
        target_role_arn = target_role_arn,
        session_name = session_name,
        "Performing AssumeRole chain"
    );

    let resp = sts
        .assume_role()
        .role_arn(target_role_arn)
        .role_session_name(session_name)
        // Role chaining has a maximum duration of 1 hour (AWS limitation)
        .duration_seconds(3600)
        .send()
        .await
        .map_err(|e| sdk_error_to_crate_error("AssumeRole", e))?;

    let creds = resp.credentials().ok_or_else(|| {
        crate::Error::RemoteError(crate::client::Error::Unknown(
            "STS AssumeRole returned empty credentials".to_string(),
            Box::new(crate::Error::UserError("".to_string())),
        ))
    })?;

    let exp = creds.expiration();
    let expiration = chrono::DateTime::from_timestamp(exp.secs(), exp.subsec_nanos())
        .ok_or_else(|| {
            crate::Error::UnknownError(format!(
                "Failed to parse expiration timestamp: {}",
                exp
            ))
        })?;

    tracing::debug!(
        target_role_arn = target_role_arn,
        access_key_id = creds.access_key_id(),
        expiration = ?expiration,
        "AssumeRole chain completed successfully"
    );

    Ok(crate::client::AssumeRoleResponse {
        version: 1,
        access_key_id: creds.access_key_id().to_owned(),
        secret_access_key: creds.secret_access_key().into(),
        session_token: Some(creds.session_token().to_owned()),
        expiration,
        mairu: crate::client::AssumeRoleResponseMairuExt::default(),
    })
}

/// Session name appears in CloudTrail logs for auditing.
fn generate_session_name() -> String {
    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
    let random: u16 = rand::random();
    format!("mairu-{}-{:x}", timestamp, random)
}

async fn create_sts_client(
    region: &str,
    credentials: &crate::client::AssumeRoleResponse,
) -> aws_sdk_sts::Client {
    use secrecy::ExposeSecret;

    let creds = aws_sdk_sts::config::Credentials::new(
        &credentials.access_key_id,
        credentials.secret_access_key.expose_secret(),
        credentials.session_token.clone(),
        Some(credentials.expiration.into()),
        "mairu-sts-assume-role",
    );

    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest())
        .await
        .to_builder()
        .region(Some(aws_config::Region::new(region.to_owned())))
        // Disable cache to always use the provided credentials
        .identity_cache(aws_config::identity::IdentityCache::no_cache())
        .credentials_provider(aws_sdk_sts::config::SharedCredentialsProvider::new(creds))
        .build();

    aws_sdk_sts::Client::new(&config)
}

/// Maps STS SDK errors to crate::Error, following awssso_client pattern.
fn sdk_error_to_crate_error<E, R>(
    context: &str,
    err: aws_sdk_sts::error::SdkError<E, R>,
) -> crate::Error
where
    E: std::marker::Send
        + std::marker::Sync
        + std::error::Error
        + aws_sdk_sts::error::ProvideErrorMetadata
        + 'static,
    R: std::marker::Send + std::marker::Sync + std::fmt::Debug + 'static,
{
    use aws_sdk_sts::error::ProvideErrorMetadata;

    macro_rules! match_map_error {
        (
            $e:expr,
            $(
                $c:literal => $t:ident,
            )*
        ) => {
            match $e {
                $(
                    e1 if e1.code() == Some($c) => {
                        let message = format!(
                            "AWS STS says {code} for {context}: {message:?}",
                            code = $c,
                            context = context,
                            message = e1.message(),
                        );
                        crate::Error::RemoteError(crate::client::Error::$t(
                            message,
                            Box::new(e1),
                        ))
                    }
                )*
                e => {
                    let message = format!(
                        "AWS STS returned error for {context}: {code:?} {message:?}",
                        context = context,
                        code = e.code(),
                        message = e.message(),
                    );
                    crate::Error::RemoteError(crate::client::Error::Unknown(
                        message,
                        Box::new(e),
                    ))
                }
            }
        }
    }

    match_map_error! {
        err,
        "AccessDenied" => PermissionDenied,
        "ExpiredTokenException" => Unauthenticated,
        "InvalidClientTokenId" => Unauthenticated,
        "MalformedPolicyDocument" => InvalidArgument,
        "PackedPolicyTooLarge" => InvalidArgument,
        "RegionDisabledException" => InvalidArgument,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_session_name() {
        let name = generate_session_name();
        assert!(name.starts_with("mairu-"));
        assert!(name.len() <= 64); // AWS session name limit

        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "mairu");
        assert_eq!(parts[1].len(), 14);
        assert!(parts[1].chars().all(|c| c.is_ascii_digit()));
        assert!(parts[2].chars().all(|c| c.is_ascii_hexdigit()));
    }
}
