/// AssumeRole chain implementation using AWS STS
///
/// This module provides functionality to perform sts:AssumeRole after obtaining
/// base credentials from AWS SSO or other credential sources.

/// # Arguments
///
/// * `region` - AWS region for the STS API call (typically from AWS SSO configuration)
/// * `base_credentials` - Credentials obtained from the credential server
/// * `target_role_arn` - ARN of the IAM role to assume (e.g., `arn:aws:iam::123456789012:role/RoleName`)
///
/// # Returns
///
/// Returns temporary credentials for the target role.
///
/// # Errors
///
/// Returns `crate::Error` if:
/// - STS AssumeRole API call fails (e.g., AccessDenied, InvalidClientTokenId)
/// - Base credentials are expired or invalid
/// - Target role ARN is malformed
/// - Trust policy doesn't allow the base role to assume the target role
/// - Response parsing fails
///
/// # Session Name
///
/// The role session is created with an auto-generated name in the format `mairu-{YYYYMMDDHHMMSS}`.
/// This appears in CloudTrail logs and can be used for auditing.
pub(crate) async fn perform_assume_role_chain(
    region: &str,
    base_credentials: crate::client::AssumeRoleResponse,
    target_role_arn: &str,
) -> crate::Result<crate::client::AssumeRoleResponse> {
    // Create STS client with base credentials
    let sts = create_sts_client(region, &base_credentials).await;

    // Generate session name
    let session_name = generate_session_name();

    tracing::debug!(
        region = region,
        target_role_arn = target_role_arn,
        session_name = session_name,
        "Performing AssumeRole chain"
    );

    // Call AssumeRole API
    let resp = sts
        .assume_role()
        .role_arn(target_role_arn)
        .role_session_name(session_name)
        .duration_seconds(3600) // 1 hour (maximum for role chaining)
        .send()
        .await
        .map_err(|e| sdk_error_to_crate_error("AssumeRole", e))?;

    // Extract credentials from response
    let creds = resp.credentials().ok_or_else(|| {
        crate::Error::RemoteError(crate::client::Error::Unknown(
            "STS AssumeRole returned empty credentials".to_string(),
            Box::new(crate::Error::UserError("".to_string())),
        ))
    })?;

    // Parse expiration timestamp (aws_smithy_types::DateTime -> chrono::DateTime)
    // Note: Different from awssso_client.rs which uses from_timestamp_millis().
    // STS returns DateTime type (not i64 millis), so we convert via as_secs_f64().
    let epoch_secs = creds.expiration().as_secs_f64();
    let secs = epoch_secs.floor() as i64;
    let nsecs = ((epoch_secs - secs as f64) * 1_000_000_000.0) as u32;
    let expiration = chrono::DateTime::from_timestamp(secs, nsecs).ok_or_else(|| {
        crate::Error::UnknownError(format!(
            "Failed to parse expiration timestamp: {}",
            creds.expiration()
        ))
    })?;

    tracing::debug!(
        target_role_arn = target_role_arn,
        access_key_id = creds.access_key_id(),
        expiration = ?expiration,
        "AssumeRole chain completed successfully"
    );

    // Convert to AssumeRoleResponse
    Ok(crate::client::AssumeRoleResponse {
        version: 1,
        access_key_id: creds.access_key_id().to_owned(),
        secret_access_key: creds.secret_access_key().into(),
        session_token: Some(creds.session_token().to_owned()),
        expiration,
        mairu: crate::client::AssumeRoleResponseMairuExt::default(),
    })
}

/// Generate session name in the format: mairu-{timestamp}-{random}
///
/// AWS session name requirements:
/// - Length: 2-64 characters
/// - Pattern: `[\w+=,.@-]+`
///
/// Format: `mairu-{YYYYMMDDHHMMSS}-{hex}` (e.g., `mairu-20260108100639-a3f`)
fn generate_session_name() -> String {
    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
    let random: u16 = rand::random();
    format!("mairu-{}-{:x}", timestamp, random)
}

/// Create STS client with the given credentials
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
        .identity_cache(aws_config::identity::IdentityCache::no_cache())
        .credentials_provider(aws_sdk_sts::config::SharedCredentialsProvider::new(creds))
        .build();

    aws_sdk_sts::Client::new(&config)
}

/// Map AWS STS SDK errors to crate::Error
///
/// This follows the same pattern as `awssso_client::sdk_error_to_crate_error`,
/// but maps STS-specific error codes.
///
/// Mapped error codes:
/// - `AccessDeniedException` → `PermissionDenied`
/// - `ExpiredTokenException` → `Unauthenticated`
/// - `InvalidClientTokenId` → `Unauthenticated`
/// - `MalformedPolicyDocumentException` → `InvalidArgument`
/// - `PackedPolicyTooLargeException` → `InvalidArgument`
/// - `RegionDisabledException` → `InvalidArgument`
/// - Other errors → `Unknown`
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
        "AccessDeniedException" => PermissionDenied,
        "ExpiredTokenException" => Unauthenticated,
        "InvalidClientTokenId" => Unauthenticated,
        "MalformedPolicyDocumentException" => InvalidArgument,
        "PackedPolicyTooLargeException" => InvalidArgument,
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
        assert!(name.len() >= 22); // "mairu-" (6) + 14 digits + "-" + hex (1-4 chars)
        assert!(name.len() <= 64); // AWS session name limit

        // Check format: mairu-{14 digits}-{hex}
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 3, "Expected 3 parts separated by '-'");
        assert_eq!(parts[0], "mairu");
        assert_eq!(parts[1].len(), 14, "Timestamp should be 14 digits");
        assert!(parts[1].chars().all(|c| c.is_ascii_digit()), "Timestamp should be all digits");
        assert!(parts[2].chars().all(|c| c.is_ascii_hexdigit()), "Random suffix should be hexadecimal");
    }

}
