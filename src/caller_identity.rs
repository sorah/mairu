//! Who credentials really belong to, from `sts:GetCallerIdentity` through an endpoint the agent fixes.

/// The global endpoint of the `aws` partition; never taken from the environment.
const STS_ENDPOINT: &str = "https://sts.amazonaws.com";
const STS_REGION: &str = "us-east-1";
const STS_OPERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// The identity credentials carry, as `context.caller` sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub account: String,
    pub arn: String,
    pub user_id: String,
    pub r#type: CallerType,
    pub role_name: Option<String>,
    pub session_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerType {
    AssumedRole,
    User,
    FederatedUser,
    Root,
    Other,
}

impl CallerType {
    pub fn as_str(self) -> &'static str {
        match self {
            CallerType::AssumedRole => "assumed-role",
            CallerType::User => "user",
            CallerType::FederatedUser => "federated-user",
            CallerType::Root => "root",
            CallerType::Other => "other",
        }
    }
}

impl Caller {
    /// Fills the fields derived from `arn`.
    pub fn new(account: String, arn: String, user_id: String) -> Self {
        let (r#type, role_name, session_name) = parse_arn(&arn);
        Self {
            account,
            arn,
            user_id,
            r#type,
            role_name,
            session_name,
        }
    }

    pub fn summary(&self) -> String {
        summary(&self.arn)
    }

    pub fn to_json(&self) -> serde_json::Value {
        let mut caller = serde_json::json!({
            "account": self.account,
            "arn": self.arn,
            "user_id": self.user_id,
            "type": self.r#type.as_str(),
        });
        if let Some(r) = &self.role_name {
            caller["role_name"] = serde_json::Value::from(r.clone());
        }
        if let Some(s) = &self.session_name {
            caller["session_name"] = serde_json::Value::from(s.clone());
        }
        caller
    }
}

fn parse_arn(arn: &str) -> (CallerType, Option<String>, Option<String>) {
    let mut parts = arn.splitn(6, ':');
    let (
        Some("arn"),
        Some(_partition),
        Some(service),
        Some(_region),
        Some(_account),
        Some(resource),
    ) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    )
    else {
        return (CallerType::Other, None, None);
    };
    match (service, resource.split_once('/')) {
        ("sts", Some(("assumed-role", rest))) => match rest.split_once('/') {
            Some((role, session)) if !role.is_empty() && !session.is_empty() => (
                CallerType::AssumedRole,
                Some(role.to_owned()),
                Some(session.to_owned()),
            ),
            _ => (CallerType::Other, None, None),
        },
        ("iam", Some(("user", name))) if !name.is_empty() => (CallerType::User, None, None),
        ("sts", Some(("federated-user", name))) if !name.is_empty() => {
            (CallerType::FederatedUser, None, None)
        }
        ("iam", None) if resource == "root" => (CallerType::Root, None, None),
        _ => (CallerType::Other, None, None),
    }
}

/// `999999999999 assumed-role/Admin` for the terminal: the account and the ARN resource, without a session name.
pub fn summary(arn: &str) -> String {
    let mut parts = arn.splitn(6, ':');
    let (Some(account), Some(resource)) = (parts.nth(4), parts.next()) else {
        return arn.to_owned();
    };
    let resource = match parse_arn(arn) {
        (CallerType::AssumedRole, Some(role), _) => format!("assumed-role/{role}"),
        _ => resource.to_owned(),
    };
    format!("{account} {resource}")
}

/// Where `sts:GetCallerIdentity` is sent: the global endpoint unless an approved `authorization.json` says otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StsTarget {
    pub region: String,
    pub endpoint: String,
}

impl Default for StsTarget {
    fn default() -> Self {
        Self {
            region: STS_REGION.to_owned(),
            endpoint: STS_ENDPOINT.to_owned(),
        }
    }
}

impl StsTarget {
    /// A server's own region takes its regional endpoint; otherwise the configured endpoint, or the regional
    /// endpoint of the configured region.
    pub fn from_settings(
        sts: Option<&crate::policy::settings::StsSettings>,
        server_id: &str,
    ) -> Self {
        let Some(sts) = sts else {
            return Self::default();
        };
        if let Some(region) = sts.servers.get(server_id).and_then(|s| s.region.clone()) {
            return Self {
                endpoint: regional_endpoint(&region),
                region,
            };
        }
        let region = sts.region.clone().unwrap_or_else(|| STS_REGION.to_owned());
        let endpoint = match (&sts.endpoint, &sts.region) {
            (Some(e), _) => e.as_str().trim_end_matches('/').to_owned(),
            (None, Some(r)) => regional_endpoint(r),
            (None, None) => STS_ENDPOINT.to_owned(),
        };
        Self { region, endpoint }
    }
}

fn regional_endpoint(region: &str) -> String {
    if region.starts_with("cn-") {
        format!("https://sts.{region}.amazonaws.com.cn")
    } else {
        format!("https://sts.{region}.amazonaws.com")
    }
}

/// Asks who credentials belong to.
#[async_trait::async_trait]
pub trait Identify: Send + Sync + std::fmt::Debug {
    async fn identify(
        &self,
        credentials: &crate::client::AssumeRoleResponse,
        target: &StsTarget,
    ) -> Result<Caller, String>;
}

/// `sts:GetCallerIdentity` against a [`StsTarget`], configured explicitly so that no `AWS_*` variable or shared
/// config file can redirect it.
#[derive(Debug, Default)]
pub struct Sts {
    http_client: Option<aws_smithy_runtime_api::client::http::SharedHttpClient>,
}

impl Sts {
    #[cfg(test)]
    fn with_http_client(
        http_client: aws_smithy_runtime_api::client::http::SharedHttpClient,
    ) -> Self {
        Self {
            http_client: Some(http_client),
        }
    }

    fn client(
        &self,
        credentials: &crate::client::AssumeRoleResponse,
        target: &StsTarget,
    ) -> aws_sdk_sts::Client {
        use secrecy::ExposeSecret;
        let credentials = aws_sdk_sts::config::Credentials::new(
            &credentials.access_key_id,
            credentials.secret_access_key.expose_secret(),
            credentials.session_token.clone(),
            None,
            "mairu",
        );
        let mut config = aws_sdk_sts::Config::builder()
            .behavior_version(aws_sdk_sts::config::BehaviorVersion::latest())
            .region(aws_sdk_sts::config::Region::new(target.region.clone()))
            .endpoint_url(&target.endpoint)
            .credentials_provider(credentials)
            .timeout_config(
                aws_sdk_sts::config::timeout::TimeoutConfig::builder()
                    .operation_timeout(STS_OPERATION_TIMEOUT)
                    .build(),
            );
        if let Some(http_client) = self
            .http_client
            .clone()
            .or_else(crate::network::sdk_http_client)
        {
            config = config.http_client(http_client);
        }
        aws_sdk_sts::Client::from_conf(config.build())
    }
}

#[async_trait::async_trait]
impl Identify for Sts {
    async fn identify(
        &self,
        credentials: &crate::client::AssumeRoleResponse,
        target: &StsTarget,
    ) -> Result<Caller, String> {
        let resp = self
            .client(credentials, target)
            .get_caller_identity()
            .send()
            .await
            .map_err(|e| {
                use std::error::Error;
                let mut message = e.to_string();
                let mut source = e.source();
                while let Some(s) = source {
                    message.push_str(&format!(": {s}"));
                    source = s.source();
                }
                message
            })?;
        let (Some(account), Some(arn), Some(user_id)) =
            (resp.account(), resp.arn(), resp.user_id())
        else {
            return Err("GetCallerIdentity returned an incomplete identity".to_owned());
        };
        Ok(Caller::new(
            account.to_owned(),
            arn.to_owned(),
            user_id.to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_arn() {
        let c = Caller::new(
            "999999999999".to_owned(),
            "arn:aws:sts::999999999999:assumed-role/Admin/alice@example.com".to_owned(),
            "AROAEXAMPLE:alice@example.com".to_owned(),
        );
        assert_eq!(c.r#type, CallerType::AssumedRole);
        assert_eq!(c.role_name.as_deref(), Some("Admin"));
        assert_eq!(c.session_name.as_deref(), Some("alice@example.com"));
        assert_eq!(c.summary(), "999999999999 assumed-role/Admin");

        for (arn, ty) in [
            ("arn:aws:iam::123456789012:user/bob", CallerType::User),
            (
                "arn:aws:iam::123456789012:user/division/team/bob",
                CallerType::User,
            ),
            (
                "arn:aws:sts::123456789012:federated-user/carol",
                CallerType::FederatedUser,
            ),
            ("arn:aws:iam::123456789012:root", CallerType::Root),
            ("arn:aws-cn:iam::123456789012:root", CallerType::Root),
            ("arn:aws:iam::123456789012:role/Admin", CallerType::Other),
            (
                "arn:aws:sts::123456789012:assumed-role/Admin",
                CallerType::Other,
            ),
            ("not an arn", CallerType::Other),
        ] {
            let (t, role, session) = parse_arn(arn);
            assert_eq!(t, ty, "{arn}");
            if t != CallerType::AssumedRole {
                assert_eq!((role, session), (None, None), "{arn}");
            }
        }
        assert_eq!(
            summary("arn:aws:iam::123456789012:user/division/bob"),
            "123456789012 user/division/bob"
        );
        assert_eq!(summary("garbage"), "garbage");
    }

    #[test]
    fn test_to_json() {
        let c = Caller::new(
            "123456789012".to_owned(),
            "arn:aws:iam::123456789012:user/bob".to_owned(),
            "AIDAEXAMPLE".to_owned(),
        );
        assert_eq!(
            c.to_json(),
            serde_json::json!({
                "account": "123456789012",
                "arn": "arn:aws:iam::123456789012:user/bob",
                "user_id": "AIDAEXAMPLE",
                "type": "user",
            })
        );
    }

    /// Answers every request with a fixed GetCallerIdentity response and records the requests.
    #[derive(Debug, Default, Clone)]
    struct FakeSts {
        requests: std::sync::Arc<parking_lot::Mutex<Vec<(String, String)>>>,
    }

    impl aws_smithy_runtime_api::client::http::HttpConnector for FakeSts {
        fn call(
            &self,
            request: aws_smithy_runtime_api::client::orchestrator::HttpRequest,
        ) -> aws_smithy_runtime_api::client::http::HttpConnectorFuture {
            let authorization = request
                .headers()
                .get("authorization")
                .unwrap_or_default()
                .to_owned();
            self.requests
                .lock()
                .push((request.uri().to_owned(), authorization));
            let body = r#"<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::999999999999:assumed-role/Admin/alice</Arn>
    <UserId>AROAEXAMPLE:alice</UserId>
    <Account>999999999999</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata><RequestId>00000000-0000-0000-0000-000000000000</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>"#;
            let response = aws_smithy_runtime_api::http::Response::new(
                200.try_into().unwrap(),
                aws_smithy_types::body::SdkBody::from(body),
            );
            aws_smithy_runtime_api::client::http::HttpConnectorFuture::ready(Ok(response))
        }
    }

    impl aws_smithy_runtime_api::client::http::HttpClient for FakeSts {
        fn http_connector(
            &self,
            _settings: &aws_smithy_runtime_api::client::http::HttpConnectorSettings,
            _components: &aws_smithy_runtime_api::client::runtime_components::RuntimeComponents,
        ) -> aws_smithy_runtime_api::client::http::SharedHttpConnector {
            aws_smithy_runtime_api::client::http::SharedHttpConnector::new(self.clone())
        }
    }

    fn credentials() -> crate::client::AssumeRoleResponse {
        crate::client::AssumeRoleResponse {
            version: 1,
            access_key_id: "ASIAEXAMPLE".to_owned(),
            secret_access_key: secrecy::SecretString::from("secret".to_owned()),
            session_token: Some("token".to_owned()),
            expiration: chrono::Utc::now() + chrono::TimeDelta::seconds(3600),
            mairu: Default::default(),
        }
    }

    async fn identify_through_fake() -> (Caller, Vec<(String, String)>) {
        identify_at(&StsTarget::default()).await
    }

    async fn identify_at(target: &StsTarget) -> (Caller, Vec<(String, String)>) {
        let fake = FakeSts::default();
        let sts = Sts::with_http_client(
            aws_smithy_runtime_api::client::http::SharedHttpClient::new(fake.clone()),
        );
        let caller = sts.identify(&credentials(), target).await.unwrap();
        let requests = fake.requests.lock().clone();
        (caller, requests)
    }

    fn assert_fixed_endpoint(caller: &Caller, requests: &[(String, String)]) {
        assert_eq!(caller.account, "999999999999");
        assert_eq!(caller.r#type, CallerType::AssumedRole);
        assert_eq!(requests.len(), 1);
        let (uri, authorization) = &requests[0];
        assert!(uri.starts_with("https://sts.amazonaws.com/"), "{uri}");
        assert!(
            authorization.contains("/us-east-1/sts/aws4_request"),
            "{authorization}"
        );
        assert!(authorization.contains("Credential=ASIAEXAMPLE/"));
    }

    #[tokio::test]
    async fn test_sts_fixed_endpoint() {
        let (caller, requests) = identify_through_fake().await;
        assert_fixed_endpoint(&caller, &requests);
    }

    #[tokio::test]
    async fn test_sts_target_from_settings() {
        let sts: crate::policy::settings::StsSettings = serde_json::from_value(serde_json::json!({
            "region": "eu-west-1",
            "servers": {"cn": {"region": "cn-north-1"}},
        }))
        .unwrap();
        assert_eq!(StsTarget::from_settings(None, "x"), StsTarget::default());
        let t = StsTarget::from_settings(Some(&sts), "contoso");
        assert_eq!(t.endpoint, "https://sts.eu-west-1.amazonaws.com");
        assert_eq!(t.region, "eu-west-1");
        let t = StsTarget::from_settings(Some(&sts), "cn");
        assert_eq!(t.endpoint, "https://sts.cn-north-1.amazonaws.com.cn");
        let sts: crate::policy::settings::StsSettings = serde_json::from_value(serde_json::json!({
            "region": "us-east-1",
            "endpoint": "https://vpce-0123.sts.us-east-1.vpce.amazonaws.com/",
        }))
        .unwrap();
        let t = StsTarget::from_settings(Some(&sts), "contoso");
        assert_eq!(
            t.endpoint,
            "https://vpce-0123.sts.us-east-1.vpce.amazonaws.com"
        );

        let (_, requests) = identify_at(&StsTarget::from_settings(
            Some(&serde_json::from_value(serde_json::json!({"region": "eu-west-1"})).unwrap()),
            "contoso",
        ))
        .await;
        assert!(
            requests[0]
                .0
                .starts_with("https://sts.eu-west-1.amazonaws.com/"),
            "{requests:?}"
        );
        assert!(requests[0].1.contains("/eu-west-1/sts/aws4_request"));
    }

    const ENV_CHILD: &str = "MAIRU_TEST_CALLER_IDENTITY_ENV_CHILD";

    /// Runs [`test_sts_ignores_environment_child`] in a child process whose environment points STS elsewhere;
    /// setting variables in this multi-threaded test process would race with other tests.
    #[test]
    fn test_sts_ignores_environment() {
        let dir = std::env::temp_dir().join(format!("mairu-test-sts-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config");
        std::fs::write(
            &config,
            "[profile evil]\nregion = eu-west-1\nendpoint_url = https://evil.invalid\n",
        )
        .unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "--ignored",
                "--nocapture",
                "caller_identity::tests::test_sts_ignores_environment_child",
            ])
            .env(ENV_CHILD, "1")
            .env("AWS_ENDPOINT_URL_STS", "https://evil.invalid")
            .env("AWS_ENDPOINT_URL", "https://evil.invalid")
            .env("AWS_REGION", "eu-west-1")
            .env("AWS_DEFAULT_REGION", "eu-west-1")
            .env("AWS_PROFILE", "evil")
            .env("AWS_CONFIG_FILE", &config)
            .env("AWS_USE_FIPS_ENDPOINT", "true")
            .env("AWS_USE_DUALSTACK_ENDPOINT", "true")
            .status()
            .unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert!(status.success());
    }

    #[tokio::test]
    #[ignore = "run by test_sts_ignores_environment"]
    async fn test_sts_ignores_environment_child() {
        assert_eq!(
            std::env::var(ENV_CHILD).as_deref(),
            Ok("1"),
            "run through test_sts_ignores_environment"
        );
        let (caller, requests) = identify_through_fake().await;
        assert_fixed_endpoint(&caller, &requests);
    }
}
