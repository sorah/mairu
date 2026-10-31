//! The agent's outbound connections. An approved `authorization.json` may set a proxy and extra TLS roots, trusted in
//! addition to the system roots; otherwise a hardened agent connects directly and trusts the system roots only.

/// The clients built for the settings in force.
#[derive(Debug)]
struct Clients {
    settings: Option<crate::policy::settings::NetworkSettings>,
    http: reqwest::Client,
    /// `None` leaves the AWS SDK's default client in place.
    sdk: Option<aws_smithy_runtime_api::client::http::SharedHttpClient>,
}

static CURRENT: std::sync::LazyLock<parking_lot::RwLock<std::sync::Arc<Clients>>> =
    std::sync::LazyLock::new(|| {
        parking_lot::RwLock::new(std::sync::Arc::new(Clients::default_clients()))
    });

impl Clients {
    fn default_clients() -> Self {
        Self {
            settings: None,
            http: http_builder().build().expect("the default HTTP client"),
            sdk: None,
        }
    }

    fn build(settings: &crate::policy::settings::NetworkSettings) -> Result<Self, String> {
        Ok(Self {
            settings: Some(settings.clone()),
            http: configured_http(settings)?,
            sdk: Some(configured_sdk(settings)?),
        })
    }
}

fn http_builder() -> reqwest::ClientBuilder {
    let builder = reqwest::ClientBuilder::new()
        .user_agent(format!(
            "{}/{}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ))
        .redirect(reqwest::redirect::Policy::none());
    // A proxy is set by same-user code, which a hardened agent does not trust with session tokens.
    if crate::hardening::Hardening::marker().is_some() {
        builder.no_proxy()
    } else {
        builder
    }
}

fn configured_http(
    settings: &crate::policy::settings::NetworkSettings,
) -> Result<reqwest::Client, String> {
    let mut builder = http_builder().no_proxy();
    if let Some(proxy) = &settings.proxy {
        builder = builder.proxy(reqwest::Proxy::all(proxy.as_str()).map_err(|e| e.to_string())?);
    }
    for pem in &settings.extra_roots {
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(pem.as_bytes()).map_err(|e| e.to_string())?,
        );
    }
    builder.build().map_err(|e| e.to_string())
}

fn configured_sdk(
    settings: &crate::policy::settings::NetworkSettings,
) -> Result<aws_smithy_runtime_api::client::http::SharedHttpClient, String> {
    use aws_smithy_http_client::{proxy::ProxyConfig, tls};
    let mut trust_store = tls::TrustStore::default().with_native_roots(true);
    for pem in &settings.extra_roots {
        trust_store.add_pem_certificate(pem.as_bytes().to_vec());
    }
    let tls_context = tls::TlsContext::builder()
        .with_trust_store(trust_store)
        .build()
        .map_err(|e| e.to_string())?;
    let proxy = match &settings.proxy {
        Some(url) => ProxyConfig::all(url.as_str()).map_err(|e| e.to_string())?,
        None => ProxyConfig::disabled(),
    };
    Ok(
        aws_smithy_http_client::Builder::new().build_with_connector_fn(
            move |connector_settings, runtime_components| {
                let mut builder = aws_smithy_http_client::Connector::builder();
                builder.set_connector_settings(connector_settings.cloned());
                if let Some(components) = runtime_components {
                    builder.set_sleep_impl(components.sleep_impl());
                }
                builder
                    .proxy_config(proxy.clone())
                    .tls_provider(tls::Provider::Rustls(
                        tls::rustls_provider::CryptoMode::AwsLc,
                    ))
                    .tls_context(tls_context.clone())
                    .build()
            },
        ),
    )
}

/// Puts `settings` in force, rebuilding the clients when they changed. `None` restores the defaults.
pub fn apply(settings: Option<&crate::policy::settings::NetworkSettings>) {
    if CURRENT.read().settings.as_ref() == settings {
        return;
    }
    let clients = match settings {
        None => Clients::default_clients(),
        Some(s) => match Clients::build(s) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    err = e,
                    "Failed to build clients for the approved network settings; using the defaults"
                );
                Clients::default_clients()
            }
        },
    };
    tracing::info!(
        proxy = settings.and_then(|s| s.proxy.as_ref()).map(|u| u.as_str()),
        extra_roots = settings.map_or(0, |s| s.extra_roots.len()),
        "Outbound connection settings changed"
    );
    *CURRENT.write() = std::sync::Arc::new(clients);
}

/// The HTTP client for credential servers and OAuth endpoints.
pub fn http() -> reqwest::Client {
    CURRENT.read().http.clone()
}

/// The HTTP client for AWS SDK clients; `None` keeps the SDK's default.
pub fn sdk_http_client() -> Option<aws_smithy_runtime_api::client::http::SharedHttpClient> {
    CURRENT.read().sdk.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A self-signed certificate for "example.com".
    const CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBgzCCASmgAwIBAgIUEDgCz6ZhH3oNclSxpavYJ+7Ot+cwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wIBcNMjYxMDMxMDA0NjM1WhgPMjEyNjEw
MDcwMDQ2MzVaMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEKtIB7uCunWTPV0ygrW7QGORJVm7va52RqqC22jtu05GC2bIP
shjt1p+vMEmXbodiXaP0GOc3wLueekf6RQlAG6NTMFEwHQYDVR0OBBYEFB0t+Xi9
ZYQxxEHwv8r2aR4DZrXlMB8GA1UdIwQYMBaAFB0t+Xi9ZYQxxEHwv8r2aR4DZrXl
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgDkKdwrVsjQ7oXxRX
7SdlxC6KrKdcXWRfueK/7wFLo8sCIQDC7L0+2uBLGfjI8ojTSlcg24kSsNzjKSxG
XLz4KNOFkg==
-----END CERTIFICATE-----";

    fn settings(proxy: Option<&str>) -> crate::policy::settings::NetworkSettings {
        crate::policy::settings::NetworkSettings {
            proxy: proxy.map(|p| p.parse().unwrap()),
            extra_roots: vec![CERT.to_owned()],
        }
    }

    /// Accepts one connection and returns its request head.
    async fn first_request(listener: tokio::net::TcpListener) -> String {
        use tokio::io::AsyncReadExt;
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    #[test]
    fn test_build() {
        assert!(Clients::build(&settings(Some("http://proxy.example:3128"))).is_ok());
        assert!(Clients::build(&settings(None)).unwrap().sdk.is_some());
        let mut bad = settings(None);
        bad.extra_roots = vec!["junk".to_owned()];
        assert!(Clients::build(&bad).is_err());
    }

    #[tokio::test]
    async fn test_reqwest_goes_through_the_proxy() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let client = configured_http(&settings(Some(&proxy))).unwrap();
        let request = tokio::spawn(async move {
            let _ = client
                .get("https://cred.invalid/assume-role")
                .timeout(std::time::Duration::from_secs(2))
                .send()
                .await;
        });
        let head = first_request(listener).await;
        assert!(head.starts_with("CONNECT cred.invalid:443 "), "{head}");
        request.abort();
    }

    #[tokio::test]
    async fn test_sdk_goes_through_the_proxy() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let http_client = configured_sdk(&settings(Some(&proxy))).unwrap();
        let config = aws_sdk_sts::Config::builder()
            .behavior_version(aws_sdk_sts::config::BehaviorVersion::latest())
            .region(aws_sdk_sts::config::Region::from_static("us-east-1"))
            .credentials_provider(aws_sdk_sts::config::Credentials::new(
                "AKIDEXAMPLE",
                "secret",
                None,
                None,
                "test",
            ))
            .http_client(http_client)
            .build();
        let request = tokio::spawn(async move {
            let _ = aws_sdk_sts::Client::from_conf(config)
                .get_caller_identity()
                .send()
                .await;
        });
        let head = first_request(listener).await;
        assert!(
            head.starts_with("CONNECT sts.us-east-1.amazonaws.com:443 ")
                || head.starts_with("CONNECT sts.amazonaws.com:443 "),
            "{head}"
        );
        request.abort();
    }
}
