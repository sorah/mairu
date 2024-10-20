#[derive(Debug)]
pub struct OAuthCodeFlow {
    pub handle: String,
    server: crate::config::Server,
    redirect_url: url::Url,
    authorize_url: url::Url,
    csrf_token: oauth2::CsrfToken,
    pkce_verifier: secrecy::SecretString, // oauth2::PkceCodeVerifier,
}

impl From<&OAuthCodeFlow> for crate::proto::InitiateOAuthCodeResponse {
    fn from(flow: &OAuthCodeFlow) -> crate::proto::InitiateOAuthCodeResponse {
        crate::proto::InitiateOAuthCodeResponse {
            handle: flow.handle.clone(),
            authorize_url: flow.authorize_url.to_string(),
        }
    }
}

impl OAuthCodeFlow {
    pub fn initiate(
        server: &crate::config::Server,
        redirect_url: &url::Url,
    ) -> crate::Result<Self> {
        let client = oauth2_client_from_server(server)?
            .set_redirect_uri(oauth2::RedirectUrl::from_url(redirect_url.clone()));
        let (oauth, _) = server.try_oauth_code_grant()?;
        let (pkce_challenge, pkce_verifier) = generate_pkce_challenge();
        let request = client
            .authorize_url(oauth2::CsrfToken::new_random)
            .add_scopes(oauth.scope.iter().map(|x| oauth2::Scope::new(x.to_owned())))
            .set_pkce_challenge(pkce_challenge);
        let (authorize_url, csrf_token) = request.url();
        let handle = crate::utils::generate_flow_handle();
        tracing::info!(server = ?server, handle = ?handle, "Initiating OAuth 2.0 Authorization Code flow");
        Ok(Self {
            handle,
            server: server.to_owned(),
            redirect_url: redirect_url.clone(),
            authorize_url,
            csrf_token,
            pkce_verifier,
        })
    }

    pub async fn complete(
        &self,
        completion: crate::proto::CompleteOAuthCodeRequest,
    ) -> crate::Result<crate::token::ServerToken> {
        use secrecy::ExposeSecret;
        tracing::info!(flow = ?self, "Completing OAuth 2.0 Authorization Code flow");

        let client = oauth2_client_from_server(&self.server)?
            .set_redirect_uri(oauth2::RedirectUrl::from_url(self.redirect_url.clone()));
        if self.csrf_token.secret() != &completion.state {
            return Err(crate::Error::AuthError("csrf detected".to_owned()));
        }
        let req = client
            .exchange_code(oauth2::AuthorizationCode::new(completion.code))
            .set_pkce_verifier(oauth2::PkceCodeVerifier::new(
                self.pkce_verifier.expose_secret().to_owned(),
            ));
        let resp = req.request_async(&crate::client::http()).await?;
        Ok(crate::token::ServerToken::from_token_response(
            self.server.clone(),
            resp,
        ))
    }
}

// We can't use oauth2 provided method where prohibits cloning strings
fn generate_pkce_challenge() -> (oauth2::PkceCodeChallenge, secrecy::SecretString) {
    use base64::Engine;
    use rand::RngCore;
    use secrecy::ExposeSecret;

    let mut buf = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut buf);
    let verifier_raw =
        secrecy::SecretString::new(base64::engine::general_purpose::URL_SAFE.encode(buf).into());
    let verifier = oauth2::PkceCodeVerifier::new(verifier_raw.expose_secret().to_owned());

    (
        oauth2::PkceCodeChallenge::from_code_verifier_sha256(&verifier),
        verifier_raw,
    )
}

fn oauth2_client_from_server(
    server: &crate::config::Server,
) -> crate::Result<
    crate::ext_oauth2::SecrecyClient<
        oauth2::EndpointSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointSet,
    >,
> {
    let (oauth, code_grant) = server.try_oauth_code_grant()?;

    let client = crate::ext_oauth2::SecrecyClient::new(oauth2::ClientId::new(oauth.client_id.clone()))
        .set_client_secret(
            oauth2::ClientSecret::new(
                oauth
                    .client_secret
                    .clone()
                    .ok_or_else(|| crate::Error::ConfigError(format!("Server '{}' is missing OAuth 2.0 Client Secret; Required for Authorization Code Grant", server.id())))?
            )
        )
        .set_auth_uri(oauth2::AuthUrl::from_url(
            code_grant
                .authorization_endpoint
                .clone()
                .map(Ok)
                .unwrap_or_else(|| server.url.join("oauth/authorize"))?,
        ))
        .set_token_uri(oauth2::TokenUrl::from_url(
                    oauth
                        .token_endpoint
                        .clone()
                        .map(Ok)
                        .unwrap_or_else(|| server.url.join("oauth/token"))?,
        ));
    Ok(client)
}

pub async fn bind_tcp_for_callback(
    port: Option<u16>,
) -> crate::Result<(tokio::net::TcpListener, url::Url)> {
    // FIXME: IPv6
    let bindaddr =
        std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), port.unwrap_or(0));
    let sock = tokio::net::TcpListener::bind(bindaddr).await?;
    let addr = sock.local_addr()?;
    let mut url = url::Url::parse("http://127.0.0.1/oauth2callback")?;
    url.set_port(Some(addr.port())).unwrap();
    tracing::debug!(url = %url, "Listening TCP for Callback");
    Ok((sock, url))
}

struct OneoffServerContext {
    result_tx: tokio::sync::mpsc::Sender<()>,
    session: crate::proto::InitiateOAuthCodeResponse,
}

pub async fn listen_for_callback(
    listener: tokio::net::TcpListener,
    session: crate::proto::InitiateOAuthCodeResponse,
    agent: &crate::agent::AgentConn,
) -> crate::Result<()> {
    use std::future::IntoFuture;

    // crate::token::ServerToken
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let (result_tx, mut result_rx) = tokio::sync::mpsc::channel::<()>(1);

    let context = std::sync::Arc::new(OneoffServerContext { result_tx, session });
    let conn = agent.clone();
    let app = axum::Router::new()
        .route("/oauth2callback", axum::routing::get(callback))
        .layer(axum::extract::Extension(conn))
        .layer(axum::extract::Extension(context));

    let server = axum::serve(listener, app)
        .with_graceful_shutdown(async {
            shutdown_rx.await.ok();
            tracing::trace!("Server shutting down");
        })
        .into_future();

    tracing::debug!("Server started");

    tokio::select! {
        r = server => {
            shutdown_tx.send(()).ok();
            tracing::error!(r = ?r, "server returned before receiving result");
            return match r {
                Err(e) => Err(e.into()),
                Ok(_) => Err(crate::Error::AuthError("server returned before receiving result".to_owned())),
            }
        },
        r = result_rx.recv() => {
            if r.is_none() {
                tracing::error!("result_rx.recv returned None");
                return Err(crate::Error::AuthError("result_rx channel dropped without result".to_owned()));
            }
            tracing::debug!("Server completed its job");
        }
    }
    shutdown_tx.send(()).ok();
    Ok(())
}

#[derive(Debug, serde::Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

/// HTML <head> to supress favicon.ico request
const HTML_PREAMBLE: &str = r#"<!DOCTYPE html><html><head><link rel="icon" href="data:;base64,iVBORw0KGgo="><style>body { font-family: monospace; }</style></head><body>"#;

#[allow(clippy::type_complexity)]
#[tracing::instrument(skip_all)]
async fn callback(
    query: axum::extract::Query<CallbackQuery>,
    axum::extract::Extension(context): axum::extract::Extension<
        std::sync::Arc<OneoffServerContext>,
    >,
    axum::extract::Extension(mut agent): axum::extract::Extension<crate::agent::AgentConn>,
) -> axum::response::Result<(
    axum::http::StatusCode,
    [(&'static str, &'static str); 1],
    String,
)> {
    tracing::debug!("Processing oauth2 callback");
    let completion = agent
        .complete_oauth_code(tonic::Request::new(
            crate::proto::CompleteOAuthCodeRequest {
                handle: context.session.handle.clone(),
                code: query.code.clone(),
                state: query.state.clone(),
            },
        ))
        .await;

    match completion {
        Ok(_) => tracing::debug!("CompleteOauthCode succeeded"),
        Err(e) => {
            // FIXME: 4xx is 4xx
            tracing::error!(e = ?e, "CompleteOauthCode RPC returned an error");
            return Ok((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                [("content-type", "text/html; charset=utf-8")],
                format!(
                    "{}Error, agent response; status={}, message={}",
                    HTML_PREAMBLE,
                    e.code(),
                    e.message()
                ),
            ));
        }
    }

    context.result_tx.send(()).await.ok();

    Ok((
        axum::http::StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        format!("{}ok", HTML_PREAMBLE),
    ))
}
