//! ECS Credentials Provider Server Implementation

#[derive(Debug, Clone)]
pub struct EcsServer<B, U>
where
    B: Backend + Send + Sync + Clone + std::fmt::Debug,
    U: UserFeedbackDelegate + Send + Sync + Clone + std::fmt::Debug,
{
    inner: std::sync::Arc<EcsServerInner<B, U>>,
}

impl<U> EcsServer<AgentBackend, U>
where
    U: UserFeedbackDelegate + Send + Sync + Clone + std::fmt::Debug + 'static,
{
    pub fn new_with_agent(
        agent: crate::agent::AgentConn,
        request: crate::proto::AssumeRoleRequest,
        feedback: U,
    ) -> EcsServer<AgentBackend, U> {
        EcsServer {
            inner: std::sync::Arc::new(EcsServerInner {
                bearer_token: generate_bearer_token(),
                backend: AgentBackend { agent, request },
                coalesce_group: crate::singleflight::Singleflight::new(),
                feedback,
            }),
        }
    }
}

impl<B, U> EcsServer<B, U>
where
    B: Backend + Send + Sync + Clone + std::fmt::Debug + 'static,
    U: UserFeedbackDelegate + Send + Sync + Clone + std::fmt::Debug + 'static,
{
    pub fn router(&self) -> axum::Router {
        axum::Router::new()
            .route(
                "/mairu/ecs/credentials",
                axum::routing::get(handle_get_credentials::<B, U>),
            )
            .layer(axum::extract::Extension(self.inner.clone()))
    }

    pub fn bearer_token(&self) -> &secrecy::SecretString {
        &self.inner.bearer_token
    }
}

#[derive(Debug)]
struct EcsServerInner<B, U>
where
    B: Backend + Send + Sync + Clone + std::fmt::Debug,
    U: UserFeedbackDelegate,
{
    bearer_token: secrecy::SecretString,
    backend: B,
    feedback: U,
    coalesce_group: crate::singleflight::Singleflight<
        u8,
        std::sync::Arc<Result<crate::proto::AssumeRoleResponse, BackendRequestError>>,
    >,
}

impl<B, U> EcsServerInner<B, U>
where
    B: Backend + Send + Sync + Clone + 'static,
    U: UserFeedbackDelegate,
{
    fn verify_token(&self, other: &secrecy::SecretString) -> crate::Result<()> {
        use secrecy::ExposeSecret;
        use subtle::ConstantTimeEq;

        if self
            .bearer_token
            .expose_secret()
            .as_bytes()
            .ct_eq(other.expose_secret().as_ref())
            .unwrap_u8()
            == 1
        {
            return Ok(());
        }

        Err(crate::Error::AuthError("unauthorized".to_owned()))
    }

    async fn request(
        &self,
    ) -> std::sync::Arc<Result<crate::proto::AssumeRoleResponse, BackendRequestError>> {
        self.coalesce_group
            .request(0, || {
                tracing::debug!(server = ?self, "requesting credentials to backend");
                let mut backend = self.backend.clone();
                async move { backend.request_arc().await }
            })
            .await
    }
}

#[async_trait::async_trait]
pub trait Backend: Send + Sync + Clone + std::fmt::Debug {
    async fn request(&mut self) -> Result<crate::proto::AssumeRoleResponse, BackendRequestError>;

    async fn request_arc(
        &mut self,
    ) -> std::sync::Arc<Result<crate::proto::AssumeRoleResponse, BackendRequestError>> {
        std::sync::Arc::new(self.request().await)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BackendRequestError {
    #[error(transparent)]
    Forbidden(crate::Error),
    #[error(transparent)]
    Unauthorized(crate::Error),
    #[error(transparent)]
    Unknown(crate::Error),
}

impl BackendRequestError {
    pub fn ui_message(&self) -> String {
        match self {
            BackendRequestError::Forbidden(crate::Error::TonicStatusError(e)) => {
                format!("{:?}, {}", e.code(), e.message())
            }
            BackendRequestError::Unauthorized(crate::Error::TonicStatusError(e)) => {
                format!("{:?}, {}", e.code(), e.message())
            }
            BackendRequestError::Unknown(e) => e.to_string(),
            _ => self.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AgentBackend {
    pub agent: crate::agent::AgentConn,
    pub request: crate::proto::AssumeRoleRequest,
}

#[async_trait::async_trait]
impl Backend for AgentBackend {
    async fn request(&mut self) -> Result<crate::proto::AssumeRoleResponse, BackendRequestError> {
        tracing::debug!(request = ?self.request, agent = ?self.agent, "requesting credentials to agent");
        let resp = self.agent.assume_role(self.request.clone()).await;
        match resp {
            Ok(r) => Ok(r.into_inner()),
            Err(e) => {
                tracing::warn!(request = ?self.request, agent = ?self.agent, err = ?e, "agent returned error for credentials request");
                match e.code() {
                    tonic::Code::Unauthenticated => {
                        Err(BackendRequestError::Unauthorized(e.into()))
                    }
                    tonic::Code::PermissionDenied => Err(BackendRequestError::Forbidden(e.into())),
                    _ => Err(BackendRequestError::Unknown(e.into())),
                }
            }
        }
    }
}

pub trait UserFeedbackDelegate: Send + Sync + Clone + std::fmt::Debug {
    fn on_error(&self, err: &BackendRequestError);
}

#[derive(Debug, Clone)]
pub struct NoUserFeedback;

impl UserFeedbackDelegate for NoUserFeedback {
    fn on_error(&self, _err: &BackendRequestError) {}
}

pub async fn bind_tcp(port: Option<u16>) -> crate::Result<(tokio::net::TcpListener, url::Url)> {
    // FIXME: IPv6
    let bindaddr =
        std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), port.unwrap_or(0));
    let sock = tokio::net::TcpListener::bind(bindaddr).await?;
    let addr = sock.local_addr()?;
    let mut url = url::Url::parse("http://127.0.0.1/mairu/ecs/credentials")?;
    url.set_port(Some(addr.port())).unwrap();
    tracing::debug!(url = %url, "Listening TCP");
    Ok((sock, url))
}

fn generate_bearer_token() -> secrecy::SecretString {
    use base64ct::Encoding;
    use rand::RngCore;
    let mut buf = zeroize::Zeroizing::new([0u8; 64]);
    rand::thread_rng().fill_bytes(buf.as_mut());
    base64ct::Base64UrlUnpadded::encode_string(buf.as_ref()).into()
}

#[tracing::instrument(skip_all)]
async fn handle_get_credentials<B: Backend + 'static, U: UserFeedbackDelegate>(
    crate::ext_axum::ExtractBearer {
        value: bearer,
        source: _,
    }: crate::ext_axum::ExtractBearer,
    axum::extract::Extension(server): axum::extract::Extension<
        std::sync::Arc<EcsServerInner<B, U>>,
    >,
) -> axum::response::Result<axum::response::Response> {
    use axum::response::IntoResponse;

    if server.verify_token(&bearer).is_err() {
        tracing::error!("Unauthorized credentials request received");
        return Ok((
            axum::http::StatusCode::UNAUTHORIZED,
            "unauthorized".to_owned(),
        )
            .into_response());
    }

    tracing::debug!(server = ?server, "received credentials request");
    let resp = server.request().await;
    match resp.as_ref() {
        Err(be) => {
            tracing::debug!(err = ?be, server = ?server, "ecs_server backend returned error during credential retrieval");
            let code = match &be {
                BackendRequestError::Unauthorized(e) => {
                    tracing::warn!(err = ?e, err_human = %e, server = ?server, "credential request was denied (unauthorized)");
                    server.feedback.on_error(&be);
                    axum::http::StatusCode::SERVICE_UNAVAILABLE
                }
                BackendRequestError::Forbidden(e) => {
                    tracing::warn!(err = ?e, err_human = %e, server = ?server, "credential request was denied (forbidden)");
                    server.feedback.on_error(&be);
                    axum::http::StatusCode::FORBIDDEN
                }
                BackendRequestError::Unknown(e) => {
                    tracing::warn!(err = ?e, err_human = %e, server = ?server, "credential request returned an unknown error");
                    server.feedback.on_error(&be);
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR
                }
            };
            Ok((code, "error".to_owned()).into_response())
        }
        Ok(r) => match r.credentials.as_ref() {
            None => {
                tracing::error!(server = ?server, "agent returned a response without credentials");
                Ok((
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "error".to_owned(),
                )
                    .into_response())
            }
            Some(c) => {
                tracing::info!(server = ?server, aws_access_key_id = ?c.access_key_id, expiration = ?c.expiration, "vending retrieved credentials to client");
                let response = ContainerCredentialsResponse::from(c);
                Ok(axum::Json(response).into_response())
            }
        },
    }
}

/// https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html
#[derive(Clone, Debug, serde::Serialize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerCredentialsResponse {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub token: Option<String>,
    #[zeroize(skip)]
    pub expiration: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<&crate::proto::Credentials> for ContainerCredentialsResponse {
    fn from(cred: &crate::proto::Credentials) -> ContainerCredentialsResponse {
        ContainerCredentialsResponse {
            access_key_id: cred.access_key_id.clone(),
            secret_access_key: cred.secret_access_key.clone(),
            token: if cred.session_token.is_empty() {
                None
            } else {
                Some(cred.session_token.clone())
            },
            expiration: cred
                .expiration
                .as_ref()
                .and_then(|ts| std::time::SystemTime::try_from(ts.clone()).ok())
                .map(|st| -> chrono::DateTime<chrono::Utc> { chrono::DateTime::from(st) }),
        }
    }
}
