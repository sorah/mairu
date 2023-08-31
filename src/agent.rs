use crate::proto::*;

#[derive(Default)]
pub struct Agent {
    auth_flow_manager: crate::auth_flow_manager::AuthFlowManager,
    token_manager: crate::token_manager::TokenManager,
}

impl Agent {
    pub fn new() -> Self {
        Self {
            auth_flow_manager: crate::auth_flow_manager::AuthFlowManager::new(),
            token_manager: crate::token_manager::TokenManager::new(),
        }
    }
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent").finish()
    }
}

#[tonic::async_trait]
impl crate::proto::agent_server::Agent for Agent {
    #[tracing::instrument]
    async fn ping_agent(
        &self,
        _request: tonic::Request<PingAgentRequest>,
    ) -> Result<tonic::Response<PingAgentResponse>, tonic::Status> {
        Ok(tonic::Response::new(PingAgentResponse {
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }))
    }

    #[tracing::instrument]
    async fn get_server(
        &self,
        request: tonic::Request<GetServerRequest>,
    ) -> Result<tonic::Response<GetServerResponse>, tonic::Status> {
        let query = &request.get_ref().query;
        if !request.get_ref().no_cache {
            if let Ok(token) = self.token_manager.get(query) {
                let json = serde_json::to_string(&token.server)
                    .map_err(|e| tonic::Status::internal(e.to_string()))?;
                return Ok(tonic::Response::new(GetServerResponse {
                    json,
                    cached: true,
                }));
            }
        }
        match crate::config::Server::find_from_fs(query).await {
            Ok(server) => {
                let json = serde_json::to_string(&server)
                    .map_err(|e| tonic::Status::internal(e.to_string()))?;
                Ok(tonic::Response::new(GetServerResponse {
                    json,
                    cached: false,
                }))
            }
            Err(crate::Error::ConfigError(e)) => Err(tonic::Status::internal(e)),
            Err(crate::Error::UserError(e)) => Err(tonic::Status::not_found(e)),
            Err(e) => Err(tonic::Status::internal(e.to_string())),
        }
    }

    #[tracing::instrument]
    async fn initiate_oauth_code(
        &self,
        request: tonic::Request<InitiateOAuthCodeRequest>,
    ) -> Result<tonic::Response<InitiateOAuthCodeResponse>, tonic::Status> {
        let req = request.get_ref();

        let server = match crate::config::Server::find_from_fs(&req.server_id).await {
            Ok(server) => server,
            Err(crate::Error::ConfigError(e)) => return Err(tonic::Status::internal(e)),
            Err(crate::Error::UserError(e)) => return Err(tonic::Status::not_found(e)),
            Err(e) => return Err(tonic::Status::internal(e.to_string())),
        };
        server.validate().map_err(|e| {
            tonic::Status::failed_precondition(format!(
                "Server '{}' has invalid configuration; {:}",
                server.id(),
                e,
            ))
        })?;

        let redirect_url = url::Url::parse(&req.redirect_url)
            .map_err(|e| tonic::Status::invalid_argument(format!("Bad Redirect URL: {:}", e)))?;

        let flow =
            crate::oauth_code::OAuthCodeFlow::initiate(&server, &redirect_url).map_err(|e| {
                tracing::error!(err = ?e, "OAuthCodeFlow initiate failure");
                tonic::Status::internal(e.to_string())
            })?;

        let response = (&flow).into();

        self.auth_flow_manager
            .store(crate::auth_flow_manager::AuthFlow::OAuthCode(flow));

        return Ok(tonic::Response::new(response));
    }

    #[tracing::instrument]
    async fn complete_oauth_code(
        &self,
        request: tonic::Request<CompleteOAuthCodeRequest>,
    ) -> Result<tonic::Response<CompleteOAuthCodeResponse>, tonic::Status> {
        let req = request.get_ref();
        let Some(flow0) = self.auth_flow_manager.retrieve(&req.handle) else {
            return Err(tonic::Status::not_found("flow handle not found"));
        };

        let crate::auth_flow_manager::AuthFlow::OAuthCode(flow) = flow0.as_ref() else {
            return Err(tonic::Status::invalid_argument(
                "flow handle is not for the grant type",
            ));
        };

        let token = match flow.complete(request.into_inner()).await {
            Ok(t) => t,
            Err(crate::Error::AuthError(x)) => {
                tracing::error!(err = ?x, "OAuthCodeFlow complete failure");
                return Err(tonic::Status::invalid_argument(x));
            }
            Err(e) => {
                tracing::error!(err = ?e, "OAuthCodeFlow complete failure");
                return Err(tonic::Status::unknown(e.to_string()));
            }
        };
        flow0.mark_as_done(); // authorization codes cannot be reused, so mark as done now (whlist
                              // later lines may fail)
        self.token_manager
            .add(token)
            .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?;

        Ok(tonic::Response::new(CompleteOAuthCodeResponse {}))
    }
}

pub type AgentConn = crate::proto::agent_client::AgentClient<tonic::transport::Channel>;
pub async fn connect_to_agent() -> crate::Result<AgentConn> {
    connect_to_agent_with_path(crate::config::socket_path()).await
}
pub async fn connect_to_agent_with_path(
    path_: impl AsRef<std::path::Path>,
) -> crate::Result<AgentConn> {
    // https://github.com/hyperium/tonic/blob/master/examples/src/uds/client.rs
    // url is unused for connection
    let path = path_.as_ref().to_path_buf();
    let ch = tonic::transport::Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(tower::service_fn(move |_| {
            tokio::net::UnixStream::connect(path.clone())
        }))
        .await?;

    let mut client = crate::proto::agent_client::AgentClient::new(ch);
    client
        .ping_agent(tonic::Request::new(crate::proto::PingAgentRequest {}))
        .await?;

    Ok(client)
}
