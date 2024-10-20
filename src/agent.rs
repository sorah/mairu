use crate::proto::*;

#[derive(Default)]
pub struct Agent {
    auth_flow_manager: crate::auth_flow_manager::AuthFlowManager,
    session_manager: crate::session_manager::SessionManager,
}

impl Agent {
    pub fn new() -> Self {
        Self {
            auth_flow_manager: crate::auth_flow_manager::AuthFlowManager::new(),
            session_manager: crate::session_manager::SessionManager::new(),
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
    #[tracing::instrument(skip_all)]
    async fn ping_agent(
        &self,
        _request: tonic::Request<PingAgentRequest>,
    ) -> Result<tonic::Response<PingAgentResponse>, tonic::Status> {
        Ok(tonic::Response::new(PingAgentResponse {
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }))
    }

    #[tracing::instrument(skip_all)]
    async fn get_server(
        &self,
        request: tonic::Request<GetServerRequest>,
    ) -> Result<tonic::Response<GetServerResponse>, tonic::Status> {
        let query = &request.get_ref().query;
        if !request.get_ref().no_cache {
            if let Ok(session) = self.session_manager.get(query) {
                let json = serde_json::to_string(&session.token.server)
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

    #[tracing::instrument(skip_all)]
    async fn assume_role(
        &self,
        request: tonic::Request<AssumeRoleRequest>,
    ) -> Result<tonic::Response<AssumeRoleResponse>, tonic::Status> {
        let query = &request.get_ref().server_id;
        let role = &request.get_ref().role;
        let Ok(session) = self.session_manager.get(query) else {
            if let Err(e) = crate::config::Server::find_from_fs(query).await {
                tracing::warn!(server_id = ?query, role = ?role, err = ?e, "requested server doesn't exist or is invalid");
                return Err(tonic::Status::not_found(
                    "requested server doesn't exist or is invalid",
                ));
            } else {
                tracing::warn!(server_id = ?query, role = ?role, "session doesn't exist, require authentication");
                return Err(tonic::Status::unauthenticated("authentication needed"));
            }
        };

        // tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        if request.get_ref().cached {
            if let Some(cache) = session.credential_cache.get(role) {
                tracing::info!(server_id = ?session.token.server.id(), server_url = %session.token.server.url, role = ?role, aws_access_key_id = ?cache.credentials.access_key_id, ext = ?cache.credentials.mairu, "Vending credentials from cache");
                return Ok(tonic::Response::new(cache.credentials.as_ref().into()));
            }
        }
        tracing::debug!(server_id = ?session.token.server.id(), server_url = %session.token.server.url, role = ?role, "Obtaining credentials from server");
        let client = crate::api_client::Client::from(session.token.as_ref());
        match client.assume_role(role).await {
            Ok(r) => {
                if request.get_ref().cached {
                    session.credential_cache.store(role.to_owned(), &r);
                }
                tracing::info!(server_id = ?session.token.server.id(), server_url = %session.token.server.url, role = ?role, aws_access_key_id = ?r.access_key_id, ext = ?r.mairu, "Vending credentials from server");
                Ok(tonic::Response::new((&r).into()))
            }
            Err(crate::Error::ApiError {
                url: _url,
                status_code,
                message,
            }) => match status_code {
                reqwest::StatusCode::BAD_REQUEST => Err(tonic::Status::invalid_argument(message)),
                reqwest::StatusCode::UNAUTHORIZED => Err(tonic::Status::unauthenticated(message)),
                reqwest::StatusCode::FORBIDDEN => Err(tonic::Status::permission_denied(message)),
                reqwest::StatusCode::TOO_MANY_REQUESTS => {
                    Err(tonic::Status::resource_exhausted(message))
                }
                reqwest::StatusCode::NOT_FOUND => Err(tonic::Status::not_found(message)),
                _ => Err(tonic::Status::unknown(format!(
                    "{}: {}",
                    status_code, message
                ))),
            },
            Err(e) => {
                tracing::error!(server_id = ?session.token.server.id(), server_url = %session.token.server.url, role = ?role, err = ?e, "assume-role API returned error");
                Err(tonic::Status::unknown(e.to_string()))
            }
        }
    }

    #[tracing::instrument(skip_all)]
    async fn list_sessions(
        &self,
        _request: tonic::Request<ListSessionsRequest>,
    ) -> Result<tonic::Response<ListSessionsResponse>, tonic::Status> {
        let sessions = self
            .session_manager
            .list()
            .iter()
            .map(|x| x.into())
            .collect();
        Ok(tonic::Response::new(ListSessionsResponse { sessions }))
    }

    #[tracing::instrument(skip_all)]
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

        tracing::debug!(flow = ?flow, "Initiated OAuth 2.0 Authorization Code flow");
        self.auth_flow_manager
            .store(crate::auth_flow_manager::AuthFlow::OAuthCode(flow));

        return Ok(tonic::Response::new(response));
    }

    #[tracing::instrument(skip_all)]
    async fn complete_oauth_code(
        &self,
        request: tonic::Request<CompleteOAuthCodeRequest>,
    ) -> Result<tonic::Response<CompleteOAuthCodeResponse>, tonic::Status> {
        let req = request.get_ref();
        let Some(flow0) = self.auth_flow_manager.retrieve(&req.handle) else {
            return Err(tonic::Status::not_found("flow handle not found"));
        };
        let completion = {
            let crate::auth_flow_manager::AuthFlow::OAuthCode(flow) = flow0.as_ref() else {
                return Err(tonic::Status::invalid_argument(
                    "flow handle is not for the grant type",
                ));
            };
            tracing::debug!(flow = ?flow0.as_ref(), "Completing OAuth 2.0 Authorization Code flow...");
            flow.complete(request.into_inner()).await
        };

        self.accept_completed_auth_flow(flow0, completion)?;

        Ok(tonic::Response::new(CompleteOAuthCodeResponse {}))
    }

    #[tracing::instrument(skip_all)]
    async fn refresh_aws_sso_client_registration(
        &self,
        request: tonic::Request<RefreshAwsSsoClientRegistrationRequest>,
    ) -> Result<tonic::Response<RefreshAwsSsoClientRegistrationResponse>, tonic::Status> {
        let req = request.get_ref();

        let mut server = match crate::config::Server::find_from_fs(&req.server_id).await {
            Ok(server) => server,
            Err(crate::Error::ConfigError(e)) => return Err(tonic::Status::internal(e)),
            Err(crate::Error::UserError(e)) => return Err(tonic::Status::not_found(e)),
            Err(e) => return Err(tonic::Status::internal(e.to_string())),
        };

        tracing::info!(server_id = ?server.id(), server_url = %server.url, "Refreshing AWS SSO Client Registration");

        // XXX: validate checks .oauth existence...
        //server.validate().map_err(|e| {
        //    tonic::Status::failed_precondition(format!(
        //        "Server '{}' has invalid configuration; {:}",
        //        server.id(),
        //        e,
        //    ))
        //})?;

        server.ensure_aws_sso_oauth_client_registration(true)
            .await
            .map_err(|e| {
                tracing::error!(err = ?e, server_id = server.id(), "error while refreshing oauth client registration");
                tonic::Status::internal(format!("error while refreshing oauth client registration: {e}"))
            })?;

        Ok(tonic::Response::new(
            RefreshAwsSsoClientRegistrationResponse {},
        ))
    }

    #[tracing::instrument(skip_all)]
    async fn initiate_aws_sso_device(
        &self,
        request: tonic::Request<InitiateAwsSsoDeviceRequest>,
    ) -> Result<tonic::Response<InitiateAwsSsoDeviceResponse>, tonic::Status> {
        let req = request.get_ref();

        let mut server = match crate::config::Server::find_from_fs(&req.server_id).await {
            Ok(server) => server,
            Err(crate::Error::ConfigError(e)) => return Err(tonic::Status::internal(e)),
            Err(crate::Error::UserError(e)) => return Err(tonic::Status::not_found(e)),
            Err(e) => return Err(tonic::Status::internal(e.to_string())),
        };

        server.ensure_aws_sso_oauth_client_registration(false)
            .await
            .map_err(|e| {
                tracing::error!(err = ?e, server_id = server.id(), "error while refreshing oauth client registration");
                tonic::Status::internal(format!("error while refreshing oauth client registration: {e}"))
            })?;

        server.validate().map_err(|e| {
            tonic::Status::failed_precondition(format!(
                "Server '{}' has invalid configuration; {:}",
                server.id(),
                e,
            ))
        })?;

        let flow = crate::oauth_awssso::AwsSsoDeviceFlow::initiate(&server)
            .await
            .map_err(|e| {
                tracing::error!(err = ?e, "AwsSsoDeviceFlow initiate failure");
                tonic::Status::internal(e.to_string())
            })?;

        let response = (&flow).into();

        tracing::debug!(flow = ?flow, "Initiated AWS SSO Device Grant flow");
        self.auth_flow_manager
            .store(crate::auth_flow_manager::AuthFlow::AwsSsoDevice(flow));

        return Ok(tonic::Response::new(response));
    }

    #[tracing::instrument(skip_all)]
    async fn complete_aws_sso_device(
        &self,
        request: tonic::Request<CompleteAwsSsoDeviceRequest>,
    ) -> Result<tonic::Response<CompleteAwsSsoDeviceResponse>, tonic::Status> {
        let req = request.get_ref();
        let Some(flow0) = self.auth_flow_manager.retrieve(&req.handle) else {
            return Err(tonic::Status::not_found("flow handle not found"));
        };
        let completion = {
            let crate::auth_flow_manager::AuthFlow::AwsSsoDevice(flow) = flow0.as_ref() else {
                return Err(tonic::Status::invalid_argument(
                    "flow handle is not for the grant type",
                ));
            };
            tracing::trace!(flow = ?flow0.as_ref(), "Completing AWS SSO Device Grant flow...");
            flow.complete().await
        };

        self.accept_completed_auth_flow(flow0, completion)?;

        Ok(tonic::Response::new(CompleteAwsSsoDeviceResponse {}))
    }
}

impl Agent {
    fn accept_completed_auth_flow(
        &self,
        flow: crate::auth_flow_manager::AuthFlowRetrieval,
        completion: crate::Result<crate::token::ServerToken>,
    ) -> tonic::Result<()> {
        let token = match completion {
            Ok(t) => t,
            Err(crate::Error::AuthNotReadyError) => {
                tracing::debug!(flow = ?flow.as_ref(), "not yet ready");
                return Err(tonic::Status::failed_precondition(
                    "not yet ready".to_string(),
                ));
            }
            Err(crate::Error::AuthError(x)) => {
                tracing::error!(flow = ?flow.as_ref(), err = ?x, "flow complete failure (AuthError)");
                return Err(tonic::Status::invalid_argument(x));
            }
            Err(e) => {
                tracing::error!(flow = ?flow.as_ref(), err = ?e, "flow complete failure (unknown)");
                return Err(tonic::Status::unknown(e.to_string()));
            }
        };

        flow.mark_as_done(); // authorization codes cannot be reused, so mark as done now (whlist
                             // later lines may fail)
        self.session_manager
            .add(token)
            .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?;

        Ok(())
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
            let path = path.clone();
            async {
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                    tokio::net::UnixStream::connect(path).await?,
                ))
            }
        }))
        .await?;

    let mut client = crate::proto::agent_client::AgentClient::new(ch);
    client
        .ping_agent(tonic::Request::new(crate::proto::PingAgentRequest {}))
        .await?;

    Ok(client)
}
