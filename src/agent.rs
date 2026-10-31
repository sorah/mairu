use crate::proto::*;

pub struct Agent {
    auth_flow_manager: crate::auth_flow_manager::AuthFlowManager,
    session_manager: crate::session_manager::SessionManager,
    shutdown_tx: tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    platform_helper: std::sync::Arc<crate::platform::helper::HelperClient>,
    authorizer: crate::authorization::Authorizer,
}

impl Agent {
    /// Needs a Tokio runtime.
    pub fn new(
        shutdown_tx: tokio::sync::oneshot::Sender<()>,
        platform_helper: crate::platform::helper::HelperClient,
    ) -> Result<Self, anyhow::Error> {
        let platform_helper = std::sync::Arc::new(platform_helper);
        let authorizer = crate::authorization::Authorizer::from_config(platform_helper.clone())
            .map_err(|e| anyhow::anyhow!("failed to build the authorization policy: {e}"))?;
        Ok(Self {
            auth_flow_manager: crate::auth_flow_manager::AuthFlowManager::new(),
            session_manager: crate::session_manager::SessionManager::new(),
            shutdown_tx: tokio::sync::Mutex::new(Some(shutdown_tx)),
            platform_helper,
            authorizer,
        })
    }

    /// What the helper reports, with this agent's own peer verification and notes.
    async fn capabilities(&self) -> crate::proto::platform::Capabilities {
        use crate::platform::PlatformServices;
        let platform = crate::platform::process();
        let mut capabilities = self.platform_helper.capabilities().await;
        capabilities.peer_verification = platform.peer_verification().into();
        let mut notes = platform.notes();
        notes.append(&mut capabilities.notes);
        capabilities.notes = notes;
        capabilities
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
    async fn get_agent_status(
        &self,
        request: tonic::Request<GetAgentStatusRequest>,
    ) -> Result<tonic::Response<GetAgentStatusResponse>, tonic::Status> {
        let env_names = request
            .get_ref()
            .client_context
            .as_ref()
            .map(|c| c.env_names.as_slice())
            .unwrap_or_default();
        let caller = request
            .extensions()
            .get::<std::sync::Arc<crate::platform::PeerIdentity>>()
            .map(|peer| {
                let (detection, marks) = self.authorizer.tools_of(peer, env_names);
                PeerView {
                    verified: peer.trust == crate::platform::PeerTrust::Verified,
                    pid: peer.pid,
                    start_time: peer.start_time,
                    session: describe_session(peer),
                    tools: detection.tools.into_iter().collect(),
                    tool_matches: detection.tool_matches.into_iter().collect(),
                    marks,
                }
            });
        let (grants, leases) = self.authorizer.counts();
        let agent_hardening = match crate::hardening::Hardening::state() {
            crate::hardening::HardeningState::Unhardened { .. } => HardeningState::Unhardened,
            crate::hardening::HardeningState::Hardened { .. } => HardeningState::Hardened,
            crate::hardening::HardeningState::Misconfigured { .. } => HardeningState::Misconfigured,
        };
        Ok(tonic::Response::new(GetAgentStatusResponse {
            version: crate::version::VERSION.to_owned(),
            agent_hardening: agent_hardening.into(),
            caller,
            capabilities: Some(self.capabilities().await),
            grants,
            leases,
            platform_helper: self.platform_helper.describe(),
            authorization_methods: self.authorizer.methods().await,
            profile: crate::config::Profile::current().name().to_owned(),
        }))
    }

    #[tracing::instrument(skip_all)]
    async fn get_server(
        &self,
        request: tonic::Request<GetServerRequest>,
    ) -> Result<tonic::Response<GetServerResponse>, tonic::Status> {
        Self::require_trusted(&request)?;
        let query = &request.get_ref().query;
        let check_session = &request.get_ref().check_session;

        let maybe_session = self.session_manager.get(query);

        if !request.get_ref().no_cache
            && let Ok(session) = maybe_session.as_ref()
        {
            let json = serde_json::to_string(&session.token.server)
                .map_err(|e| tonic::Status::internal(e.to_string()))?;
            return Ok(tonic::Response::new(GetServerResponse {
                json,
                cached: true,
                session: Some(session.into()),
            }));
        }

        let session = if *check_session {
            maybe_session.ok()
        } else {
            None
        };
        match crate::config::Server::find_from_fs(query).await {
            Ok(server) => {
                let json = serde_json::to_string(&server)
                    .map_err(|e| tonic::Status::internal(e.to_string()))?;
                Ok(tonic::Response::new(GetServerResponse {
                    json,
                    cached: false,
                    session: session.map(|ref x| x.into()),
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
        Self::require_trusted(&request)?;

        let query = &request.get_ref().server_id;
        let cacheable = request.get_ref().cached;
        let rolespec = request.get_ref().rolespec();
        let role = &rolespec.role;
        let server_config = crate::config::Server::find_from_fs(query).await.map_err(|e| {
            tracing::warn!(server_id = ?query, role = ?role, err = ?e, "requested server doesn't exist or is invalid");
            tonic::Status::not_found("requested server doesn't exist or is invalid")
        })?;
        let user_config = crate::config::UserConfig::load().await.map_err(|e| {
            tracing::error!(err = ?e, "failed to load user configuration");
            tonic::Status::internal(format!(
                "failed to load {}: {e}",
                crate::config::UserConfig::path().display()
            ))
        })?;
        let peer = request
            .extensions()
            .get::<std::sync::Arc<crate::platform::PeerIdentity>>()
            .cloned();
        // Before the session and cache lookups, so that a refused request fetches nothing.
        let authorized = self
            .authorizer
            .authorize_assume_role(crate::authorization::Request {
                peer: peer.as_deref(),
                server: &server_config,
                user_config: &user_config,
                rolespec: &rolespec,
                client_context: request.get_ref().client_context.as_ref(),
            })
            .await
            .map_err(AuthorizationError::into_status)?;
        let Ok(session) = self.session_manager.get(query) else {
            tracing::warn!(server_id = ?query, role = ?role, "session doesn't exist, require authentication");
            return Err(tonic::Status::unauthenticated("authentication needed"));
        };

        let cache = session.credential_cache.clone();
        let server_id = session.token.server.id().to_owned();
        let server_url = session.token.server.url.clone();
        // Gate 2 runs inside, with the caller identity of whatever is about to be vended.
        let obtained = self
            .authorizer
            .obtain(authorized, &cache, &rolespec, cacheable, || {
                self.fetch_credentials(session, &rolespec, cacheable)
            })
            .await?;
        let credentials = &obtained.credentials;
        let caller_arn = obtained.caller.as_ref().map(|c| c.arn.as_str());
        match obtained.source {
            crate::authorization::Source::Cache => {
                tracing::info!(server_id, server_url = %server_url, role = ?role, assume_role = ?rolespec.assume_role, aws_access_key_id = ?credentials.access_key_id, caller_arn, ext = ?credentials.mairu, "Vending credentials from cache")
            }
            crate::authorization::Source::Held => {
                tracing::info!(server_id, server_url = %server_url, role = ?role, assume_role = ?rolespec.assume_role, aws_access_key_id = ?credentials.access_key_id, caller_arn, ext = ?credentials.mairu, "Vending credentials held for a retried authorization")
            }
            crate::authorization::Source::Fetched => {
                tracing::info!(server_id, server_url = %server_url, role = ?role, assume_role = ?rolespec.assume_role, aws_access_key_id = ?credentials.access_key_id, caller_arn, ext = ?credentials.mairu, "Vending credentials")
            }
        }
        obtained.authorized.vended(Some(credentials.expiration));
        Ok(tonic::Response::new(credentials.as_ref().into()))
    }

    #[tracing::instrument(skip_all)]
    async fn list_sessions(
        &self,
        request: tonic::Request<ListSessionsRequest>,
    ) -> Result<tonic::Response<ListSessionsResponse>, tonic::Status> {
        Self::require_trusted(&request)?;
        let sessions = self
            .session_manager
            .list()
            .iter()
            .map(|x| x.into())
            .collect();
        Ok(tonic::Response::new(ListSessionsResponse { sessions }))
    }

    #[tracing::instrument(skip_all)]
    async fn refresh_session(
        &self,
        request: tonic::Request<RefreshSessionRequest>,
    ) -> Result<tonic::Response<RefreshSessionResponse>, tonic::Status> {
        Self::require_trusted(&request)?;
        let query = &request.get_ref().query;
        let session = match self.session_manager.get(query) {
            Ok(x) => x,
            Err(crate::Error::ConfigError(e)) => return Err(tonic::Status::internal(e)),
            Err(crate::Error::UserError(e)) => return Err(tonic::Status::not_found(e)),
            Err(e) => return Err(tonic::Status::internal(e.to_string())),
        };
        match self.refresh_session(&session).await {
            Ok(new) => Ok(tonic::Response::new(RefreshSessionResponse {
                session: Some((&new).into()),
            })),
            Err(e) => Err(tonic::Status::internal(e.to_string())),
        }
    }

    #[tracing::instrument(skip_all)]
    async fn initiate_oauth_code(
        &self,
        request: tonic::Request<InitiateOAuthCodeRequest>,
    ) -> Result<tonic::Response<InitiateOAuthCodeResponse>, tonic::Status> {
        Self::require_trusted(&request)?;
        let req = request.get_ref();

        let mut server = match crate::config::Server::find_from_fs(&req.server_id).await {
            Ok(server) => server,
            Err(crate::Error::ConfigError(e)) => return Err(tonic::Status::internal(e)),
            Err(crate::Error::UserError(e)) => return Err(tonic::Status::not_found(e)),
            Err(e) => return Err(tonic::Status::internal(e.to_string())),
        };

        if server.aws_sso.is_some() {
            server.ensure_aws_sso_oauth_client_registration(false, crate::config::OAuthGrantType::Code)
                .await
                .map_err(|e| {
                    tracing::error!(err = ?e, server_id = server.id(), "error while refreshing oauth client registration");
                    tonic::Status::internal(format!("error while refreshing oauth client registration: {e}"))
                })?;
        }

        server.validate().map_err(|e| {
            tonic::Status::failed_precondition(format!(
                "Server '{}' has invalid configuration; {:}",
                server.id(),
                e,
            ))
        })?;

        let redirect_url = url::Url::parse(&req.redirect_url)
            .map_err(|e| tonic::Status::invalid_argument(format!("Bad Redirect URL: {:}", e)))?;

        let (response, flow_to_store) = if server.aws_sso.is_some() {
            let flow = crate::oauth_awssso_code::AwsSsoCodeFlow::initiate(&server, &redirect_url)
                .await
                .map_err(|e| {
                    tracing::error!(err = ?e, "AwsSsoCodeFlow initiate failure");
                    tonic::Status::internal(e.to_string())
                })?;
            (
                (&flow).into(),
                crate::auth_flow_manager::AuthFlow::AwsSsoCode(flow),
            )
        } else {
            let flow = crate::oauth_code::OAuthCodeFlow::initiate(&server, &redirect_url).map_err(
                |e| {
                    tracing::error!(err = ?e, "OAuthCodeFlow initiate failure");
                    tonic::Status::internal(e.to_string())
                },
            )?;
            (
                (&flow).into(),
                crate::auth_flow_manager::AuthFlow::OAuthCode(flow),
            )
        };

        tracing::debug!(flow = ?flow_to_store, "Initiated OAuth 2.0 Authorization Code flow");
        self.auth_flow_manager.store(flow_to_store);

        return Ok(tonic::Response::new(response));
    }

    #[tracing::instrument(skip_all)]
    async fn complete_oauth_code(
        &self,
        request: tonic::Request<CompleteOAuthCodeRequest>,
    ) -> Result<tonic::Response<CompleteOAuthCodeResponse>, tonic::Status> {
        Self::require_trusted(&request)?;
        let req = request.get_ref();
        let Some(flow0) = self.auth_flow_manager.retrieve(&req.handle) else {
            return Err(tonic::Status::not_found("flow handle not found"));
        };
        tracing::debug!(flow = ?flow0.as_ref(), "Completing OAuth 2.0 Authorization Code flow...");
        let completion = match flow0.as_ref() {
            crate::auth_flow_manager::AuthFlow::OAuthCode(flow) => {
                flow.complete(request.into_inner()).await
            }
            crate::auth_flow_manager::AuthFlow::AwsSsoCode(flow) => {
                flow.complete(request.into_inner()).await
            }
            _ => {
                return Err(tonic::Status::invalid_argument(
                    "flow handle is not for the grant type",
                ));
            }
        };

        self.accept_completed_auth_flow(flow0, completion)?;

        Ok(tonic::Response::new(CompleteOAuthCodeResponse {}))
    }

    #[tracing::instrument(skip_all)]
    async fn initiate_oauth_device_code(
        &self,
        request: tonic::Request<InitiateOAuthDeviceCodeRequest>,
    ) -> Result<tonic::Response<InitiateOAuthDeviceCodeResponse>, tonic::Status> {
        Self::require_trusted(&request)?;
        let req = request.get_ref();

        let mut server = match crate::config::Server::find_from_fs(&req.server_id).await {
            Ok(server) => server,
            Err(crate::Error::ConfigError(e)) => return Err(tonic::Status::internal(e)),
            Err(crate::Error::UserError(e)) => return Err(tonic::Status::not_found(e)),
            Err(e) => return Err(tonic::Status::internal(e.to_string())),
        };

        if server.aws_sso.is_some() {
            server.ensure_aws_sso_oauth_client_registration(false, crate::config::OAuthGrantType::DeviceCode)
                .await
                .map_err(|e| {
                    tracing::error!(err = ?e, server_id = server.id(), "error while refreshing oauth client registration");
                    tonic::Status::internal(format!("error while refreshing oauth client registration: {e}"))
                })?;
        }

        server.validate().map_err(|e| {
            tonic::Status::failed_precondition(format!(
                "Server '{}' has invalid configuration; {:}",
                server.id(),
                e,
            ))
        })?;

        let (response, flow_to_store) = if server.aws_sso.is_some() {
            let flow = crate::oauth_awssso_device_code::AwsSsoDeviceFlow::initiate(&server)
                .await
                .map_err(|e| {
                    tracing::error!(err = ?e, "AwsSsoDeviceFlow initiate failure");
                    tonic::Status::internal(e.to_string())
                })?;
            (
                (&flow).into(),
                crate::auth_flow_manager::AuthFlow::AwsSsoDevice(flow),
            )
        } else {
            let flow = crate::oauth_device_code::OAuthDeviceCodeFlow::initiate(&server)
                .await
                .map_err(|e| {
                    tracing::error!(err = ?e, "OAuthDeviceCodeFlow initiate failure");
                    tonic::Status::internal(e.to_string())
                })?;
            (
                (&flow).into(),
                crate::auth_flow_manager::AuthFlow::OAuthDeviceCode(flow),
            )
        };

        tracing::debug!(flow = ?flow_to_store, "Initiated OAuth 2.0 Device Code flow");
        self.auth_flow_manager.store(flow_to_store);

        return Ok(tonic::Response::new(response));
    }

    #[tracing::instrument(skip_all)]
    async fn complete_oauth_device_code(
        &self,
        request: tonic::Request<CompleteOAuthDeviceCodeRequest>,
    ) -> Result<tonic::Response<CompleteOAuthDeviceCodeResponse>, tonic::Status> {
        Self::require_trusted(&request)?;
        let req = request.get_ref();
        let Some(flow0) = self.auth_flow_manager.retrieve(&req.handle) else {
            return Err(tonic::Status::not_found("flow handle not found"));
        };
        tracing::trace!(flow = ?flow0.as_ref(), "Completing OAuth 2.0 Device Code Grant flow...");
        let completion = match flow0.as_ref() {
            crate::auth_flow_manager::AuthFlow::OAuthDeviceCode(flow) => flow.complete().await,
            crate::auth_flow_manager::AuthFlow::AwsSsoDevice(flow) => flow.complete().await,
            _ => {
                return Err(tonic::Status::invalid_argument(
                    "flow handle is not for the grant type",
                ));
            }
        };

        self.accept_completed_auth_flow(flow0, completion)?;

        Ok(tonic::Response::new(CompleteOAuthDeviceCodeResponse {}))
    }

    #[tracing::instrument(skip_all)]
    async fn refresh_aws_sso_client_registration(
        &self,
        request: tonic::Request<RefreshAwsSsoClientRegistrationRequest>,
    ) -> Result<tonic::Response<RefreshAwsSsoClientRegistrationResponse>, tonic::Status> {
        Self::require_trusted(&request)?;
        let req = request.get_ref();

        let mut server = match crate::config::Server::find_from_fs(&req.server_id).await {
            Ok(server) => server,
            Err(crate::Error::ConfigError(e)) => return Err(tonic::Status::internal(e)),
            Err(crate::Error::UserError(e)) => return Err(tonic::Status::not_found(e)),
            Err(e) => return Err(tonic::Status::internal(e.to_string())),
        };

        let force = req.force;
        tracing::info!(server_id = ?server.id(), server_url = %server.url, force = ?force, "refreshing AWS SSO Client Registration if needed");

        // XXX: validate checks .oauth existence...
        //server.validate().map_err(|e| {
        //    tonic::Status::failed_precondition(format!(
        //        "Server '{}' has invalid configuration; {:}",
        //        server.id(),
        //        e,
        //    ))
        //})?;

        server.ensure_aws_sso_oauth_client_registration(force, crate::config::OAuthGrantType::Code)
            .await
            .map_err(|e| {
                tracing::error!(err = ?e, server_id = server.id(), "error while refreshing oauth client registration (Code)");
                tonic::Status::internal(format!("error while refreshing oauth client registration: {e}"))
            })?;
        server.ensure_aws_sso_oauth_client_registration(force, crate::config::OAuthGrantType::DeviceCode)
            .await
            .map_err(|e| {
                tracing::error!(err = ?e, server_id = server.id(), "error while refreshing oauth client registration (DeviceCode)");
                tonic::Status::internal(format!("error while refreshing oauth client registration: {e}"))
            })?;

        Ok(tonic::Response::new(
            RefreshAwsSsoClientRegistrationResponse {},
        ))
    }

    #[tracing::instrument(skip_all)]
    async fn list_roles(
        &self,
        request: tonic::Request<ListRolesRequest>,
    ) -> Result<tonic::Response<ListRolesResponse>, tonic::Status> {
        Self::require_trusted(&request)?;
        use crate::client::CredentialVendor;

        let req = request.get_ref();
        let (sessions, configured_servers) = if req.server_id.is_empty() {
            (
                self.session_manager.list(),
                match crate::config::Server::find_all_from_fs().await {
                    Ok(x) => x,
                    Err(e) => return Err(tonic::Status::internal(e.to_string())),
                },
            )
        } else {
            (
                match self.session_manager.get(&req.server_id) {
                    Ok(x) => vec![x],
                    Err(crate::Error::ConfigError(e)) => return Err(tonic::Status::internal(e)),
                    Err(crate::Error::UserError(e)) => return Err(tonic::Status::not_found(e)),
                    Err(e) => return Err(tonic::Status::internal(e.to_string())),
                },
                vec![],
            )
        };

        let mut map = std::collections::HashMap::new();
        let mut servers = std::vec::Vec::with_capacity(configured_servers.len());

        for session in sessions.into_iter() {
            let session = self.ensure_session_freshness(session).await;
            map.insert(session.server().id().to_owned(), true);
            let client = crate::client::make_credential_vendor(&session).map_err(|e| {
                tracing::error!(server_id = ?session.token.server.id(), server_url = %session.token.server.url, err = ?e, "Failed to make_credential_vendor");
                tonic::Status::internal(e.to_string())
            })?;
            match client.list_roles().await {
                Ok(x) => servers.push(x.to_proto(session.server())),
                Err(crate::Error::RemoteError(crate::client::Error::Unauthenticated(_m, e))) => {
                    tracing::warn!(server_id = ?session.token.server.id(), server_url = %session.token.server.url, err = ?e, "list_roles returned unauthenticated");
                    // do nothing
                }
                Err(e) => {
                    tracing::error!(server_id = ?session.token.server.id(), server_url = %session.token.server.url, err = ?e, "Failed to list_roles");
                    return Err(tonic::Status::internal(e.to_string()));
                }
            }
        }
        for server in configured_servers.into_iter() {
            if map.contains_key(server.id()) {
                continue;
            }
            servers.push(crate::proto::list_roles_response::Item {
                server_id: server.id().to_owned(),
                server_url: server.url.to_string(),
                logged_in: false,
                roles: vec![],
            });
        }
        tracing::debug!("done");

        Ok(tonic::Response::new(crate::proto::ListRolesResponse {
            servers,
        }))
    }

    #[tracing::instrument(skip_all)]
    async fn shutdown_agent(
        &self,
        request: tonic::Request<ShutdownAgentRequest>,
    ) -> Result<tonic::Response<ShutdownAgentResponse>, tonic::Status> {
        Self::require_trusted(&request)?;
        tracing::debug!("Shutdown requested");

        match self.shutdown_tx.lock().await.take() {
            Some(tx) => match tx.send(()) {
                Ok(()) => {
                    tracing::info!("Shutdown signal sent successfully");
                    Ok(tonic::Response::new(ShutdownAgentResponse {}))
                }
                Err(_) => {
                    tracing::error!("Failed to send shutdown signal - receiver already dropped");
                    Err(tonic::Status::internal("Failed to send shutdown signal"))
                }
            },
            None => {
                tracing::warn!("Shutdown already requested or not available");
                Err(tonic::Status::unavailable(
                    "Shutdown already requested or not available",
                ))
            }
        }
    }

    #[tracing::instrument(skip_all)]
    async fn revoke_authorizations(
        &self,
        request: tonic::Request<RevokeAuthorizationsRequest>,
    ) -> Result<tonic::Response<RevokeAuthorizationsResponse>, tonic::Status> {
        Self::require_trusted(&request)?;
        let req = request.get_ref();
        let peer = request
            .extensions()
            .get::<std::sync::Arc<crate::platform::PeerIdentity>>();
        let caller_session = || peer.and_then(|p| crate::platform::process().session_identity(p));
        if let Some(label) = req
            .mark_tools
            .iter()
            .find(|l| !crate::tool_detection::ToolLabel::is_valid_name(l))
        {
            return Err(tonic::Status::invalid_argument(format!(
                "invalid tool label {label:?}: use lowercase letters, digits and '-'"
            )));
        }
        let mark_session = if req.mark_tools.is_empty() {
            None
        } else {
            match caller_session() {
                Some(s @ crate::platform::SessionIdentity::Tty { .. }) => Some(s),
                _ => {
                    return Err(tonic::Status::failed_precondition(
                        crate::authorization::NO_TERMINAL_SESSION,
                    ));
                }
            }
        };
        let session = match (req.scope(), mark_session) {
            // Marking drops the grants of the marked session, as `--session` does.
            (_, Some(s)) => Some(Some(s)),
            (revoke_authorizations_request::Scope::All, None) => None,
            (revoke_authorizations_request::Scope::CallerSession, None) => Some(caller_session()),
            (revoke_authorizations_request::Scope::Unspecified, None) => {
                return Err(tonic::Status::invalid_argument("scope is required"));
            }
        };
        let (revoked_grants, revoked_leases) = self.authorizer.revoke(session, req.include_leases);
        tracing::info!(scope = ?req.scope(), session = ?session, include_leases = req.include_leases, revoked_grants, revoked_leases, "Revoked authorizations");
        if let Some(s) = mark_session {
            self.authorizer.mark_tools(s, &req.mark_tools);
            tracing::info!(session = ?s, tools = ?req.mark_tools, "Marked a terminal session with tool labels");
        }
        Ok(tonic::Response::new(RevokeAuthorizationsResponse {
            revoked_grants,
            revoked_leases,
        }))
    }

    #[tracing::instrument(skip_all)]
    async fn get_policy(
        &self,
        request: tonic::Request<GetPolicyRequest>,
    ) -> Result<tonic::Response<GetPolicyResponse>, tonic::Status> {
        Self::require_trusted(&request)?;
        let effective = self
            .authorizer
            .policy()
            .map_err(|e| tonic::Status::internal(format!("failed to build the policy: {e}")))?;
        let integrity = match effective.state {
            crate::policy::settings::PolicyState::Absent => PolicyIntegrity::Absent,
            crate::policy::settings::PolicyState::Unapproved => PolicyIntegrity::Unapproved,
        };
        Ok(tonic::Response::new(GetPolicyResponse {
            effective_policies: effective.engine.text().to_owned(),
            effective_settings_json: effective.settings.to_json(),
            integrity: integrity.into(),
            notes: effective.notes.clone(),
        }))
    }

    #[tracing::instrument(skip_all)]
    async fn unmark_tools(
        &self,
        request: tonic::Request<UnmarkToolsRequest>,
    ) -> Result<tonic::Response<UnmarkToolsResponse>, tonic::Status> {
        Self::require_trusted(&request)?;
        let labels = &request.get_ref().tools;
        if labels.is_empty() {
            return Err(tonic::Status::invalid_argument("no tool label given"));
        }
        let peer = request
            .extensions()
            .get::<std::sync::Arc<crate::platform::PeerIdentity>>()
            .cloned();
        let remaining = self
            .authorizer
            .unmark_tools(peer.as_deref(), labels)
            .await?;
        Ok(tonic::Response::new(UnmarkToolsResponse { remaining }))
    }
}

/// `PeerView.session`, e.g. `tty sid=4242 /dev/pts/3`.
fn describe_session(peer: &crate::platform::PeerIdentity) -> String {
    let platform = crate::platform::process();
    match platform.session_identity(peer) {
        Some(s @ crate::platform::SessionIdentity::Tty { .. }) => {
            match platform.controlling_tty(peer) {
                Some(tty) => format!("{s} {tty}"),
                None => s.to_string(),
            }
        }
        Some(s) => s.to_string(),
        None => "none".to_owned(),
    }
}

impl Agent {
    /// Refuses a peer the hardened agent rejected, and a verified peer older than the minimum client version.
    /// `PingAgent` and `GetAgentStatus` skip this so that unverified binaries can diagnose themselves.
    fn require_trusted<T>(request: &tonic::Request<T>) -> Result<(), tonic::Status> {
        let Some(peer) = request
            .extensions()
            .get::<std::sync::Arc<crate::platform::PeerIdentity>>()
        else {
            if crate::hardening::Hardening::marker().is_some() {
                return Err(AuthorizationError::unverified_peer(
                    "the connection has no recorded peer",
                )
                .into_status());
            }
            return Ok(());
        };
        match peer.trust {
            crate::platform::PeerTrust::Unverifiable => Ok(()),
            crate::platform::PeerTrust::Rejected => Err(AuthorizationError::unverified_peer(format!(
                "the agent is hardened and this mairu (pid {}) is not, so it is refused; use the hardened mairu, or run `mairu doctor` for details",
                peer.pid
            ))
            .into_status()),
            crate::platform::PeerTrust::Verified => {
                let version = request
                    .metadata()
                    .get(VERSION_METADATA)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if crate::version::at_least(version, crate::version::MINIMUM_CLIENT_VERSION) {
                    return Ok(());
                }
                tracing::warn!(pid = peer.pid, client_version = version, "Refusing a client older than the minimum client version");
                Err(AuthorizationError::unverified_peer(format!(
                    "this mairu ({version:?}) is older than {}, the minimum client version of the agent; use the current mairu",
                    crate::version::MINIMUM_CLIENT_VERSION
                ))
                .into_status())
            }
        }
    }

    fn accept_completed_auth_flow(
        &self,
        flow: crate::auth_flow_manager::AuthFlowRetrieval,
        completion: crate::Result<crate::token::ServerToken>,
    ) -> tonic::Result<()> {
        let token = match completion {
            Ok(t) => t,
            Err(crate::Error::AuthNotReadyError { slow_down: true }) => {
                tracing::debug!(flow = ?flow.as_ref(), "not yet ready, slow down");
                return Err(tonic::Status::resource_exhausted(
                    "not yet ready, slow down".to_string(),
                ));
            }
            Err(crate::Error::AuthNotReadyError { slow_down: false }) => {
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

    /// Credentials for `rolespec` from the credential server, plus `sts:AssumeRole` for a chained role. Only the
    /// first hop of a chain is cached here; the caller caches what it vends.
    async fn fetch_credentials(
        &self,
        session: crate::session_manager::Session,
        rolespec: &crate::proto::Rolespec,
        cacheable: bool,
    ) -> Result<crate::client::AssumeRoleResponse, tonic::Status> {
        use crate::client::CredentialVendor;
        let role = &rolespec.role;
        let has_next_role = rolespec.assume_role.is_some();
        let base_rolespec = rolespec.base();

        let first_hop_cache = if cacheable && has_next_role {
            session.credential_cache.get(&base_rolespec)
        } else {
            None
        };

        let (session, first_hop) = match first_hop_cache {
            Some(cached_first_hop) => {
                tracing::debug!(server_id = ?session.token.server.id(), server_url = %session.token.server.url, role = ?role, "Using cached first-hop credentials for assume_next_role");
                (session, Ok(cached_first_hop.credentials.as_ref().clone()))
            }
            None => {
                tracing::debug!(server_id = ?session.token.server.id(), server_url = %session.token.server.url, role = ?role, "Obtaining credentials from server");
                let session = self.ensure_session_freshness(session).await;
                let client =
                    crate::client::make_credential_vendor(&session).map_err(|e| {
                        tracing::error!(server_id = ?session.token.server.id(), server_url = %session.token.server.url, role = ?role, err = ?e, "Failed to make_credential_vendor");
                        tonic::Status::internal(e.to_string())
                    })?;
                let r = client.assume_role(&base_rolespec.role).await;
                if cacheable
                    && has_next_role
                    && let Ok(ref body) = r
                {
                    session.credential_cache.store(
                        base_rolespec,
                        std::sync::Arc::new(body.clone()),
                        None,
                    );
                }
                (session, r)
            }
        };

        match first_hop {
            Ok(r) => {
                if !has_next_role {
                    return Ok(r);
                }
                tracing::info!(server_id = ?session.token.server.id(), server_url = %session.token.server.url, role = ?role, assume_role = ?rolespec.assume_role, aws_access_key_id = ?r.access_key_id, ext = ?r.mairu, "calling sts:AssumeRole to the next role using the first hop credentials");
                let region = session
                    .token
                    .server
                    .aws_sso
                    .as_ref()
                    .map(|s| s.region.as_str());
                assume_next_role(&r, rolespec.assume_role.as_ref().unwrap(), region).await
            }
            Err(crate::Error::RemoteError(crate::client::Error::InvalidArgument(message, _))) => {
                Err(tonic::Status::invalid_argument(message))
            }
            Err(crate::Error::RemoteError(crate::client::Error::Unauthenticated(message, _))) => {
                Err(tonic::Status::unauthenticated(message))
            }
            Err(crate::Error::RemoteError(crate::client::Error::PermissionDenied(message, _))) => {
                Err(tonic::Status::permission_denied(message))
            }
            Err(crate::Error::RemoteError(crate::client::Error::ResourceExhausted(message, _))) => {
                Err(tonic::Status::resource_exhausted(message))
            }
            Err(crate::Error::RemoteError(crate::client::Error::NotFound(message, _))) => {
                Err(tonic::Status::not_found(message))
            }
            Err(crate::Error::RemoteError(crate::client::Error::Unknown(message, _))) => {
                Err(tonic::Status::unknown(message))
            }
            Err(e) => {
                tracing::error!(server_id = ?session.token.server.id(), server_url = %session.token.server.url, role = ?role, err = ?e, "assume-role API returned error");
                Err(tonic::Status::unknown(e.to_string()))
            }
        }
    }

    /// Refresh session if necessary and able to do so, using refresh_token.
    async fn ensure_session_freshness(
        &self,
        session: crate::session_manager::Session,
    ) -> crate::session_manager::Session {
        if !session.token.is_access_token_near_expiration() {
            return session;
        }
        if !session.token.has_active_refresh_token() {
            return session;
        }
        let result = self.refresh_session(&session).await;
        match result {
            Ok(new) => new,
            Err(_) => session,
        }
    }

    async fn refresh_session(
        &self,
        session: &crate::session_manager::Session,
    ) -> crate::Result<crate::session_manager::Session> {
        let maybe_new = if session.token.server.aws_sso.is_some() {
            refresh_token_using_awssso(session).await
        } else {
            refresh_token_using_oauth2(session).await
        };
        match maybe_new {
            Ok(new) => {
                let sess = self.session_manager.add(new).unwrap(); // XXX: unwrap()
                Ok(sess)
            }
            Err(e) => Err(e),
        }
    }
}

async fn refresh_token_using_oauth2(
    session: &crate::session_manager::Session,
) -> crate::Result<crate::token::ServerToken> {
    match crate::oauth_refresh_token::refresh_token(&session.token).await {
        Ok(token) => Ok(token),
        Err(e) => {
            tracing::warn!(
                server_id = session.token.server.id(),
                url = %session.token.server.url,
                err = ?e,
                "Failed to refresh session using refresh_token"
            );
            Err(e)
        }
    }
}

async fn refresh_token_using_awssso(
    session: &crate::session_manager::Session,
) -> crate::Result<crate::token::ServerToken> {
    match crate::ext_awssso::refresh_token(&session.token).await {
        Ok(token) => Ok(token),
        Err(e) => {
            tracing::warn!(
                server_id = session.token.server.id(),
                url = %session.token.server.url,
                err = ?e,
                "Failed to refresh session using refresh_token against AWS sso-oidc"
            );
            Err(e)
        }
    }
}

async fn assume_next_role(
    first_hop: &crate::client::AssumeRoleResponse,
    assume_role: &crate::proto::AssumeRole,
    region: Option<&str>,
) -> Result<crate::client::AssumeRoleResponse, tonic::Status> {
    use secrecy::ExposeSecret;

    let creds = aws_sdk_sts::config::Credentials::new(
        &first_hop.access_key_id,
        first_hop.secret_access_key.expose_secret(),
        first_hop.session_token.clone(),
        None,
        "mairu",
    );
    let config = crate::ext_awssso::sdk_config(region)
        .await
        .to_builder()
        .credentials_provider(aws_sdk_sts::config::SharedCredentialsProvider::new(creds))
        .identity_cache(aws_config::identity::IdentityCache::no_cache())
        .build();
    let sts = aws_sdk_sts::Client::new(&config);

    let role_session_name = match assume_role.role_session_name {
        Some(ref name) => name.clone(),
        None => resolve_role_session_name(&sts).await,
    };

    let mut req = sts
        .assume_role()
        .role_arn(&assume_role.role_arn)
        .role_session_name(role_session_name);
    if let Some(secs) = assume_role.duration_seconds {
        req = req.duration_seconds(secs);
    }
    if let Some(ref eid) = assume_role.external_id {
        req = req.external_id(eid);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| {
            tracing::error!(role_arn = ?assume_role.role_arn, err = ?e, "assume_next_role STS call failed");
            tonic::Status::unknown(format!("assume_next_role failed: {e}"))
        })?;

    let sts_creds = resp
        .credentials()
        .ok_or_else(|| tonic::Status::internal("STS AssumeRole returned no credentials"))?;
    let expiration_chrono = chrono::DateTime::<chrono::Utc>::from(
        std::time::SystemTime::try_from(*sts_creds.expiration()).map_err(|e| {
            tonic::Status::internal(format!("Failed to convert STS expiration: {e}"))
        })?,
    );

    Ok(crate::client::AssumeRoleResponse {
        version: 1,
        access_key_id: sts_creds.access_key_id().to_owned(),
        secret_access_key: secrecy::SecretString::from(sts_creds.secret_access_key().to_owned()),
        session_token: Some(sts_creds.session_token().to_owned()),
        expiration: expiration_chrono,
        mairu: Default::default(),
    })
}

async fn resolve_role_session_name(sts: &aws_sdk_sts::Client) -> String {
    if let Ok(identity) = sts.get_caller_identity().send().await
        && let Some(arn) = identity.arn()
    {
        // arn:aws:sts::<account>:assumed-role/<role>/<session-name>
        if let Some(session_name) = arn
            .split(':')
            .next_back()
            .and_then(|resource| resource.strip_prefix("assumed-role/"))
            .and_then(|rest| rest.split('/').nth(1))
            && !session_name.is_empty()
        {
            return session_name.to_owned();
        }
    }
    std::env::var("USER").unwrap_or_else(|_| "mairu".to_owned())
}

/// gRPC metadata carrying the client's version on every request.
pub const VERSION_METADATA: &str = "mairu-version";

/// RPCs a client sends to an agent it could not verify. None carries anything secret.
const UNVERIFIED_AGENT_PATHS: &[&str] = &[
    "/mairu.Agent/PingAgent",
    "/mairu.Agent/GetAgentStatus",
    "/mairu.Agent/ShutdownAgent",
];

const UNVERIFIED_PING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Why a hardened client does not use the agent it connected to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplacementReason {
    Unverified,
    /// Verified, but older than this build's minimum agent version.
    Outdated,
}

/// A connection to the agent, with what the client learned about it while connecting.
#[derive(Clone, Debug)]
pub struct AgentConn {
    client: crate::proto::agent_client::AgentClient<AgentChannel>,
    identity: crate::platform::AgentIdentity,
    version: String,
    path: std::path::PathBuf,
}

impl std::ops::Deref for AgentConn {
    type Target = crate::proto::agent_client::AgentClient<AgentChannel>;
    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl std::ops::DerefMut for AgentConn {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client
    }
}

impl AgentConn {
    pub fn identity(&self) -> crate::platform::AgentIdentity {
        self.identity
    }

    pub fn trust(&self) -> crate::platform::AgentTrust {
        self.identity.trust
    }

    /// The version the agent reported through `PingAgent`.
    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Only a hardened client ever replaces an agent, so an unhardened client never replaces a hardened agent.
    pub fn replacement_reason(&self) -> Option<ReplacementReason> {
        match self.identity.trust {
            crate::platform::AgentTrust::Unverified => Some(ReplacementReason::Unverified),
            crate::platform::AgentTrust::Verified
                if !crate::version::at_least(
                    &self.version,
                    crate::version::MINIMUM_AGENT_VERSION,
                ) =>
            {
                Some(ReplacementReason::Outdated)
            }
            _ => None,
        }
    }
}

/// Sends `mairu-version` with every request, and refuses locally, before sending anything, every RPC but
/// [`UNVERIFIED_AGENT_PATHS`] to an unverified agent.
#[derive(Clone, Debug)]
pub struct AgentChannel {
    inner: tonic::transport::Channel,
    trust: crate::platform::AgentTrust,
}

impl tower::Service<tonic::codegen::http::Request<tonic::body::Body>> for AgentChannel {
    type Response = tonic::codegen::http::Response<tonic::body::Body>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(
        &mut self,
        mut request: tonic::codegen::http::Request<tonic::body::Body>,
    ) -> Self::Future {
        if self.trust == crate::platform::AgentTrust::Unverified
            && !UNVERIFIED_AGENT_PATHS.contains(&request.uri().path())
        {
            let status = tonic::Status::permission_denied(
                "the agent is not hardened mairu, so nothing is sent to it; run `mairu doctor` for details",
            );
            return Box::pin(std::future::ready(Err(status.into())));
        }
        request.headers_mut().insert(
            VERSION_METADATA,
            tonic::codegen::http::HeaderValue::from_static(crate::version::VERSION),
        );
        let fut = self.inner.call(request);
        Box::pin(async move { fut.await.map_err(Into::into) })
    }
}

pub async fn connect_to_agent() -> crate::Result<AgentConn> {
    connect_to_agent_with_path(crate::config::socket_path()).await
}

pub async fn connect_to_agent_with_path(
    path_: impl AsRef<std::path::Path>,
) -> crate::Result<AgentConn> {
    // https://github.com/hyperium/tonic/blob/master/examples/src/uds/client.rs
    // url is unused for connection
    let path = path_.as_ref().to_path_buf();
    // tonic calls the connector again on every reconnect; each must find the agent the first one verified.
    let pinned = std::sync::Arc::new(std::sync::OnceLock::new());
    let ch = {
        let path = path.clone();
        let pinned = pinned.clone();
        tonic::transport::Endpoint::try_from("http://[::]:50051")?
            .connect_with_connector(tower::service_fn(move |_| {
                let path = path.clone();
                let pinned = pinned.clone();
                async move {
                    let stream = crate::hardening::with_privileged_gid(|| {
                        std::os::unix::net::UnixStream::connect(&path)
                    })?;
                    let identity = crate::platform::process()
                        .verify_agent(&stream)
                        .map_err(std::io::Error::other)?;
                    let first: &crate::platform::AgentIdentity = pinned.get_or_init(|| identity);
                    if first.trust != identity.trust {
                        return Err(std::io::Error::other(format!(
                            "the agent at {} changed from {:?} to {:?}",
                            path.display(),
                            first.trust,
                            identity.trust
                        )));
                    }
                    stream.set_nonblocking(true)?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                        tokio::net::UnixStream::from_std(stream)?,
                    ))
                }
            }))
            .await?
    };
    let identity = *pinned
        .get()
        .expect("connector runs before connect_with_connector returns");

    let mut client = crate::proto::agent_client::AgentClient::new(AgentChannel {
        inner: ch,
        trust: identity.trust,
    });
    let ping = client.ping_agent(tonic::Request::new(crate::proto::PingAgentRequest {}));
    let version = if identity.trust == crate::platform::AgentTrust::Unverified {
        // A squatter may never answer. It is replaced either way, so its version is informational.
        match tokio::time::timeout(UNVERIFIED_PING_TIMEOUT, ping).await {
            Ok(Ok(pong)) => pong.into_inner().version,
            _ => String::new(),
        }
    } else {
        ping.await?.into_inner().version
    };
    let conn = AgentConn {
        client,
        identity,
        version,
        path,
    };
    if conn.replacement_reason().is_none() && conn.version != crate::version::VERSION {
        tracing::warn!(
            agent_version = conn.version,
            client_version = crate::version::VERSION,
            "agent version is diverged; you may want to restart your agent via `mairu kill-agent` command."
        );
        let product = env!("CARGO_PKG_NAME");
        crate::terminal::send(
            &format!(
                ":: {product} :: Warning | agent version is diverged; Restart your agent via `mairu kill-agent` command. (client={client_version}, agent={agent_version})",
                agent_version = conn.version,
                client_version = crate::version::VERSION,
            )
        ).await;
    }

    Ok(conn)
}

/// The `AuthorizationError` an agent attached to a failure anywhere in `err`'s chain.
pub fn authorization_error(err: &anyhow::Error) -> Option<crate::proto::AuthorizationError> {
    err.chain().find_map(|e| {
        let status = e.downcast_ref::<tonic::Status>().or_else(|| {
            match e.downcast_ref::<crate::Error>() {
                Some(crate::Error::TonicStatusError(s)) => Some(s),
                _ => None,
            }
        })?;
        crate::proto::AuthorizationError::from_status(status)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_from(
        trust: crate::platform::PeerTrust,
        version: Option<&'static str>,
    ) -> tonic::Request<()> {
        let mut request = tonic::Request::new(());
        request
            .extensions_mut()
            .insert(std::sync::Arc::new(crate::platform::PeerIdentity {
                uid: 1000,
                gid: 973,
                real_gid: Some(1000),
                pid: 4242,
                pidfd: None,
                start_time: 1,
                exe: None,
                trust,
            }));
        if let Some(v) = version {
            request
                .metadata_mut()
                .insert(VERSION_METADATA, v.parse().unwrap());
        }
        request
    }

    fn unverified_peer(status: tonic::Status) -> crate::proto::AuthorizationError {
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        let err = AuthorizationError::from_status(&status).expect("AuthorizationError details");
        assert_eq!(
            err.reason(),
            crate::proto::authorization_error::Reason::UnverifiedPeer
        );
        assert_eq!(status.message(), err.detail);
        err
    }

    #[test]
    fn test_require_trusted_unverifiable() {
        let request = request_from(crate::platform::PeerTrust::Unverifiable, None);
        assert!(Agent::require_trusted(&request).is_ok());
    }

    #[test]
    fn test_require_trusted_no_peer_unhardened() {
        assert!(Agent::require_trusted(&tonic::Request::new(())).is_ok());
    }

    #[test]
    fn test_require_trusted_rejected() {
        let request = request_from(crate::platform::PeerTrust::Rejected, None);
        let err = unverified_peer(Agent::require_trusted(&request).unwrap_err());
        assert!(err.detail.contains("pid 4242"), "{}", err.detail);
        assert!(err.detail.contains("mairu doctor"), "{}", err.detail);
    }

    #[test]
    fn test_require_trusted_verified_current() {
        let request = request_from(
            crate::platform::PeerTrust::Verified,
            Some(crate::version::VERSION),
        );
        assert!(Agent::require_trusted(&request).is_ok());
    }

    #[test]
    fn test_require_trusted_verified_older_than_minimum() {
        let request = request_from(crate::platform::PeerTrust::Verified, Some("0.0.1"));
        let err = unverified_peer(Agent::require_trusted(&request).unwrap_err());
        assert!(
            err.detail.contains(crate::version::MINIMUM_CLIENT_VERSION),
            "{}",
            err.detail
        );
    }

    #[test]
    fn test_require_trusted_verified_without_version() {
        let request = request_from(crate::platform::PeerTrust::Verified, None);
        unverified_peer(Agent::require_trusted(&request).unwrap_err());
    }

    #[tokio::test]
    async fn test_agent_channel_unverified_refuses_locally() {
        let inner = tonic::transport::Endpoint::from_static("http://[::]:50051").connect_lazy();
        let mut client = crate::proto::agent_client::AgentClient::new(AgentChannel {
            inner,
            trust: crate::platform::AgentTrust::Unverified,
        });
        let status = client
            .list_sessions(tonic::Request::new(ListSessionsRequest {}))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert!(status.message().contains("not hardened"), "{status:?}");
    }

    #[test]
    fn test_unverified_agent_paths_exist() {
        for method in ["PingAgent", "GetAgentStatus", "ShutdownAgent"] {
            assert!(UNVERIFIED_AGENT_PATHS.contains(&format!("/mairu.Agent/{method}").as_str()));
        }
        assert_eq!(UNVERIFIED_AGENT_PATHS.len(), 3);
    }

    #[test]
    fn test_authorization_error_from_anyhow() {
        let status = AuthorizationError::unverified_peer("nope").into_status();
        let err = anyhow::Error::from(crate::Error::TonicStatusError(status));
        assert_eq!(authorization_error(&err).unwrap().detail, "nope");
        let err = anyhow::Error::from(tonic::Status::permission_denied("plain"));
        assert!(authorization_error(&err).is_none());
    }
}
