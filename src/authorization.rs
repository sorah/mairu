//! The gates of `AssumeRole`: decides whether a human must approve a request, before fetching (gate 1) and once the
//! credentials' caller identity is known (gate 2), asks through the platform helper, and remembers the answer as
//! grants (per terminal session) and leases (per running `mairu exec`).

// A refusal is the protocol's own AuthorizationError, returned once per request.
#![allow(clippy::result_large_err)]

const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
/// Credentials refused at gate 2 with a status the client retries after wait this long for the retry.
const HOLD_DURATION: std::time::Duration = std::time::Duration::from_secs(60);

/// The presence method backed by `PlatformServices::authorize`.
pub const METHOD_PLATFORM: &str = "platform";

const COMMAND_DETAIL_LIMIT: usize = 512;
const COMMAND_LINE_LIMIT: usize = 4096;

/// Time for ages and idle times.
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> std::time::Duration;
}

/// `CLOCK_BOOTTIME`, so that suspended time counts.
#[derive(Debug)]
pub struct BootClock;

impl Clock for BootClock {
    fn now(&self) -> std::time::Duration {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let id = nix::time::ClockId::CLOCK_BOOTTIME;
        // Darwin's CLOCK_MONOTONIC keeps counting during sleep.
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let id = nix::time::ClockId::CLOCK_MONOTONIC;
        nix::time::clock_gettime(id)
            .map(std::time::Duration::from)
            .unwrap_or_default()
    }
}

/// A `Rolespec` as a map key; a chained role is different access.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RoleKey {
    role: String,
    assume_role: Option<ChainKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ChainKey {
    role_arn: String,
    duration_seconds: Option<i32>,
    external_id: Option<String>,
    role_session_name: Option<String>,
}

impl From<&crate::proto::Rolespec> for RoleKey {
    fn from(r: &crate::proto::Rolespec) -> Self {
        Self {
            role: r.role.clone(),
            assume_role: r.assume_role.as_ref().map(|a| ChainKey {
                role_arn: a.role_arn.clone(),
                duration_seconds: a.duration_seconds,
                external_id: a.external_id.clone(),
                role_session_name: a.role_session_name.clone(),
            }),
        }
    }
}

type GrantKey = (crate::platform::SessionIdentity, String, RoleKey);
type LeaseKey = (u32, u64, String, RoleKey);

#[derive(Debug, Clone)]
struct Grant {
    created: std::time::Duration,
    last_used: std::time::Duration,
    method: String,
}

#[derive(Debug)]
struct Lease {
    created: std::time::Duration,
    method: String,
    last_demand_expiry: std::time::Duration,
    session: Option<crate::platform::SessionIdentity>,
    pidfd: std::sync::Arc<std::os::fd::OwnedFd>,
}

/// Fetched credentials waiting for the client's retry of a gate-2 check; never vended without passing gate 2.
#[derive(Debug)]
struct Held {
    credentials: std::sync::Arc<crate::client::AssumeRoleResponse>,
    caller: crate::caller_identity::Caller,
    until: std::time::Duration,
    session: Option<crate::platform::SessionIdentity>,
}

#[derive(Debug, Default)]
struct State {
    grants: std::collections::HashMap<GrantKey, Grant>,
    leases: std::collections::HashMap<LeaseKey, Lease>,
    held: std::collections::HashMap<FlightKey, Held>,
    marks: crate::tool_detection::Marks,
}

impl State {
    /// Grants are dropped after `retention` to bound memory; freshness itself is up to the policy.
    fn sweep(
        &mut self,
        now: std::time::Duration,
        retention: std::time::Duration,
        process: &dyn crate::platform::ProcessPlatform,
    ) {
        self.leases.retain(|_, l| pidfd_alive(&l.pidfd));
        self.marks.sweep(|s| process.session_alive(s));
        self.grants
            .retain(|_, g| now.saturating_sub(g.created) <= retention);
        self.held.retain(|_, h| now < h.until);
    }
}

type PromptFuture = futures::future::Shared<
    futures::future::BoxFuture<'static, crate::proto::platform::AuthorizeResponse>,
>;
type FlightKey = (u32, u64, [u8; 32]);

struct Shared {
    policy: crate::policy::files::PolicyFiles,
    checks: std::sync::Arc<parking_lot::Mutex<Checks>>,
    services: std::sync::Arc<dyn crate::platform::PlatformServices>,
    identifier: std::sync::Arc<dyn crate::caller_identity::Identify>,
    process: &'static dyn crate::platform::ProcessPlatform,
    clock: std::sync::Arc<dyn Clock>,
    hardened: bool,
    state: parking_lot::Mutex<State>,
    inflight: parking_lot::Mutex<
        std::collections::HashMap<
            FlightKey,
            futures::future::WeakShared<
                futures::future::BoxFuture<'static, crate::proto::platform::AuthorizeResponse>,
            >,
        >,
    >,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}

/// Holds every grant and lease in memory; restarting the agent forgets them.
#[derive(Clone)]
pub struct Authorizer {
    shared: std::sync::Arc<Shared>,
}

impl std::fmt::Debug for Authorizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorizer")
            .field("hardened", &self.shared.hardened)
            .finish()
    }
}

/// A request as gate 1 sees it; gate 2 adds the caller identity.
#[derive(Debug)]
pub struct Request<'a> {
    pub peer: Option<&'a crate::platform::PeerIdentity>,
    pub server: &'a crate::config::Server,
    /// Of the config captured in the server's session, or of its file when not logged in.
    pub server_digest: crate::policy::integrity_state::Digest,
    pub user_config: &'a crate::config::UserConfig,
    pub rolespec: &'a crate::proto::Rolespec,
    pub client_context: Option<&'a crate::proto::ClientContext>,
}

/// The facts about a request, gathered before deciding.
#[derive(Debug, Clone)]
struct Pending {
    pid: u32,
    start_time: u64,
    uid: u32,
    exe: Option<std::path::PathBuf>,
    pidfd: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
    session: Option<crate::platform::SessionIdentity>,
    server_id: String,
    role_key: RoleKey,
    exec: bool,
    prefetch: bool,
    facts: crate::policy::Facts,
    command_detail: Option<String>,
    digest: [u8; 32],
    detection: crate::tool_detection::Detection,
    /// What is in force for this request's server, at both gates.
    effective: std::sync::Arc<crate::policy::files::Effective>,
}

/// A permitted request. Report what was vended through [`Authorized::vended`].
#[derive(Debug)]
pub struct Authorized {
    shared: std::sync::Arc<Shared>,
    lease: Option<LeaseKey>,
    demand: bool,
    pending: Pending,
    /// What permitted it; counts as a remembered candidate at gate 2.
    presence: crate::policy::Presence,
}

/// Where vended credentials came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Cache,
    /// Held for the retry of a gate-2 check.
    Held,
    Fetched,
}

/// Credentials that passed both gates.
#[derive(Debug)]
pub struct Obtained {
    pub credentials: std::sync::Arc<crate::client::AssumeRoleResponse>,
    pub caller: Option<crate::caller_identity::Caller>,
    pub source: Source,
    pub authorized: Authorized,
}

impl Authorized {
    /// Credentials vended on demand keep the lease of the running `mairu exec` alive until they expire.
    pub fn vended(&self, expiration: Option<chrono::DateTime<chrono::Utc>>) {
        let (Some(key), true, Some(expiration)) = (&self.lease, self.demand, expiration) else {
            return;
        };
        let remaining = (expiration - chrono::Utc::now())
            .to_std()
            .unwrap_or_default();
        let expiry = self.shared.clock.now() + remaining;
        if let Some(lease) = self.shared.state.lock().leases.get_mut(key) {
            lease.last_demand_expiry = lease.last_demand_expiry.max(expiry);
        }
    }
}

type Refusal = crate::proto::AuthorizationError;

impl Authorizer {
    /// Starts the sweeper; needs a Tokio runtime.
    pub fn new(
        policy: crate::policy::files::PolicyFiles,
        services: std::sync::Arc<dyn crate::platform::PlatformServices>,
        hardened: bool,
    ) -> Self {
        let this = Self::with_clock(
            policy,
            services,
            std::sync::Arc::new(crate::caller_identity::Sts::default()),
            crate::platform::process(),
            hardened,
            std::sync::Arc::new(BootClock),
        );
        let weak = std::sync::Arc::downgrade(&this.shared);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(SWEEP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let Some(shared) = weak.upgrade() else {
                    return;
                };
                let now = shared.clock.now();
                let retention = shared.grant_retention();
                shared.state.lock().sweep(now, retention, shared.process);
            }
        });
        this
    }

    fn with_clock(
        policy: crate::policy::files::PolicyFiles,
        services: std::sync::Arc<dyn crate::platform::PlatformServices>,
        identifier: std::sync::Arc<dyn crate::caller_identity::Identify>,
        process: &'static dyn crate::platform::ProcessPlatform,
        hardened: bool,
        clock: std::sync::Arc<dyn Clock>,
    ) -> Self {
        Self {
            shared: std::sync::Arc::new(Shared {
                policy,
                services,
                identifier,
                process,
                clock,
                hardened,
                checks: Default::default(),
                state: Default::default(),
                inflight: Default::default(),
            }),
        }
    }

    /// The policy files in `config_dir()`, verified against the stores of the platform helper, and the built-ins for
    /// this process's hardening state. Fails only when the built-ins cannot be built.
    pub async fn from_config(
        services: std::sync::Arc<dyn crate::platform::PlatformServices>,
    ) -> Result<Self, String> {
        let hardened = crate::hardening::Hardening::marker().is_some();
        let policy = crate::policy::files::PolicyFiles::new(
            crate::config::config_dir(),
            hardened,
            crate::policy::files::Stores {
                services: services.clone(),
                uid: nix::unistd::geteuid().as_raw(),
                name: crate::policy::integrity_state::record_name().to_owned(),
            },
        );
        policy.load().await?;
        Ok(Self::new(policy, services, hardened))
    }

    /// The policy and settings in force now, verified.
    pub async fn policy(&self) -> Result<std::sync::Arc<crate::policy::files::Verified>, String> {
        self.shared.policy.load().await
    }

    /// Live grants and leases.
    pub fn counts(&self) -> (u32, u32) {
        let now = self.shared.clock.now();
        let retention = self.shared.grant_retention();
        let mut state = self.shared.state.lock();
        state.sweep(now, retention, self.shared.process);
        (
            u32::try_from(state.grants.len()).unwrap_or(u32::MAX),
            u32::try_from(state.leases.len()).unwrap_or(u32::MAX),
        )
    }

    /// The effective methods that could ask a human right now, in order.
    pub async fn methods(&self) -> Vec<String> {
        let Ok(verified) = self.shared.policy.load().await else {
            return vec![];
        };
        let mut methods = vec![];
        for method in &verified.effective.settings.methods {
            if method == METHOD_PLATFORM && self.shared.platform_usable().await.is_ok() {
                methods.push(method.clone());
            }
        }
        methods
    }

    /// Drops grants (of `session` only, when given) and, with `include_leases`, leases. Returns the counts.
    pub fn revoke(
        &self,
        session: Option<Option<crate::platform::SessionIdentity>>,
        include_leases: bool,
    ) -> (u32, u32) {
        let mut state = self.shared.state.lock();
        let (grants_before, leases_before) = (state.grants.len(), state.leases.len());
        match session {
            None => state.held.clear(),
            Some(session) => state.held.retain(|_, h| h.session != session),
        }
        match session {
            None => {
                state.grants.clear();
                if include_leases {
                    state.leases.clear();
                }
            }
            Some(session) => {
                state.grants.retain(|k, _| Some(k.0) != session);
                if include_leases {
                    state
                        .leases
                        .retain(|_, l| session.is_none() || l.session != session);
                }
            }
        }
        let revoked =
            |before: usize, after: usize| u32::try_from(before - after).unwrap_or(u32::MAX);
        (
            revoked(grants_before, state.grants.len()),
            revoked(leases_before, state.leases.len()),
        )
    }

    /// Marks a terminal session with tool labels until the session ends.
    pub fn mark_tools(&self, session: crate::platform::SessionIdentity, labels: &[String]) {
        self.shared.state.lock().marks.add(session, labels);
    }

    /// The labels the agent detects for `peer`, and those marked on its own terminal session.
    pub fn tools_of(
        &self,
        peer: &crate::platform::PeerIdentity,
        env_names: &[String],
    ) -> (crate::tool_detection::Detection, Vec<String>) {
        let labels = self
            .shared
            .policy
            .last()
            .map_or_else(crate::tool_detection::ToolLabel::builtin, |v| {
                v.effective.labels.clone()
            });
        let detection = self.shared.detect(Some(peer), env_names, &labels);
        let marks = self
            .shared
            .process
            .session_identity(peer)
            .map(|s| self.shared.state.lock().marks.get(&s).cloned().collect())
            .unwrap_or_default();
        (detection, marks)
    }

    /// Removes marks from the caller's terminal session. The marked tool could ask for this itself, so it always
    /// asks the human and never counts a grant or lease. Returns the labels still marked.
    pub async fn unmark_tools(
        &self,
        peer: Option<&crate::platform::PeerIdentity>,
        labels: &[String],
    ) -> Result<Vec<String>, tonic::Status> {
        use crate::proto::authorization_error::Reason;
        use crate::proto::platform::authorize_response::Result as R;
        let shared = &self.shared;
        let (peer, session) = match peer.map(|p| (p, shared.process.session_identity(p))) {
            Some((peer, Some(session @ crate::platform::SessionIdentity::Tty { .. }))) => {
                (peer, session)
            }
            _ => return Err(tonic::Status::failed_precondition(NO_TERMINAL_SESSION)),
        };
        let tty = shared
            .process
            .controlling_tty(peer)
            .unwrap_or_else(|| session.to_string());
        let quoted = labels
            .iter()
            .map(|l| format!("\"{l}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let noun = if labels.len() == 1 { "mark" } else { "marks" };
        let mut details = std::collections::HashMap::new();
        details.insert("tty".to_owned(), tty.clone());
        details.insert("tools".to_owned(), labels.join(", "));
        let request = crate::proto::platform::AuthorizeRequest {
            action: crate::proto::platform::authorize_request::Action::ApprovePolicy.into(),
            subject: Some(subject(
                peer.pid,
                peer.start_time,
                peer.uid,
                peer.exe.as_deref(),
            )),
            message: format!("Remove the tool {noun} {quoted} from {tty}"),
            details,
        };
        let refuse = |reason: Reason, detail: String| {
            tracing::info!(pid = peer.pid, session = ?session, tools = ?labels, reason = ?reason, detail, "Tool marks kept");
            Err(Refusal::new(reason, detail).into_status())
        };
        if let Err(e) = shared.platform_usable().await {
            return refuse(
                Reason::Unavailable,
                format!("no method could ask for approval; tried {METHOD_PLATFORM}: {e}"),
            );
        }
        let _check = match Checks::begin_check(&shared.checks, tty.clone()) {
            Ok(guard) => guard,
            Err(approval) => {
                return refuse(Reason::CheckPending, Checks::approval_pending(&approval));
            }
        };
        let resp = shared.services.authorize(request).await;
        match resp.result() {
            R::Allowed => {
                let remaining = shared.state.lock().marks.remove(&session, labels);
                tracing::info!(pid = peer.pid, session = ?session, tools = ?labels, remaining = ?remaining, "Removed tool marks");
                Ok(remaining)
            }
            R::Denied | R::Cancelled => refuse(Reason::Denied, resp.reason),
            R::Unavailable if resp.reason == REASON_NO_AUTHENTICATION_AGENT => {
                refuse(Reason::NoAuthenticationAgent, String::new())
            }
            R::Unavailable | R::Unspecified => refuse(
                Reason::Unavailable,
                format!(
                    "no method could ask for approval; tried {METHOD_PLATFORM}: {}: {}",
                    resp.reason, resp.detail
                ),
            ),
        }
    }

    /// Gate 1. Decides; asks a human when the policy would permit the request after a check and nothing
    /// remembered does.
    pub async fn authorize_assume_role(&self, req: Request<'_>) -> Result<Authorized, Refusal> {
        use crate::proto::authorization_error::Reason;
        let verified = self.shared.policy.load().await.map_err(|e| {
            Refusal::new(
                Reason::NotPermitted,
                format!("the authorization policy could not be built: {e}"),
            )
        })?;
        let server_state = verified.server_state(req.server.id(), &req.server_digest);
        let Some(effective) = verified.for_server(server_state) else {
            tracing::warn!(
                server_id = req.server.id(),
                server_url = %req.server.url,
                role = req.rolespec.role,
                "Refused: the server changed since the policy was approved"
            );
            let mut refusal = Refusal::new(
                Reason::Forbidden,
                format!(
                    "server '{}' ({}) changed since the policy was approved; review it and run `mairu policy approve`, then log in to it again",
                    req.server.id(),
                    req.server.url
                ),
            );
            refusal.gate = crate::proto::GATE_ASSUME_ROLE.to_owned();
            return Err(refusal);
        };
        let pending = self.shared.pending(&req, effective);
        if req
            .user_config
            .is_role_disallowed(req.server, &req.rolespec.role)
        {
            tracing::warn!(
                server_id = req.server.id(),
                role = req.rolespec.role,
                "Refused by disallow_roles"
            );
            let mut refusal = Refusal::new(
                crate::proto::authorization_error::Reason::Forbidden,
                format!(
                    "role '{}' is disallowed by disallow_roles in {}",
                    req.rolespec.role,
                    crate::config::UserConfig::path().display()
                ),
            );
            refusal.gate = crate::proto::GATE_ASSUME_ROLE.to_owned();
            refusal.tools = pending.detection.tools.iter().cloned().collect();
            return Err(refusal);
        }
        self.gate1(pending).await
    }

    async fn gate1(&self, pending: Pending) -> Result<Authorized, Refusal> {
        let result = self
            .shared
            .decide(pending.clone(), crate::policy::Action::AssumeRole, None)
            .await;
        if result.is_err() {
            self.shared.state.lock().held.remove(&pending.flight_key());
        }
        log_decision(&pending, None, &result);
        result
    }

    /// Gate 2: decides again with the caller identity of the credentials, counting what permitted gate 1 first. An
    /// unhardened agent skips it.
    pub async fn authorize_use_credentials(
        &self,
        gate1: Authorized,
        caller: &crate::caller_identity::Caller,
    ) -> Result<Authorized, Refusal> {
        if !gate1.pending.gate2(self.shared.hardened) {
            return Ok(gate1);
        }
        let result = self
            .shared
            .decide(
                gate1.pending.clone(),
                crate::policy::Action::UseCredentials(caller),
                Some(gate1.presence.clone()),
            )
            .await;
        log_decision(&gate1.pending, Some(caller), &result);
        let gate2 = result?;
        Ok(Authorized {
            lease: gate1.lease.or(gate2.lease),
            ..gate1
        })
    }

    /// Obtains credentials for a request gate 1 permitted, from those held for its retry, the cache, or `fetch`,
    /// and passes them through gate 2 with their caller identity. Caches them, with that identity, only once they
    /// pass.
    pub async fn obtain<F, Fut>(
        &self,
        gate1: Authorized,
        cache: &crate::credential_cache::CredentialCache,
        rolespec: &crate::proto::Rolespec,
        cacheable: bool,
        fetch: F,
    ) -> Result<Obtained, tonic::Status>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<crate::client::AssumeRoleResponse, tonic::Status>>,
    {
        use crate::proto::authorization_error::Reason;
        let key = gate1.pending.flight_key();
        let held = {
            let now = self.shared.clock.now();
            self.shared
                .state
                .lock()
                .held
                .remove(&key)
                .filter(|h| now < h.until)
        };
        let (credentials, caller, source) = if let Some(held) = held {
            (held.credentials, Some(held.caller), Source::Held)
        } else if cacheable && let Some(cached) = cache.get(rolespec) {
            (cached.credentials, cached.caller, Source::Cache)
        } else {
            (std::sync::Arc::new(fetch().await?), None, Source::Fetched)
        };

        if !gate1.pending.gate2(self.shared.hardened) {
            if cacheable && source == Source::Fetched {
                cache.store(rolespec.clone(), credentials.clone(), None);
            }
            return Ok(Obtained {
                credentials,
                caller: None,
                source,
                authorized: gate1,
            });
        }

        let caller = match caller {
            Some(caller) => caller,
            None => match self
                .shared
                .identifier
                .identify(&credentials, &gate1.pending.sts_target())
                .await
            {
                Ok(caller) => {
                    if source == Source::Cache {
                        cache.set_caller(rolespec, &credentials, caller.clone());
                    }
                    caller
                }
                Err(e) => {
                    tracing::warn!(
                        pid = gate1.pending.pid,
                        server_id = gate1.pending.server_id,
                        rolespec = ?gate1.pending.role_key,
                        aws_access_key_id = credentials.access_key_id,
                        err = e,
                        "Failed to identify the caller of credentials; refusing"
                    );
                    let mut refusal = Refusal::new(
                        Reason::Unavailable,
                        format!(
                            "could not identify the credentials through sts:GetCallerIdentity: {e}"
                        ),
                    );
                    refusal.gate = crate::proto::GATE_USE_CREDENTIALS.to_owned();
                    return Err(refusal.into_status());
                }
            },
        };

        let session = gate1.pending.session;
        match self.authorize_use_credentials(gate1, &caller).await {
            Ok(authorized) => {
                if cacheable && source != Source::Cache {
                    cache.store(rolespec.clone(), credentials.clone(), Some(caller.clone()));
                }
                Ok(Obtained {
                    credentials,
                    caller: Some(caller),
                    source,
                    authorized,
                })
            }
            Err(refusal) => {
                if refusal.reason() == Reason::NoAuthenticationAgent {
                    let until = self.shared.clock.now() + HOLD_DURATION;
                    self.shared.state.lock().held.insert(
                        key,
                        Held {
                            credentials,
                            caller,
                            until,
                            session,
                        },
                    );
                }
                Err(refusal.into_status())
            }
        }
    }
}

fn log_decision(
    pending: &Pending,
    caller: Option<&crate::caller_identity::Caller>,
    result: &Result<Authorized, Refusal>,
) {
    let gate = match caller {
        None => crate::proto::GATE_ASSUME_ROLE,
        Some(_) => crate::proto::GATE_USE_CREDENTIALS,
    };
    let caller_arn = caller.map(|c| c.arn.as_str());
    match result {
        Ok(a) => tracing::info!(
            gate,
            pid = pending.pid,
            session = ?pending.session,
            server_id = pending.server_id,
            rolespec = ?pending.role_key,
            intent = pending.facts.intent,
            tools = ?pending.detection.tool_matches,
            caller_arn,
            presence = a.presence.scope.as_str(),
            "Authorization permitted"
        ),
        Err(e) => tracing::info!(
            gate,
            pid = pending.pid,
            session = ?pending.session,
            server_id = pending.server_id,
            rolespec = ?pending.role_key,
            intent = pending.facts.intent,
            tools = ?pending.detection.tool_matches,
            caller_arn,
            reason = ?e.reason(),
            detail = e.detail,
            "Authorization refused"
        ),
    }
}

impl Shared {
    fn grant_retention(&self) -> std::time::Duration {
        self.policy.last().map_or_else(
            || crate::policy::settings::EffectiveSettings::default().grant_retention(),
            |v| v.effective.settings.grant_retention(),
        )
    }

    fn pending(
        &self,
        req: &Request<'_>,
        effective: std::sync::Arc<crate::policy::files::Effective>,
    ) -> Pending {
        let platform = self.process;
        let env_names = req
            .client_context
            .map(|c| c.env_names.as_slice())
            .unwrap_or_default();
        let detection = self.detect(req.peer, env_names, &effective.labels);
        let session = req.peer.and_then(|p| platform.session_identity(p));
        let tty = req.peer.and_then(|p| platform.controlling_tty(p));
        let uid = req
            .peer
            .map(|p| p.uid)
            .unwrap_or_else(|| nix::unistd::geteuid().as_raw());
        let pidfd = req
            .peer
            .and_then(|p| p.pidfd.as_ref())
            .and_then(|fd| fd.try_clone().ok())
            .map(std::sync::Arc::new);
        let mut pending = Pending::new(
            req,
            uid,
            session,
            if session.is_some_and(|s| s.kind() == "tty") {
                tty
            } else {
                None
            },
            self.hardened,
            detection,
            effective,
        );
        pending.pidfd = pidfd;
        pending
    }

    /// Detection runs once per request, and its result serves every candidate at both gates.
    fn detect(
        &self,
        peer: Option<&crate::platform::PeerIdentity>,
        env_names: &[String],
        labels: &[crate::tool_detection::ToolLabel],
    ) -> crate::tool_detection::Detection {
        let ancestry = peer
            .map(|p| self.process.ancestry(p.pid, p.start_time, p.uid))
            .unwrap_or_default();
        crate::tool_detection::Detection::detect(
            &ancestry,
            env_names,
            &self.state.lock().marks,
            labels,
        )
    }

    async fn platform_usable(&self) -> Result<(), String> {
        let caps = self.services.capabilities().await;
        match caps.authorization() {
            crate::proto::platform::AuthorizationFacility::None
            | crate::proto::platform::AuthorizationFacility::Unspecified => {
                let notes = if caps.notes.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", caps.notes.join("; "))
                };
                Err(format!("no authorization facility{notes}"))
            }
            _ => Ok(()),
        }
    }

    /// The decision procedure at either gate. `extra` is a remembered candidate tried first.
    async fn decide(
        self: &std::sync::Arc<Self>,
        pending: Pending,
        action: crate::policy::Action<'_>,
        extra: Option<crate::policy::Presence>,
    ) -> Result<Authorized, Refusal> {
        let caller = match action {
            crate::policy::Action::AssumeRole => None,
            crate::policy::Action::UseCredentials(caller) => Some(caller),
        };
        let pending_tools = pending.detection.tools.iter().cloned().collect();
        self.decide_at(pending, action, extra)
            .await
            .map_err(|mut refusal| {
                refusal.tools = pending_tools;
                match caller {
                    None => refusal.gate = crate::proto::GATE_ASSUME_ROLE.to_owned(),
                    Some(caller) => {
                        refusal.gate = crate::proto::GATE_USE_CREDENTIALS.to_owned();
                        refusal.caller_arn = caller.arn.clone();
                    }
                }
                refusal
            })
    }

    async fn decide_at(
        self: &std::sync::Arc<Self>,
        pending: Pending,
        action: crate::policy::Action<'_>,
        extra: Option<crate::policy::Presence>,
    ) -> Result<Authorized, Refusal> {
        use crate::proto::authorization_error::Reason;
        let caller = match action {
            crate::policy::Action::AssumeRole => None,
            crate::policy::Action::UseCredentials(caller) => Some(caller),
        };
        let effective = pending.effective.clone();
        let engine = &effective.engine;
        let retention = effective.settings.grant_retention();
        let prepared = engine.prepare(&pending.facts, action).map_err(|e| {
            tracing::error!(
                err = e,
                "Failed to build the authorization request; refusing"
            );
            Refusal::new(
                Reason::NotPermitted,
                format!("invalid authorization request: {e}"),
            )
        })?;
        let lease_key: LeaseKey = (
            pending.pid,
            pending.start_time,
            pending.server_id.clone(),
            pending.role_key.clone(),
        );
        let mut forbids: Vec<String> = vec![];
        let mut note = |eval: &crate::policy::Evaluation| {
            if !eval.errors.is_empty() {
                tracing::error!(errors = ?eval.errors, "Policy evaluation failed; counted as Deny");
            }
            for id in &eval.forbids {
                if !forbids.contains(id) {
                    forbids.push(id.clone());
                }
            }
            eval.allowed
        };

        // What is remembered: what permitted gate 1, nothing, the lease of this process, the grant of this session.
        {
            let now = self.clock.now();
            let mut state = self.state.lock();
            let has_lease = state
                .leases
                .get(&lease_key)
                .is_some_and(|l| pidfd_alive(&l.pidfd));
            let authorized = |lease: bool, presence: crate::policy::Presence| Authorized {
                shared: self.clone(),
                lease: lease.then(|| lease_key.clone()),
                demand: !pending.prefetch,
                pending: pending.clone(),
                presence,
            };
            if let Some(presence) = extra.filter(|p| p.verified)
                && note(&engine.evaluate(&prepared, &presence))
            {
                return Ok(authorized(has_lease, presence));
            }
            let none = crate::policy::Presence::none();
            if note(&engine.evaluate(&prepared, &none)) {
                return Ok(authorized(has_lease, none));
            }
            if let Some(lease) = state.leases.get(&lease_key)
                && pidfd_alive(&lease.pidfd)
            {
                let presence = crate::policy::Presence::remembered(
                    crate::policy::Scope::Process,
                    &lease.method,
                    secs(now.saturating_sub(lease.created)),
                    secs(now.saturating_sub(lease.last_demand_expiry)),
                );
                if note(&engine.evaluate(&prepared, &presence)) {
                    return Ok(authorized(true, presence));
                }
            }
            if let Some(session) = pending.session {
                let key: GrantKey = (session, pending.server_id.clone(), pending.role_key.clone());
                if let Some(grant) = state.grants.get_mut(&key)
                    && now.saturating_sub(grant.created) <= retention
                {
                    let presence = crate::policy::Presence::remembered(
                        crate::policy::Scope::Session,
                        &grant.method,
                        secs(now.saturating_sub(grant.created)),
                        secs(now.saturating_sub(grant.last_used)),
                    );
                    if note(&engine.evaluate(&prepared, &presence)) {
                        grant.last_used = now;
                        return Ok(authorized(has_lease, presence));
                    }
                }
            }
        }

        if pending.prefetch {
            return Err(Refusal::new(
                Reason::PresenceRequired,
                "a pre-fetch needs a fresh human check; nobody was asked",
            ));
        }

        // What could be asked.
        let mut tried: Vec<String> = vec![];
        let mut fresh_allowed = false;
        for method in effective.settings.methods.iter().map(String::as_str) {
            if method != METHOD_PLATFORM {
                continue;
            }
            let presence = crate::policy::Presence::fresh(method);
            if !note(&engine.evaluate(&prepared, &presence)) {
                continue;
            }
            fresh_allowed = true;
            if let Err(e) = self.platform_usable().await {
                tried.push(format!("{method}: {e}"));
                continue;
            }
            let origin = pending
                .facts
                .tty
                .clone()
                .unwrap_or_else(|| format!("pid {}", pending.pid));
            let _check = Checks::begin_check(&self.checks, origin).map_err(|approval| {
                Refusal::new(Reason::CheckPending, Checks::approval_pending(&approval))
            })?;
            let resp = self.prompt(&pending, caller).await;
            use crate::proto::platform::authorize_response::Result as R;
            match resp.result() {
                R::Allowed => {
                    self.record(&pending, &lease_key, method);
                    return Ok(Authorized {
                        shared: self.clone(),
                        lease: (pending.exec && pending.pidfd.is_some()).then_some(lease_key),
                        demand: true,
                        pending,
                        presence,
                    });
                }
                R::Denied | R::Cancelled => {
                    return Err(Refusal::new(Reason::Denied, resp.reason));
                }
                R::Unavailable if resp.reason == REASON_NO_AUTHENTICATION_AGENT => {
                    return Err(Refusal::new(Reason::NoAuthenticationAgent, ""));
                }
                R::Unavailable | R::Unspecified => {
                    tried.push(format!("{method}: {}: {}", resp.reason, resp.detail));
                }
            }
        }
        if fresh_allowed {
            return Err(Refusal::new(
                Reason::Unavailable,
                format!(
                    "no method could ask for approval; tried {}",
                    tried.join(", ")
                ),
            ));
        }
        if !forbids.is_empty() {
            let detail = match caller {
                Some(caller)
                    if forbids
                        .iter()
                        .any(|id| id == crate::policy::POLICY_CALLER_ACCOUNT_MISMATCH) =>
                {
                    format!(
                        "credentials belong to {} ({}), not to the account the role name declares ({})",
                        caller.account,
                        caller.arn,
                        crate::policy::account_id(&pending.facts.role).unwrap_or_default()
                    )
                }
                _ => format!("refused by policy {}", forbids.join(", ")),
            };
            let mut refusal = Refusal::new(Reason::Forbidden, detail);
            refusal.policy_ids = forbids;
            return Err(refusal);
        }
        Err(Refusal::new(
            Reason::NotPermitted,
            "no policy permits this role, even after a human check",
        ))
    }

    /// Concurrent identical requests from one process at the same gate share one prompt. Dropping every waiter
    /// cancels it.
    async fn prompt(
        &self,
        pending: &Pending,
        caller: Option<&crate::caller_identity::Caller>,
    ) -> crate::proto::platform::AuthorizeResponse {
        use futures::FutureExt;
        let key: FlightKey = match caller {
            None => pending.flight_key(),
            Some(_) => (
                pending.pid,
                pending.start_time,
                gate2_digest(&pending.digest),
            ),
        };
        let flight: PromptFuture = {
            let mut inflight = self.inflight.lock();
            inflight.retain(|_, w| w.upgrade().is_some());
            match inflight.get(&key).and_then(|w| w.upgrade()) {
                Some(f) => f,
                None => {
                    let services = self.services.clone();
                    let request = pending.authorize_request(caller);
                    let fut: futures::future::BoxFuture<'static, _> =
                        Box::pin(async move { services.authorize(request).await });
                    let shared = fut.shared();
                    if let Some(weak) = shared.downgrade() {
                        inflight.insert(key, weak);
                    }
                    shared
                }
            }
        };
        flight.await
    }

    fn record(&self, pending: &Pending, lease_key: &LeaseKey, method: &str) {
        let now = self.clock.now();
        let mut state = self.state.lock();
        if pending.exec
            && let Some(pidfd) = &pending.pidfd
        {
            state.leases.insert(
                lease_key.clone(),
                Lease {
                    created: now,
                    method: method.to_owned(),
                    last_demand_expiry: now,
                    session: pending.session,
                    pidfd: pidfd.clone(),
                },
            );
        }
        if let Some(session) = pending.session {
            state.grants.insert(
                (session, pending.server_id.clone(), pending.role_key.clone()),
                Grant {
                    created: now,
                    last_used: now,
                    method: method.to_owned(),
                },
            );
        }
    }
}

/// Human checks waiting for an answer. A policy approval and credential checks are never pending together, so a
/// human expecting a credential prompt is never handed an approval prompt instead.
#[derive(Debug, Default)]
struct Checks {
    next: u64,
    approval: Option<(u64, String)>,
    checks: std::collections::HashMap<u64, String>,
}

/// What kept an approval from starting.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Busy {
    Approval(String),
    Check(String),
}

impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Busy::Approval(origin) => write!(f, "another policy approval is pending from {origin}"),
            Busy::Check(origin) => write!(f, "a credential check is pending from {origin}"),
        }
    }
}

/// Ends its check when dropped.
#[derive(Debug)]
struct CheckGuard {
    checks: std::sync::Arc<parking_lot::Mutex<Checks>>,
    id: u64,
}

impl Drop for CheckGuard {
    fn drop(&mut self) {
        let mut checks = self.checks.lock();
        checks.checks.remove(&self.id);
        if checks
            .approval
            .as_ref()
            .is_some_and(|(id, _)| *id == self.id)
        {
            checks.approval = None;
        }
    }
}

impl Checks {
    /// A check that is not an approval; `Err` names the terminal of the pending approval.
    fn begin_check(
        checks: &std::sync::Arc<parking_lot::Mutex<Checks>>,
        origin: String,
    ) -> Result<CheckGuard, String> {
        let mut c = checks.lock();
        if let Some((_, approval)) = &c.approval {
            return Err(approval.clone());
        }
        c.next += 1;
        let id = c.next;
        c.checks.insert(id, origin);
        Ok(CheckGuard {
            checks: checks.clone(),
            id,
        })
    }

    fn begin_approval(
        checks: &std::sync::Arc<parking_lot::Mutex<Checks>>,
        origin: String,
    ) -> Result<CheckGuard, Busy> {
        let mut c = checks.lock();
        if let Some((_, approval)) = &c.approval {
            return Err(Busy::Approval(approval.clone()));
        }
        if let Some(check) = c.checks.values().next() {
            return Err(Busy::Check(check.clone()));
        }
        c.next += 1;
        let id = c.next;
        c.approval = Some((id, origin));
        Ok(CheckGuard {
            checks: checks.clone(),
            id,
        })
    }

    fn approval_pending(origin: &str) -> String {
        format!(
            "a policy approval is pending from {origin}; if you did not start it, something else is trying to approve the policy"
        )
    }
}

/// An `ApprovePolicy` request, with what the agent read itself.
#[derive(Debug)]
pub struct Approval<'a> {
    pub peer: Option<&'a crate::platform::PeerIdentity>,
    pub expected_digest: &'a [u8],
    pub expected_server_digests: &'a std::collections::HashMap<String, Vec<u8>>,
    /// Of each server in `servers.d`, as the files are now.
    pub server_digests: std::collections::BTreeMap<String, crate::policy::integrity_state::Digest>,
}

impl Authorizer {
    /// Records the policy files and server configs after asking the human through the approval anchor in force.
    /// Never uses or records grants.
    pub async fn approve_policy(
        &self,
        approval: Approval<'_>,
    ) -> Result<crate::proto::ApprovePolicyResponse, tonic::Status> {
        use crate::proto::authorization_error::Reason;
        use crate::proto::platform::authorize_response::Result as R;
        let shared = &self.shared;
        let (Some(dir), Some(stores)) = (shared.policy.dir(), shared.policy.stores()) else {
            return Err(tonic::Status::failed_precondition(
                "this agent has no policy files to approve",
            ));
        };
        let Some(peer) = approval.peer else {
            return Err(tonic::Status::failed_precondition(
                "the requesting process could not be identified",
            ));
        };
        let origin = shared
            .process
            .controlling_tty(peer)
            .unwrap_or_else(|| format!("pid {}", peer.pid));
        let _approval = Checks::begin_approval(&shared.checks, origin.clone()).map_err(|busy| {
            tracing::warn!(pid = peer.pid, origin, busy = %busy, "Refused a policy approval");
            tonic::Status::failed_precondition(busy.to_string())
        })?;

        let (policy, settings) = crate::policy::files::PolicyFiles::read_contents(dir);
        let digest = crate::policy::integrity_state::policy_digest(&policy, &settings);
        let servers_match = approval.expected_server_digests.len() == approval.server_digests.len()
            && approval.server_digests.iter().all(|(id, d)| {
                approval.expected_server_digests.get(id).map(Vec::as_slice) == Some(d.as_slice())
            });
        if approval.expected_digest != digest.as_slice() || !servers_match {
            return Err(tonic::Status::failed_precondition(
                "policy changed while approving; run `mairu policy approve` again",
            ));
        }
        let file_settings = Self::validate_for_approval(&policy, &settings)
            .map_err(|errors| tonic::Status::invalid_argument(errors.join("; ")))?;

        let files_absent = policy == crate::policy::files::Content::Absent
            && settings == crate::policy::files::Content::Absent;
        let decision = crate::policy::integrity_state::Decision::decide(
            stores.verify(&digest).await,
            &digest,
            files_absent,
            shared.hardened,
        );
        let servers: std::collections::BTreeMap<String, crate::policy::integrity_state::Digest> =
            approval.server_digests.clone();
        let approval_digest = crate::policy::integrity_state::approval_digest(&digest, &servers);
        let mut details = std::collections::HashMap::new();
        details.insert(
            "policy_digest".to_owned(),
            crate::platform::integrity::hex(&approval_digest),
        );
        details.insert("tty".to_owned(), origin.clone());
        let request = crate::proto::platform::AuthorizeRequest {
            action: crate::proto::platform::authorize_request::Action::ApprovePolicy.into(),
            subject: Some(subject(
                peer.pid,
                peer.start_time,
                peer.uid,
                peer.exe.as_deref(),
            )),
            message: format!(
                "Approve the mairu policy {}",
                &crate::platform::integrity::hex(&approval_digest)[..16]
            ),
            details,
        };
        let refuse = |reason: Reason, detail: String| {
            tracing::info!(pid = peer.pid, origin, reason = ?reason, detail, "Policy approval refused");
            Err(Refusal::new(reason, detail).into_status())
        };
        let mut tried = vec![];
        let mut allowed = false;
        for method in &decision.anchor.methods {
            if method != METHOD_PLATFORM {
                tried.push(format!("{method}: not supported by this mairu"));
                continue;
            }
            if let Err(e) = shared.platform_usable().await {
                tried.push(format!("{method}: {e}"));
                continue;
            }
            tracing::info!(
                pid = peer.pid,
                origin,
                digest = crate::platform::integrity::hex(&digest),
                "Asking to approve the policy"
            );
            let resp = shared.services.authorize(request.clone()).await;
            match resp.result() {
                R::Allowed => {
                    allowed = true;
                    break;
                }
                R::Denied | R::Cancelled => return refuse(Reason::Denied, resp.reason),
                R::Unavailable if resp.reason == REASON_NO_AUTHENTICATION_AGENT => {
                    return refuse(Reason::NoAuthenticationAgent, String::new());
                }
                R::Unavailable | R::Unspecified => {
                    tried.push(format!("{method}: {}: {}", resp.reason, resp.detail));
                }
            }
        }
        if !allowed {
            return refuse(
                Reason::Unavailable,
                format!(
                    "no method of the approval anchor could ask for approval; tried {}",
                    tried.join(", ")
                ),
            );
        }

        let record = crate::proto::platform::IntegrityRecord {
            digest: digest.to_vec(),
            approval: Some(crate::policy::settings::EffectiveSettings::anchor(
                file_settings.as_ref(),
            )),
            generation: 1 + decision.strong.as_ref().map_or(0, |r| r.generation),
            server_digests: servers
                .iter()
                .map(|(id, d)| (id.clone(), d.to_vec()))
                .collect(),
        };
        let results = stores.record(record.clone(), vec![]).await;
        let written = results
            .iter()
            .any(|r| r.status() == crate::proto::platform::IntegrityStatus::Matched);
        shared.policy.invalidate().await;
        if !written {
            tracing::warn!(stores = ?results, "No integrity store could record the approval");
            let details: Vec<String> = results
                .iter()
                .map(|r| {
                    format!(
                        "{}: {}",
                        crate::platform::integrity::store_name(r.store()),
                        r.detail
                    )
                })
                .collect();
            return Err(tonic::Status::failed_precondition(format!(
                "no integrity store is available to record the approval ({})",
                if details.is_empty() {
                    "none reachable".to_owned()
                } else {
                    details.join("; ")
                }
            )));
        }
        let verified = shared
            .policy
            .load()
            .await
            .map_err(tonic::Status::internal)?;
        tracing::info!(
            pid = peer.pid,
            origin,
            generation = record.generation,
            digest = crate::platform::integrity::hex(&digest),
            servers = ?servers.keys().collect::<Vec<_>>(),
            state = verified.state.as_str(),
            "Policy approved"
        );
        Ok(crate::proto::ApprovePolicyResponse {
            integrity: verified.state.to_proto().into(),
            stores: results,
        })
    }

    /// The checks of `mairu policy check` that fail an approval. Returns the parsed settings.
    fn validate_for_approval(
        policy: &crate::policy::files::Content,
        settings: &crate::policy::files::Content,
    ) -> Result<Option<crate::policy::settings::AuthorizationSettings>, Vec<String>> {
        use crate::policy::files::Content;
        let mut errors = vec![];
        match policy {
            Content::Absent => {}
            Content::Unreadable(e) => {
                errors.push(format!("{}: {e}", crate::policy::user::FILE_NAME))
            }
            Content::Text(source) => match crate::policy::user::PolicyFile::parse(source) {
                Err(e) => errors.push(format!("{}: {e}", crate::policy::user::FILE_NAME)),
                Ok(file) => match crate::policy::schema() {
                    Ok(schema) => errors.extend(file.errors(&schema)),
                    Err(e) => errors.push(e.to_string()),
                },
            },
        }
        let parsed = match settings {
            Content::Absent => None,
            Content::Unreadable(e) => {
                errors.push(format!("{}: {e}", crate::policy::files::SETTINGS_FILE_NAME));
                None
            }
            Content::Text(source) => {
                match crate::policy::settings::AuthorizationSettings::parse(source) {
                    Ok(s) => Some(s),
                    Err(e) => {
                        errors.push(format!("{}: {e}", crate::policy::files::SETTINGS_FILE_NAME));
                        None
                    }
                }
            }
        };
        if errors.is_empty() {
            Ok(parsed)
        } else {
            Err(errors)
        }
    }
}

/// Tool marks belong to a terminal session.
pub const NO_TERMINAL_SESSION: &str = "tool marks need a terminal session, and this process has none; run `mairu lock --tool` in the terminal that starts the tool";

/// `AuthorizeResponse.reason` when polkit has no authentication agent for the subject.
pub const REASON_NO_AUTHENTICATION_AGENT: &str = "no-authentication-agent";

fn secs(d: std::time::Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

impl Pending {
    fn new(
        req: &Request<'_>,
        uid: u32,
        session: Option<crate::platform::SessionIdentity>,
        tty: Option<String>,
        hardened: bool,
        detection: crate::tool_detection::Detection,
        effective: std::sync::Arc<crate::policy::files::Effective>,
    ) -> Self {
        let context = req.client_context.cloned().unwrap_or_default();
        let exec = match &context.intent {
            Some(crate::proto::client_context::Intent::Exec(e)) => Some(e),
            _ => None,
        };
        let intent = match &context.intent {
            Some(crate::proto::client_context::Intent::Exec(_)) => "exec",
            Some(crate::proto::client_context::Intent::CredentialProcess(_)) => {
                "credential-process"
            }
            None => "unknown",
        };
        let command_line = exec.map(|e| shell_join(&e.command));
        let user_name = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .ok()
            .flatten()
            .map(|u| u.name)
            .unwrap_or_else(|| uid.to_string());
        let facts = crate::policy::Facts {
            uid,
            user_name,
            server_id: req.server.id().to_owned(),
            server_url: req.server.url.to_string(),
            role: req.rolespec.role.clone(),
            session: session.map_or("none", |s| s.kind()),
            tty,
            hardened,
            intent,
            exec_command: exec.and_then(|e| e.command.first()).map(|argv0| {
                let argv0 = String::from_utf8_lossy(argv0);
                argv0.rsplit('/').next().unwrap_or_default().to_owned()
            }),
            exec_command_line: command_line
                .as_deref()
                .map(|l| truncate(l, COMMAND_LINE_LIMIT).to_owned()),
            cwd: (!context.cwd.is_empty())
                .then(|| String::from_utf8_lossy(&context.cwd).into_owned()),
            chained_role_arn: req
                .rolespec
                .assume_role
                .as_ref()
                .map(|a| a.role_arn.clone()),
            tools: detection.tools.clone(),
            tool_matches: detection.tool_matches.clone(),
        };
        Self {
            pid: req.peer.map_or(0, |p| p.pid),
            start_time: req.peer.map_or(0, |p| p.start_time),
            uid,
            exe: req.peer.and_then(|p| p.exe.clone()),
            pidfd: None,
            session,
            server_id: req.server.id().to_owned(),
            role_key: req.rolespec.into(),
            exec: exec.is_some(),
            prefetch: exec.is_some_and(|e| e.prefetch),
            command_detail: command_line.map(|l| truncate(&l, COMMAND_DETAIL_LIMIT).to_owned()),
            digest: request_digest(req.server.id(), req.rolespec, &context),
            facts,
            detection,
            effective,
        }
    }

    /// Gate 2 is skipped only on an unhardened agent without an approved policy, where everything is permitted
    /// anyway.
    fn gate2(&self, hardened: bool) -> bool {
        hardened || self.effective.state == crate::policy::settings::PolicyState::Approved
    }

    fn sts_target(&self) -> crate::caller_identity::StsTarget {
        crate::caller_identity::StsTarget::from_settings(
            self.effective.settings.sts.as_ref(),
            &self.server_id,
        )
    }

    /// Identifies the request; also the key of its held credentials.
    fn flight_key(&self) -> FlightKey {
        (self.pid, self.start_time, self.digest)
    }

    fn authorize_request(
        &self,
        caller: Option<&crate::caller_identity::Caller>,
    ) -> crate::proto::platform::AuthorizeRequest {
        let f = &self.facts;
        let mut details = std::collections::HashMap::new();
        details.insert("server".to_owned(), f.server_id.clone());
        details.insert("server_url".to_owned(), f.server_url.clone());
        details.insert("role".to_owned(), f.role.clone());
        details.insert(
            "command".to_owned(),
            self.command_detail
                .clone()
                .unwrap_or_else(|| "(unknown)".to_owned()),
        );
        if let Some(cwd) = &f.cwd {
            details.insert("cwd".to_owned(), cwd.clone());
        }
        if let Some(tty) = &f.tty {
            details.insert("tty".to_owned(), tty.clone());
        }
        let exe = self
            .exe
            .as_ref()
            .map_or_else(|| "(unknown)".to_owned(), |e| e.display().to_string());
        details.insert("requester".to_owned(), format!("{exe} pid {}", self.pid));
        details.insert("intent".to_owned(), f.intent.to_owned());
        if !self.detection.is_empty() {
            details.insert("tools".to_owned(), self.detection.summary());
        }
        let mut message = format!(
            "Provide AWS credentials for {} on {} ({})",
            f.role, f.server_id, f.server_url
        );
        if let Some(caller) = caller {
            details.insert(
                "caller".to_owned(),
                format!("{} {}", caller.account, caller.arn),
            );
            message.push_str(&format!(" ({})", caller.summary()));
        }
        crate::proto::platform::AuthorizeRequest {
            action: crate::proto::platform::authorize_request::Action::AssumeRole.into(),
            subject: Some(subject(
                self.pid,
                self.start_time,
                self.uid,
                self.exe.as_deref(),
            )),
            message,
            details,
        }
    }
}

fn subject(
    pid: u32,
    start_time: u64,
    uid: u32,
    exe: Option<&std::path::Path>,
) -> crate::proto::platform::Process {
    use std::os::unix::ffi::OsStrExt;
    crate::proto::platform::Process {
        pid,
        start_time,
        uid,
        executable: exe
            .map(|e| e.as_os_str().as_bytes().to_vec())
            .unwrap_or_default(),
        argv: vec![],
        name: String::new(),
    }
}

/// SHA-256 over the prost encoding of the action, server, rolespec and client context: what the human sees.
fn request_digest(
    server_id: &str,
    rolespec: &crate::proto::Rolespec,
    context: &crate::proto::ClientContext,
) -> [u8; 32] {
    use prost::Message;
    use sha2::Digest;
    let request = crate::proto::AssumeRoleRequest {
        server_id: server_id.to_owned(),
        query: Some(crate::proto::assume_role_request::Query::Rolespec(
            rolespec.clone(),
        )),
        cached: false,
        client_context: Some(context.clone()),
    };
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"AssumeRole\0");
    hasher.update(request.encode_to_vec());
    hasher.finalize().into()
}

/// Keeps a gate-2 prompt from sharing a gate-1 prompt for the same request.
fn gate2_digest(digest: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"UseCredentials\0");
    hasher.update(digest);
    hasher.finalize().into()
}

/// POSIX shell quoting, for display. Non-UTF-8 bytes become U+FFFD.
pub fn shell_join(argv: &[Vec<u8>]) -> String {
    argv.iter()
        .map(|a| {
            let a = String::from_utf8_lossy(a);
            let plain = !a.is_empty()
                && a.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "@%+=:,./-_".contains(c));
            if plain {
                a.into_owned()
            } else {
                format!("'{}'", a.replace('\'', r"'\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn truncate(s: &str, limit: usize) -> &str {
    if s.len() <= limit {
        return s;
    }
    let mut end = limit;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(target_os = "linux")]
fn pidfd_alive(pidfd: &std::os::fd::OwnedFd) -> bool {
    use std::os::fd::AsFd;
    crate::platform::process::linux::peer::pidfd_alive(pidfd.as_fd())
}

#[cfg(not(target_os = "linux"))]
fn pidfd_alive(_pidfd: &std::os::fd::OwnedFd) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::authorization_error::Reason;
    use crate::proto::platform::authorize_response::Result as R;

    #[derive(Debug, Default)]
    struct TestClock(parking_lot::Mutex<std::time::Duration>);

    impl TestClock {
        fn advance(&self, secs: u64) {
            *self.0.lock() += std::time::Duration::from_secs(secs);
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> std::time::Duration {
            *self.0.lock()
        }
    }

    #[derive(Debug)]
    struct MockServices {
        facility: crate::proto::platform::AuthorizationFacility,
        answer: parking_lot::Mutex<crate::proto::platform::AuthorizeResponse>,
        prompts: std::sync::atomic::AtomicUsize,
        delay: std::time::Duration,
        stores: std::sync::Arc<crate::policy::files::test_support::MemoryStores>,
        last_request: parking_lot::Mutex<Option<crate::proto::platform::AuthorizeRequest>>,
    }

    impl MockServices {
        fn answering(result: R, reason: &str) -> std::sync::Arc<Self> {
            Self::answering_after(result, reason, std::time::Duration::ZERO)
        }

        fn answering_after(
            result: R,
            reason: &str,
            delay: std::time::Duration,
        ) -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                facility: crate::proto::platform::AuthorizationFacility::Polkit,
                answer: parking_lot::Mutex::new(crate::proto::platform::AuthorizeResponse {
                    result: result.into(),
                    reason: reason.to_owned(),
                    detail: String::new(),
                }),
                prompts: Default::default(),
                delay,
                stores: crate::policy::files::test_support::MemoryStores::new(true, true),
                last_request: Default::default(),
            })
        }

        fn prompts(&self) -> usize {
            self.prompts.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl crate::platform::PlatformServices for MockServices {
        async fn capabilities(&self) -> crate::proto::platform::Capabilities {
            crate::proto::platform::Capabilities {
                authorization: self.facility.into(),
                ..Default::default()
            }
        }
        async fn authorize(
            &self,
            req: crate::proto::platform::AuthorizeRequest,
        ) -> crate::proto::platform::AuthorizeResponse {
            *self.last_request.lock() = Some(req);
            self.prompts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            self.answer.lock().clone()
        }
        async fn notify(
            &self,
            _req: crate::proto::platform::NotifyRequest,
        ) -> crate::proto::platform::NotifyResponse {
            Default::default()
        }
        async fn open_url(
            &self,
            _req: crate::proto::platform::OpenUrlRequest,
        ) -> crate::proto::platform::OpenUrlResponse {
            Default::default()
        }
        async fn record_integrity(
            &self,
            req: crate::proto::platform::RecordIntegrityRequest,
        ) -> crate::proto::platform::RecordIntegrityResponse {
            self.stores.record(req)
        }
        async fn verify_integrity(
            &self,
            req: crate::proto::platform::VerifyIntegrityRequest,
        ) -> crate::proto::platform::VerifyIntegrityResponse {
            self.stores.verify(req)
        }
    }

    /// Answers with a fixed caller, or fails; counts calls.
    #[derive(Debug, Default)]
    struct FakeSts {
        caller: parking_lot::Mutex<Option<crate::caller_identity::Caller>>,
        target: parking_lot::Mutex<Option<crate::caller_identity::StsTarget>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl FakeSts {
        fn answer(&self, account: Option<&str>) {
            *self.caller.lock() = account.map(caller);
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl crate::caller_identity::Identify for FakeSts {
        async fn identify(
            &self,
            _credentials: &crate::client::AssumeRoleResponse,
            target: &crate::caller_identity::StsTarget,
        ) -> Result<crate::caller_identity::Caller, String> {
            *self.target.lock() = Some(target.clone());
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.caller
                .lock()
                .clone()
                .ok_or_else(|| "connection refused".to_owned())
        }
    }

    fn caller(account: &str) -> crate::caller_identity::Caller {
        crate::caller_identity::Caller::new(
            account.to_owned(),
            format!("arn:aws:sts::{account}:assumed-role/Admin/alice"),
            "AROAEXAMPLE:alice".to_owned(),
        )
    }

    /// Reports a fixed session and ancestry for every peer.
    #[derive(Debug, Default)]
    struct FakeProcess {
        session: parking_lot::Mutex<Option<crate::platform::SessionIdentity>>,
        ancestry: parking_lot::Mutex<Vec<crate::platform::Ancestor>>,
        ended: parking_lot::Mutex<Vec<crate::platform::SessionIdentity>>,
    }

    impl crate::platform::ProcessPlatform for FakeProcess {
        fn inspect_peer(
            &self,
            _stream: &tokio::net::UnixStream,
        ) -> crate::Result<crate::platform::PeerIdentity> {
            unimplemented!()
        }
        fn verify_agent(
            &self,
            _stream: &std::os::unix::net::UnixStream,
        ) -> crate::Result<crate::platform::AgentIdentity> {
            unimplemented!()
        }
        fn peer_verification(&self) -> crate::proto::platform::PeerVerification {
            crate::proto::platform::PeerVerification::Setgid
        }
        fn notes(&self) -> Vec<String> {
            vec![]
        }
        fn verify_parent(&self, _fd: std::os::fd::BorrowedFd<'_>) -> crate::Result<u32> {
            unimplemented!()
        }
        fn session_identity(
            &self,
            _peer: &crate::platform::PeerIdentity,
        ) -> Option<crate::platform::SessionIdentity> {
            *self.session.lock()
        }
        fn controlling_tty(&self, _peer: &crate::platform::PeerIdentity) -> Option<String> {
            Some("/dev/pts/7".to_owned())
        }
        fn ancestry(
            &self,
            _pid: u32,
            _start_time: u64,
            _uid: u32,
        ) -> Vec<crate::platform::Ancestor> {
            self.ancestry.lock().clone()
        }
        fn session_alive(&self, session: &crate::platform::SessionIdentity) -> bool {
            !self.ended.lock().contains(session)
        }
    }

    struct Fixture {
        authorizer: Authorizer,
        services: std::sync::Arc<MockServices>,
        sts: std::sync::Arc<FakeSts>,
        clock: std::sync::Arc<TestClock>,
        pidfd: std::sync::Arc<std::os::fd::OwnedFd>,
        process: &'static FakeProcess,
    }

    const TTY: crate::platform::SessionIdentity = crate::platform::SessionIdentity::Tty {
        sid: 4242,
        leader_start_time: 7,
    };

    fn fixture_with(
        engine: crate::policy::Engine,
        services: std::sync::Arc<MockServices>,
    ) -> Fixture {
        fixture_with_policy(
            crate::policy::files::PolicyFiles::fixed(crate::policy::files::Effective::with_engine(
                engine,
            )),
            services,
        )
    }

    fn fixture_with_policy(
        policy: crate::policy::files::PolicyFiles,
        services: std::sync::Arc<MockServices>,
    ) -> Fixture {
        let clock = std::sync::Arc::new(TestClock::default());
        clock.advance(1_000_000);
        // Any live process will do; leases only check that it is alive.
        #[cfg(target_os = "linux")]
        let pidfd = crate::platform::process::linux::peer::pidfd_open(std::process::id()).unwrap();
        #[cfg(not(target_os = "linux"))]
        let pidfd: std::os::fd::OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        let pidfd = std::sync::Arc::new(pidfd);
        let sts = std::sync::Arc::new(FakeSts::default());
        sts.answer(Some("123456789012"));
        let process: &'static FakeProcess = Box::leak(Box::default());
        Fixture {
            authorizer: Authorizer::with_clock(
                policy,
                services.clone(),
                sts.clone(),
                process,
                true,
                clock.clone(),
            ),
            services,
            sts,
            clock,
            pidfd,
            process,
        }
    }

    fn fixture(services: std::sync::Arc<MockServices>) -> Fixture {
        fixture_with(crate::policy::Engine::builtin(true).unwrap(), services)
    }

    fn server() -> crate::config::Server {
        serde_json::from_value(serde_json::json!({
            "id": "contoso",
            "url": "https://contoso.awsapps.com/start",
        }))
        .unwrap()
    }

    fn rolespec(role: &str) -> crate::proto::Rolespec {
        crate::proto::Rolespec {
            role: role.to_owned(),
            assume_role: None,
        }
    }

    fn exec_context(command: &str, prefetch: bool) -> crate::proto::ClientContext {
        crate::proto::ClientContext {
            intent: Some(crate::proto::client_context::Intent::Exec(
                crate::proto::ExecIntent {
                    command: command.split(' ').map(|s| s.as_bytes().to_vec()).collect(),
                    mode: "ecs".to_owned(),
                    prefetch,
                },
            )),
            cwd: b"/home/alice".to_vec(),
            auto_config_path: vec![],
            env_names: vec![],
        }
    }

    impl Fixture {
        fn effective(&self) -> std::sync::Arc<crate::policy::files::Effective> {
            self.authorizer
                .shared
                .policy
                .last()
                .expect("a fixed policy")
                .effective
                .clone()
        }

        fn pending(
            &self,
            pid: u32,
            session: Option<crate::platform::SessionIdentity>,
            role: &str,
            context: Option<crate::proto::ClientContext>,
        ) -> Pending {
            let server = server();
            let rs = rolespec(role);
            let user_config = crate::config::UserConfig::default();
            let req = Request {
                peer: None,
                server: &server,
                server_digest: [0; 32],
                user_config: &user_config,
                rolespec: &rs,
                client_context: context.as_ref(),
            };
            let mut p = Pending::new(
                &req,
                1000,
                session,
                None,
                true,
                crate::tool_detection::Detection::default(),
                self.effective(),
            );
            p.pid = pid;
            p.start_time = 1;
            p.pidfd = Some(self.pidfd.clone());
            p
        }

        /// A request from a peer, with its tool labels detected through the fake process platform.
        fn peer_pending(
            &self,
            pid: u32,
            role: &str,
            context: Option<crate::proto::ClientContext>,
        ) -> Pending {
            let server = server();
            let rs = rolespec(role);
            let user_config = crate::config::UserConfig::default();
            let peer = peer(pid);
            let req = Request {
                peer: Some(&peer),
                server: &server,
                server_digest: [0; 32],
                user_config: &user_config,
                rolespec: &rs,
                client_context: context.as_ref(),
            };
            let mut p = self.authorizer.shared.pending(&req, self.effective());
            p.pidfd = Some(self.pidfd.clone());
            p
        }

        async fn decide(&self, pending: Pending) -> Result<Authorized, Refusal> {
            self.authorizer
                .shared
                .decide(pending, crate::policy::Action::AssumeRole, None)
                .await
        }
    }

    fn peer(pid: u32) -> crate::platform::PeerIdentity {
        crate::platform::PeerIdentity {
            uid: 1000,
            gid: 973,
            real_gid: Some(1000),
            pid,
            pidfd: None,
            start_time: 1,
            exe: Some("/usr/bin/mairu".into()),
            trust: crate::platform::PeerTrust::Verified,
        }
    }

    fn ancestor(
        comm: &str,
        session: Option<crate::platform::SessionIdentity>,
    ) -> crate::platform::Ancestor {
        crate::platform::Ancestor {
            pid: 100,
            comm: Some(comm.to_owned()),
            exe: None,
            argv: vec![comm.into()],
            session,
        }
    }

    fn with_env(
        mut context: crate::proto::ClientContext,
        names: &[&str],
    ) -> crate::proto::ClientContext {
        context.env_names = names.iter().map(|&n| n.to_owned()).collect();
        context
    }

    #[tokio::test]
    async fn test_ai_agent_never_reuses_session_grant() {
        let f = fixture(MockServices::answering(R::Allowed, ""));
        *f.process.session.lock() = Some(TTY);
        let human = Some(crate::proto::ClientContext {
            intent: Some(crate::proto::client_context::Intent::CredentialProcess(
                crate::proto::CredentialProcessIntent {},
            )),
            ..Default::default()
        });
        let agent = human.clone().map(|c| with_env(c, &["CLAUDECODE"]));
        f.decide(f.peer_pending(10, "r", human.clone()))
            .await
            .unwrap();
        assert_eq!(f.services.prompts(), 1);
        // The human's grant is in place, and the AI agent's request still asks.
        let pending = f.peer_pending(11, "r", agent.clone());
        assert_eq!(
            pending.facts.tools,
            ["ai-agent".to_owned()].into_iter().collect()
        );
        f.decide(pending).await.unwrap();
        assert_eq!(f.services.prompts(), 2);
        f.decide(f.peer_pending(11, "r", agent)).await.unwrap();
        assert_eq!(f.services.prompts(), 3, "every new request asks");
        f.decide(f.peer_pending(12, "r", human)).await.unwrap();
        assert_eq!(f.services.prompts(), 3, "the human keeps the grant");
    }

    #[tokio::test]
    async fn test_ai_agent_within_lease() {
        let f = fixture(MockServices::answering(R::Allowed, ""));
        *f.process.ancestry.lock() = vec![ancestor("mairu", None), ancestor("claude", None)];
        let ctx = Some(exec_context("terraform plan", false));
        let pending = f.peer_pending(10, "r", ctx.clone());
        assert_eq!(
            pending.facts.tool_matches,
            ["process:claude".to_owned()].into_iter().collect()
        );
        f.decide(pending).await.unwrap();
        f.clock.advance(3000);
        f.decide(f.peer_pending(10, "r", ctx.clone()))
            .await
            .unwrap();
        assert_eq!(f.services.prompts(), 1, "the lease covers it");
        f.clock.advance(3601);
        f.decide(f.peer_pending(10, "r", ctx)).await.unwrap();
        assert_eq!(f.services.prompts(), 2, "an idle lease asks");
    }

    #[tokio::test]
    async fn test_refusal_carries_tools() {
        let f = fixture(MockServices::answering(R::Denied, ""));
        let ctx = Some(with_env(exec_context("aws", false), &["AI_AGENT"]));
        let refusal = f
            .decide(f.peer_pending(10, "r", ctx))
            .await
            .expect_err("denied");
        assert_eq!(refusal.reason(), Reason::Denied);
        assert_eq!(refusal.tools, vec!["ai-agent"]);
    }

    #[tokio::test]
    async fn test_marks_label_descendants_until_the_session_ends() {
        let f = fixture(MockServices::answering(R::Allowed, ""));
        f.authorizer.mark_tools(TTY, &["ai-agent".to_owned()]);
        // A setsid child with no tty whose ancestry passes through the marked pane.
        *f.process.ancestry.lock() = vec![ancestor("aws", None), ancestor("zsh", Some(TTY))];
        let pending = f.peer_pending(10, "r", None);
        assert_eq!(
            pending.facts.tool_matches,
            ["mark:ai-agent".to_owned()].into_iter().collect()
        );
        // From another pane.
        let other = crate::platform::SessionIdentity::Tty {
            sid: 5000,
            leader_start_time: 7,
        };
        *f.process.ancestry.lock() = vec![ancestor("aws", None), ancestor("zsh", Some(other))];
        assert!(f.peer_pending(10, "r", None).facts.tools.is_empty());
        // The pane's leader exits: the sweep drops the mark.
        f.process.ended.lock().push(TTY);
        f.authorizer.counts();
        *f.process.ancestry.lock() = vec![ancestor("aws", None), ancestor("zsh", Some(TTY))];
        assert!(f.peer_pending(10, "r", None).facts.tools.is_empty());
    }

    #[tokio::test]
    async fn test_unmark_always_asks() {
        let f = fixture(MockServices::answering(R::Allowed, ""));
        *f.process.session.lock() = Some(TTY);
        let labels = ["ai-agent".to_owned(), "ci".to_owned()];
        f.authorizer.mark_tools(TTY, &labels);
        // A fresh grant in this session does not count.
        f.decide(f.peer_pending(10, "r", None)).await.unwrap();
        assert_eq!(f.services.prompts(), 1);
        let remaining = f
            .authorizer
            .unmark_tools(Some(&peer(10)), &labels[..1])
            .await
            .unwrap();
        assert_eq!(remaining, vec!["ci"]);
        assert_eq!(f.services.prompts(), 2);
        *f.services.answer.lock() = crate::proto::platform::AuthorizeResponse {
            result: R::Denied.into(),
            ..Default::default()
        };
        let status = f
            .authorizer
            .unmark_tools(Some(&peer(10)), &labels[1..])
            .await
            .unwrap_err();
        assert_eq!(
            crate::proto::AuthorizationError::from_status(&status)
                .unwrap()
                .reason(),
            Reason::Denied
        );
        assert_eq!(f.services.prompts(), 3);
        let (_, marks) = f.authorizer.tools_of(&peer(10), &[]);
        assert_eq!(marks, vec!["ci"], "a denied unmark keeps the mark");
        // Without a terminal session there is nothing to unmark.
        *f.process.session.lock() = None;
        let status = f
            .authorizer
            .unmark_tools(Some(&peer(10)), &labels[1..])
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(f.services.prompts(), 3);
    }

    fn reason(r: Result<Authorized, Refusal>) -> Reason {
        r.expect_err("refused").reason()
    }

    #[tokio::test]
    async fn test_grant_recorded_and_reused() {
        let f = fixture(MockServices::answering(R::Allowed, ""));
        let ctx = Some(exec_context("aws s3 ls", false));
        f.decide(f.pending(10, Some(TTY), "123456789012/Admin", ctx.clone()))
            .await
            .unwrap();
        assert_eq!(f.services.prompts(), 1);
        assert_eq!(f.authorizer.counts(), (1, 1));
        // Another process in the same terminal session reuses the grant.
        f.clock.advance(200);
        f.decide(f.pending(11, Some(TTY), "123456789012/Admin", ctx.clone()))
            .await
            .unwrap();
        assert_eq!(f.services.prompts(), 1);
        // The use touched the grant, so idle restarts.
        f.clock.advance(200);
        f.decide(f.pending(12, Some(TTY), "123456789012/Admin", ctx.clone()))
            .await
            .unwrap();
        assert_eq!(f.services.prompts(), 1);
        // Another role, or another session, asks.
        f.decide(f.pending(12, Some(TTY), "123456789012/ReadOnly", ctx.clone()))
            .await
            .unwrap();
        assert_eq!(f.services.prompts(), 2);
        let other = crate::platform::SessionIdentity::Tty {
            sid: 5000,
            leader_start_time: 7,
        };
        f.decide(f.pending(13, Some(other), "123456789012/Admin", ctx))
            .await
            .unwrap();
        assert_eq!(f.services.prompts(), 3);
    }

    #[tokio::test]
    async fn test_grant_idle_and_hard_cap() {
        let f = fixture(MockServices::answering(R::Allowed, ""));
        let ctx = Some(crate::proto::ClientContext {
            intent: Some(crate::proto::client_context::Intent::CredentialProcess(
                crate::proto::CredentialProcessIntent {},
            )),
            ..Default::default()
        });
        let p = || f.pending(10, Some(TTY), "r", ctx.clone());
        f.decide(p()).await.unwrap();
        f.clock.advance(301);
        f.decide(p()).await.unwrap();
        assert_eq!(f.services.prompts(), 2, "idle beyond 5 min asks");
        for _ in 0..(43200 / 290) {
            f.clock.advance(290);
            f.decide(p()).await.unwrap();
        }
        assert_eq!(f.services.prompts(), 2);
        f.clock.advance(290);
        f.decide(p()).await.unwrap();
        assert_eq!(f.services.prompts(), 3, "12 h cap asks again");
    }

    #[tokio::test]
    async fn test_no_session_never_remembers() {
        let f = fixture(MockServices::answering(R::Allowed, ""));
        f.decide(f.pending(10, None, "r", None)).await.unwrap();
        f.decide(f.pending(10, None, "r", None)).await.unwrap();
        assert_eq!(f.services.prompts(), 2);
        assert_eq!(f.authorizer.counts(), (0, 0));
    }

    #[tokio::test]
    async fn test_lease_idle_counts_from_demand_expiry() {
        let f = fixture(MockServices::answering(R::Allowed, ""));
        let demand = || f.pending(10, None, "r", Some(exec_context("sleep 1d", false)));
        let prefetch = || f.pending(10, None, "r", Some(exec_context("sleep 1d", true)));
        let authorized = f.decide(demand()).await.unwrap();
        assert_eq!(f.authorizer.counts(), (0, 1));
        authorized.vended(Some(chrono::Utc::now() + chrono::TimeDelta::seconds(3600)));
        // Pre-fetches within the credentials' lifetime and an hour after are covered, and move nothing.
        f.clock.advance(3600 + 3600);
        let a = f.decide(prefetch()).await.unwrap();
        a.vended(Some(chrono::Utc::now() + chrono::TimeDelta::seconds(3600)));
        f.clock.advance(1);
        assert_eq!(
            reason(f.decide(prefetch()).await),
            Reason::PresenceRequired,
            "a pre-fetch never kept the lease alive"
        );
        assert_eq!(f.services.prompts(), 1, "a pre-fetch never prompts");
        // A demand request asks again.
        f.decide(demand()).await.unwrap();
        assert_eq!(f.services.prompts(), 2);
    }

    #[tokio::test]
    async fn test_lease_kept_by_demand() {
        let f = fixture(MockServices::answering(R::Allowed, ""));
        let demand = || f.pending(10, None, "r", Some(exec_context("sleep 1d", false)));
        f.decide(demand()).await.unwrap();
        for _ in 0..30 {
            f.clock.advance(3000);
            let a = f.decide(demand()).await.unwrap();
            a.vended(Some(chrono::Utc::now() + chrono::TimeDelta::seconds(900)));
        }
        assert_eq!(f.services.prompts(), 1);
    }

    #[tokio::test]
    async fn test_lease_needs_live_process() {
        let f = fixture(MockServices::answering(R::Allowed, ""));
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        #[cfg(target_os = "linux")]
        {
            let pidfd = std::sync::Arc::new(
                crate::platform::process::linux::peer::pidfd_open(child.id()).unwrap(),
            );
            let mut p = f.pending(10, None, "r", Some(exec_context("x", false)));
            p.pidfd = Some(pidfd.clone());
            f.decide(p).await.unwrap();
            assert_eq!(f.authorizer.counts(), (0, 1));
            child.kill().unwrap();
            child.wait().unwrap();
            assert_eq!(f.authorizer.counts(), (0, 0));
            let mut p = f.pending(10, None, "r", Some(exec_context("x", true)));
            p.pidfd = Some(pidfd);
            assert_eq!(reason(f.decide(p).await), Reason::PresenceRequired);
        }
        #[cfg(not(target_os = "linux"))]
        {
            child.kill().unwrap();
            child.wait().unwrap();
        }
    }

    #[tokio::test]
    async fn test_platform_results() {
        for (result, why, expected) in [
            (R::Denied, "", Reason::Denied),
            (R::Cancelled, "timeout", Reason::Denied),
            (
                R::Unavailable,
                REASON_NO_AUTHENTICATION_AGENT,
                Reason::NoAuthenticationAgent,
            ),
            (R::Unavailable, "polkit-unavailable", Reason::Unavailable),
            (R::Unavailable, "untrusted-authority", Reason::Unavailable),
        ] {
            let f = fixture(MockServices::answering(result, why));
            let r = f.decide(f.pending(10, Some(TTY), "r", None)).await;
            assert_eq!(reason(r), expected, "{result:?} {why}");
            assert_eq!(f.authorizer.counts(), (0, 0));
        }
    }

    #[tokio::test]
    async fn test_no_facility_is_unavailable() {
        let services = std::sync::Arc::new(MockServices {
            facility: crate::proto::platform::AuthorizationFacility::None,
            ..std::sync::Arc::try_unwrap(MockServices::answering(R::Allowed, "")).unwrap()
        });
        let f = fixture(services);
        let err = f
            .decide(f.pending(10, Some(TTY), "r", None))
            .await
            .unwrap_err();
        assert_eq!(err.reason(), Reason::Unavailable);
        assert!(err.detail.contains("platform"), "{}", err.detail);
        assert_eq!(f.services.prompts(), 0);
    }

    #[tokio::test]
    async fn test_unhardened_policy_never_asks() {
        let f = fixture_with(
            crate::policy::Engine::builtin(false).unwrap(),
            MockServices::answering(R::Denied, ""),
        );
        f.decide(f.pending(10, Some(TTY), "r", None)).await.unwrap();
        assert_eq!(f.services.prompts(), 0);
    }

    #[tokio::test]
    async fn test_forbid_and_not_permitted() {
        let f = fixture_with(
            crate::policy::Engine::new(
                r#"
                @id("allow") permit (principal, action, resource) when { context.presence.verified };
                @id("no-prod") forbid (principal, action, resource) when { resource.name == "prod" };
                "#,
            )
            .unwrap(),
            MockServices::answering(R::Allowed, ""),
        );
        let err = f
            .decide(f.pending(10, Some(TTY), "prod", None))
            .await
            .unwrap_err();
        assert_eq!(err.reason(), Reason::Forbidden);
        assert_eq!(err.policy_ids, vec!["no-prod"]);
        assert_eq!(f.services.prompts(), 0);

        let f = fixture_with(
            crate::policy::Engine::new(
                r#"@id("nothing") permit (principal, action, resource) when { resource.name == "x" };"#,
            )
            .unwrap(),
            MockServices::answering(R::Allowed, ""),
        );
        assert_eq!(
            reason(f.decide(f.pending(10, Some(TTY), "y", None)).await),
            Reason::NotPermitted
        );
    }

    fn unapproved_fixture(
        hardened: bool,
        policy: &str,
        settings: Option<serde_json::Value>,
    ) -> Fixture {
        use crate::policy::files::Content;
        let effective = crate::policy::files::Effective::build(
            hardened,
            &Content::Text(policy.to_owned()),
            &settings.map_or(Content::Absent, |s| Content::Text(s.to_string())),
        )
        .unwrap();
        fixture_with_policy(
            crate::policy::files::PolicyFiles::fixed(effective),
            MockServices::answering(R::Allowed, ""),
        )
    }

    const USER_POLICY: &str = r#"
        @id("allow-all") permit (principal, action, resource);
        @id("no-prod") forbid (principal, action, resource) when { resource.name == "prod" };
    "#;

    #[tokio::test]
    async fn test_unapproved_forbid_applies_and_permit_is_ignored() {
        let f = unapproved_fixture(true, USER_POLICY, None);
        let err = f
            .decide(f.pending(10, Some(TTY), "prod", None))
            .await
            .unwrap_err();
        assert_eq!(err.reason(), Reason::Forbidden);
        assert_eq!(err.policy_ids, vec!["no-prod"]);
        assert_eq!(f.services.prompts(), 0);
        f.decide(f.pending(10, Some(TTY), "dev", None))
            .await
            .unwrap();
        assert_eq!(f.services.prompts(), 1, "allow-all is ignored");
    }

    #[tokio::test]
    async fn test_unapproved_forbid_unhardened() {
        let f = unapproved_fixture(false, USER_POLICY, None);
        assert_eq!(
            reason(f.decide(f.pending(10, Some(TTY), "prod", None)).await),
            Reason::Forbidden
        );
        f.decide(f.pending(10, Some(TTY), "dev", None))
            .await
            .unwrap();
        assert_eq!(f.services.prompts(), 0);
    }

    #[tokio::test]
    async fn test_unapproved_grant_retention() {
        let f = unapproved_fixture(
            true,
            "",
            Some(serde_json::json!({"version": 1, "grant_retention_secs": 600})),
        );
        let p = || f.pending(10, Some(TTY), "r", None);
        f.decide(p()).await.unwrap();
        f.clock.advance(250);
        f.decide(p()).await.unwrap();
        f.clock.advance(250);
        f.decide(p()).await.unwrap();
        assert_eq!(f.services.prompts(), 1);
        f.clock.advance(250);
        f.decide(p()).await.unwrap();
        assert_eq!(f.services.prompts(), 2, "the grant is dropped after 600 s");
    }

    #[tokio::test]
    async fn test_unapproved_tool_detection() {
        let f = unapproved_fixture(
            true,
            "",
            Some(serde_json::json!({
                "version": 1,
                "tool_detection": {
                    "ai-agent": {"env_names": ["MY_AGENT"]},
                    "ci": {"env_names": ["CI"]},
                },
            })),
        );
        let p = f.peer_pending(
            10,
            "r",
            Some(with_env(exec_context("aws", false), &["MY_AGENT", "CI"])),
        );
        assert_eq!(
            p.detection.tools.iter().collect::<Vec<_>>(),
            vec!["ai-agent", "ci"]
        );
    }

    #[tokio::test]
    async fn test_evaluation_error_denies_remembered_grant() {
        // Errors once a grant exists (age > 0); the error must not let the grant through the forbid.
        let f = fixture_with(
            crate::policy::Engine::new(
                r#"
                @id("allow") permit (principal, action, resource) when { context.presence.verified };
                @id("overflow") forbid (principal, action, resource)
                when { context.presence.age + 9223372036854775807 < 0 };
                "#,
            )
            .unwrap(),
            MockServices::answering(R::Allowed, ""),
        );
        f.decide(f.pending(10, Some(TTY), "r", None)).await.unwrap();
        f.clock.advance(10);
        f.decide(f.pending(10, Some(TTY), "r", None)).await.unwrap();
        assert_eq!(
            f.services.prompts(),
            2,
            "the erroring grant candidate was not used"
        );
    }

    #[tokio::test]
    async fn test_singleflight() {
        let services = std::sync::Arc::new(MockServices {
            delay: std::time::Duration::from_millis(200),
            ..std::sync::Arc::try_unwrap(MockServices::answering(R::Allowed, "")).unwrap()
        });
        let f = fixture(services);
        let same = || f.pending(10, None, "r", Some(exec_context("aws s3 ls", false)));
        let (a, b) = tokio::join!(f.decide(same()), f.decide(same()));
        a.unwrap();
        b.unwrap();
        assert_eq!(f.services.prompts(), 1, "identical requests share a prompt");

        let other_command = f.pending(20, None, "r", Some(exec_context("aws s3 rm x", false)));
        let other_command2 = f.pending(20, None, "r", Some(exec_context("aws s3 ls", false)));
        let other_peer = f.pending(21, None, "r", Some(exec_context("aws s3 ls", false)));
        let (a, b, c) = tokio::join!(
            f.decide(other_command),
            f.decide(other_command2),
            f.decide(other_peer)
        );
        a.unwrap();
        b.unwrap();
        c.unwrap();
        assert_eq!(f.services.prompts(), 4);
    }

    #[tokio::test]
    async fn test_revoke() {
        let f = fixture(MockServices::answering(R::Allowed, ""));
        let other = crate::platform::SessionIdentity::Parent {
            ppid: 777,
            start_time: 1,
        };
        f.decide(f.pending(10, Some(TTY), "a", Some(exec_context("x", false))))
            .await
            .unwrap();
        f.decide(f.pending(11, Some(other), "a", Some(exec_context("x", false))))
            .await
            .unwrap();
        assert_eq!(f.authorizer.counts(), (2, 2));
        assert_eq!(f.authorizer.revoke(Some(Some(TTY)), false), (1, 0));
        assert_eq!(f.authorizer.revoke(Some(Some(TTY)), true), (0, 1));
        assert_eq!(f.authorizer.revoke(Some(None), false), (0, 0));
        assert_eq!(f.authorizer.revoke(None, false), (1, 0));
        assert_eq!(f.authorizer.revoke(None, true), (0, 1));
        assert_eq!(f.authorizer.counts(), (0, 0));
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

    /// The agent's `assume_role` after the config lookups: gate 1, then obtain with a counted fetch.
    struct Flow {
        cache: crate::credential_cache::CredentialCache,
        fetches: std::sync::atomic::AtomicUsize,
    }

    impl Flow {
        fn new() -> Self {
            Self {
                cache: crate::credential_cache::CredentialCache::new(),
                fetches: Default::default(),
            }
        }

        fn fetches(&self) -> usize {
            self.fetches.load(std::sync::atomic::Ordering::SeqCst)
        }

        async fn request(
            &self,
            f: &Fixture,
            pending: Pending,
            cacheable: bool,
        ) -> Result<Obtained, crate::proto::AuthorizationError> {
            let rs = rolespec(&pending.facts.role);
            let gate1 = f.authorizer.gate1(pending).await?;
            f.authorizer
                .obtain(gate1, &self.cache, &rs, cacheable, || async {
                    self.fetches
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(credentials())
                })
                .await
                .map_err(|status| crate::proto::AuthorizationError::from_status(&status).unwrap())
        }
    }

    const HUMAN_AND_PROD: &str = r#"
        @id("human")
        permit (principal, action == Mairu::Action::"AssumeRole", resource)
        when { context.presence.verified };
        @id("prod-by-real-account")
        forbid (principal, action == Mairu::Action::"UseCredentials", resource in Mairu::Account::"999999999999")
        unless { context.presence.verified && context.presence.scope == "request" };
    "#;

    #[tokio::test]
    async fn test_gate2_account_mismatch() {
        let f = fixture(MockServices::answering(R::Allowed, ""));
        f.sts.answer(Some("999999999999"));
        let flow = Flow::new();
        let err = flow
            .request(
                &f,
                f.pending(10, Some(TTY), "123456789012/Admin", None),
                true,
            )
            .await
            .unwrap_err();
        assert_eq!(err.reason(), Reason::Forbidden);
        assert_eq!(
            err.policy_ids,
            vec![crate::policy::POLICY_CALLER_ACCOUNT_MISMATCH]
        );
        assert_eq!(err.gate, crate::proto::GATE_USE_CREDENTIALS);
        assert_eq!(
            err.caller_arn,
            "arn:aws:sts::999999999999:assumed-role/Admin/alice"
        );
        assert!(
            err.detail.contains("credentials belong to 999999999999")
                && err.detail.contains("(123456789012)"),
            "{}",
            err.detail
        );
        assert!(
            err.user_message()
                .starts_with("refused at use-credentials: ")
        );
        assert_eq!(f.services.prompts(), 1, "only gate 1 asked");
        assert!(flow.cache.get(&rolespec("123456789012/Admin")).is_none());
        // The declared account matches.
        f.sts.answer(Some("123456789012"));
        let obtained = flow
            .request(
                &f,
                f.pending(10, Some(TTY), "123456789012/Admin", None),
                true,
            )
            .await
            .unwrap();
        assert_eq!(obtained.source, Source::Fetched);
    }

    #[tokio::test]
    async fn test_gate2_prod_by_real_account() {
        let f = fixture_with(
            crate::policy::Engine::new(HUMAN_AND_PROD).unwrap(),
            MockServices::answering(R::Allowed, ""),
        );
        f.sts.answer(Some("999999999999"));
        let flow = Flow::new();
        // Gate 1 asked for this very request, which also satisfies gate 2.
        let obtained = flow
            .request(&f, f.pending(10, Some(TTY), "admin", None), true)
            .await
            .unwrap();
        assert_eq!(obtained.source, Source::Fetched);
        assert_eq!(f.services.prompts(), 1);
        assert_eq!(f.sts.calls(), 1);
        // Another process in the session: the grant passes gate 1, but production asks again at gate 2, from the
        // cache with the cached caller and no STS call.
        let obtained = flow
            .request(&f, f.pending(11, Some(TTY), "admin", None), true)
            .await
            .unwrap();
        assert_eq!(obtained.source, Source::Cache);
        assert_eq!(f.services.prompts(), 2);
        assert_eq!(f.sts.calls(), 1);
        assert_eq!(flow.fetches(), 1);
        // Another account behind the same opaque name is not production.
        let flow = Flow::new();
        f.sts.answer(Some("111111111111"));
        flow.request(&f, f.pending(12, Some(TTY), "admin", None), true)
            .await
            .unwrap();
        assert_eq!(f.services.prompts(), 2);
    }

    #[tokio::test]
    async fn test_gate2_prefetch_never_asks() {
        let f = fixture_with(
            crate::policy::Engine::new(HUMAN_AND_PROD).unwrap(),
            MockServices::answering(R::Allowed, ""),
        );
        f.sts.answer(Some("999999999999"));
        let flow = Flow::new();
        let demand = || f.pending(10, None, "admin", Some(exec_context("sleep 1d", false)));
        let prefetch = || f.pending(10, None, "admin", Some(exec_context("sleep 1d", true)));
        flow.request(&f, demand(), false).await.unwrap();
        assert_eq!(f.services.prompts(), 1);
        let err = flow.request(&f, prefetch(), false).await.unwrap_err();
        assert_eq!(err.reason(), Reason::PresenceRequired);
        assert_eq!(err.gate, crate::proto::GATE_USE_CREDENTIALS);
        assert_eq!(f.services.prompts(), 1, "nobody was asked");
    }

    #[tokio::test]
    async fn test_gate2_sts_failure() {
        let f = fixture(MockServices::answering(R::Allowed, ""));
        f.sts.answer(None);
        let flow = Flow::new();
        let p = || f.pending(10, Some(TTY), "123456789012/Admin", None);
        let err = flow.request(&f, p(), true).await.unwrap_err();
        assert_eq!(err.reason(), Reason::Unavailable);
        assert_eq!(err.gate, crate::proto::GATE_USE_CREDENTIALS);
        assert!(err.detail.contains("connection refused"), "{}", err.detail);
        assert!(flow.cache.get(&rolespec("123456789012/Admin")).is_none());
        let err = flow.request(&f, p(), true).await.unwrap_err();
        assert_eq!(err.reason(), Reason::Unavailable);
        assert_eq!((flow.fetches(), f.sts.calls()), (2, 2));
        f.sts.answer(Some("123456789012"));
        flow.request(&f, p(), true).await.unwrap();
        flow.request(&f, p(), true).await.unwrap();
        assert_eq!((flow.fetches(), f.sts.calls()), (3, 3));
        assert!(
            flow.cache
                .get(&rolespec("123456789012/Admin"))
                .unwrap()
                .caller
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_gate2_cached_entry_without_caller() {
        let f = fixture(MockServices::answering(R::Allowed, ""));
        let flow = Flow::new();
        // A chain's first hop is cached before anyone asked who it belongs to.
        flow.cache.store(
            rolespec("123456789012/Admin"),
            std::sync::Arc::new(credentials()),
            None,
        );
        let p = || f.pending(10, Some(TTY), "123456789012/Admin", None);
        assert_eq!(
            flow.request(&f, p(), true).await.unwrap().source,
            Source::Cache
        );
        assert_eq!(
            flow.request(&f, p(), true).await.unwrap().source,
            Source::Cache
        );
        assert_eq!((flow.fetches(), f.sts.calls()), (0, 1));
    }

    #[tokio::test]
    async fn test_gate2_retry_uses_held_credentials() {
        let f = fixture_with(
            crate::policy::Engine::new(HUMAN_AND_PROD).unwrap(),
            MockServices::answering(R::Allowed, ""),
        );
        f.sts.answer(Some("999999999999"));
        let flow = Flow::new();
        flow.request(&f, f.pending(10, Some(TTY), "admin", None), false)
            .await
            .unwrap();
        let no_agent = crate::proto::platform::AuthorizeResponse::unavailable(
            REASON_NO_AUTHENTICATION_AGENT,
            "",
        );
        *f.services.answer.lock() = no_agent.clone();
        let p = || f.pending(11, Some(TTY), "admin", None);
        let err = flow.request(&f, p(), false).await.unwrap_err();
        assert_eq!(err.reason(), Reason::NoAuthenticationAgent);
        assert_eq!(err.gate, crate::proto::GATE_USE_CREDENTIALS);
        assert_eq!((flow.fetches(), f.sts.calls()), (2, 2));
        // The retry, once an agent is registered, fetches nothing again.
        *f.services.answer.lock() = MockServices::answering(R::Allowed, "")
            .answer
            .lock()
            .clone();
        let obtained = flow.request(&f, p(), false).await.unwrap();
        assert_eq!(obtained.source, Source::Held);
        assert_eq!((flow.fetches(), f.sts.calls()), (2, 2));
        assert_eq!(f.services.prompts(), 3);
        // Taken by the retry.
        flow.request(&f, p(), false).await.unwrap();
        assert_eq!(flow.fetches(), 3);

        // Held for 60 s at most, and dropped by a revoke.
        *f.services.answer.lock() = no_agent;
        flow.request(&f, p(), false).await.unwrap_err();
        f.clock.advance(61);
        flow.request(&f, p(), false).await.unwrap_err();
        assert_eq!(flow.fetches(), 5, "an expired hold is fetched again");
        f.authorizer.revoke(Some(Some(TTY)), false);
        *f.services.answer.lock() = MockServices::answering(R::Allowed, "")
            .answer
            .lock()
            .clone();
        let obtained = flow.request(&f, p(), false).await.unwrap();
        assert_eq!(
            obtained.source,
            Source::Fetched,
            "a revoke drops held credentials"
        );
    }

    #[tokio::test]
    async fn test_gate2_skipped_unhardened() {
        let services = MockServices::answering(R::Denied, "");
        let clock = std::sync::Arc::new(TestClock::default());
        let sts = std::sync::Arc::new(FakeSts::default());
        let process: &'static FakeProcess = Box::leak(Box::default());
        let authorizer = Authorizer::with_clock(
            crate::policy::files::PolicyFiles::fixed(
                crate::policy::files::Effective::builtin(false).unwrap(),
            ),
            services.clone(),
            sts.clone(),
            process,
            false,
            clock,
        );
        let f = Fixture {
            authorizer,
            services,
            sts,
            clock: Default::default(),
            pidfd: fixture(MockServices::answering(R::Allowed, "")).pidfd,
            process,
        };
        let flow = Flow::new();
        let obtained = flow
            .request(
                &f,
                f.pending(10, Some(TTY), "123456789012/Admin", None),
                true,
            )
            .await
            .unwrap();
        assert!(obtained.caller.is_none());
        assert_eq!((f.sts.calls(), f.services.prompts()), (0, 0));
        let cached = flow.cache.get(&rolespec("123456789012/Admin")).unwrap();
        assert!(cached.caller.is_none());
    }

    #[test]
    fn test_gate2_prompt_details() {
        let f = fixture(MockServices::answering(R::Allowed, ""));
        let p = f.pending(10, Some(TTY), "admin", None);
        assert!(!p.authorize_request(None).details.contains_key("caller"));
        let c = caller("999999999999");
        let req = p.authorize_request(Some(&c));
        assert_eq!(
            req.details.get("caller").map(String::as_str),
            Some("999999999999 arn:aws:sts::999999999999:assumed-role/Admin/alice")
        );
        assert!(
            req.message.contains("999999999999 assumed-role/Admin"),
            "{}",
            req.message
        );
    }

    #[test]
    fn test_digest_covers_command() {
        let server = "contoso";
        let rs = rolespec("r");
        let a = request_digest(server, &rs, &exec_context("aws s3 ls", false));
        let b = request_digest(server, &rs, &exec_context("aws s3 rm", false));
        assert_ne!(a, b);
        assert_eq!(
            a,
            request_digest(server, &rs, &exec_context("aws s3 ls", false))
        );
    }

    #[test]
    fn test_shell_join() {
        assert_eq!(
            shell_join(&[
                b"aws".to_vec(),
                b"s3".to_vec(),
                b"it's here".to_vec(),
                vec![]
            ]),
            r#"aws s3 'it'\''s here' ''"#
        );
        assert_eq!(shell_join(&[vec![0xff, b'a']]), "'\u{fffd}a'");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("abc", 2), "ab");
        assert_eq!(truncate("aé", 2), "a");
        assert_eq!(truncate("abc", 5), "abc");
    }

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("mairu-test-authz-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const READONLY_FREE: &str = r#"@id("readonly-free") permit (principal, action == Mairu::Action::"AssumeRole", resource == Mairu::Role::"contoso:123456789012/ReadOnly");"#;

    /// A fixture reading `dir`, with the stores of `services`.
    async fn dir_fixture(dir: &TempDir, services: std::sync::Arc<MockServices>) -> Fixture {
        let f = fixture_with_policy(
            crate::policy::files::PolicyFiles::new(
                dir.0.clone(),
                true,
                crate::policy::files::test_support::stores(services.clone()),
            ),
            services,
        );
        f.authorizer.policy().await.unwrap();
        f
    }

    impl Fixture {
        async fn approve(
            &self,
            dir: &TempDir,
            peer: &crate::platform::PeerIdentity,
            servers: &[(&str, crate::policy::integrity_state::Digest)],
        ) -> Result<crate::proto::ApprovePolicyResponse, tonic::Status> {
            let (policy, settings) = crate::policy::files::PolicyFiles::read_contents(&dir.0);
            let digest = crate::policy::integrity_state::policy_digest(&policy, &settings);
            let expected: std::collections::HashMap<String, Vec<u8>> = servers
                .iter()
                .map(|(id, d)| (id.to_string(), d.to_vec()))
                .collect();
            self.authorizer
                .approve_policy(Approval {
                    peer: Some(peer),
                    expected_digest: &digest,
                    expected_server_digests: &expected,
                    server_digests: servers.iter().map(|(id, d)| (id.to_string(), *d)).collect(),
                })
                .await
        }

        async fn assume_role(
            &self,
            role: &str,
            server_digest: crate::policy::integrity_state::Digest,
        ) -> Result<Authorized, Refusal> {
            let server = server();
            let rs = rolespec(role);
            let user_config = crate::config::UserConfig::default();
            let peer = peer(10);
            self.authorizer
                .authorize_assume_role(Request {
                    peer: Some(&peer),
                    server: &server,
                    server_digest,
                    user_config: &user_config,
                    rolespec: &rs,
                    client_context: None,
                })
                .await
        }
    }

    #[tokio::test]
    async fn test_approve_policy() {
        use crate::policy::settings::PolicyState;
        let dir = TempDir::new("approve");
        let policy_path = crate::policy::files::PolicyFiles::policy_path(&dir.0);
        std::fs::write(&policy_path, READONLY_FREE).unwrap();
        let services = MockServices::answering(R::Allowed, "");
        let f = dir_fixture(&dir, services.clone()).await;
        assert_eq!(
            f.authorizer.policy().await.unwrap().state,
            PolicyState::Unapproved
        );
        let peer = peer(10);

        // Approve race: the files changed after the client read them.
        let wrong: std::collections::HashMap<String, Vec<u8>> = Default::default();
        let status = f
            .authorizer
            .approve_policy(Approval {
                peer: Some(&peer),
                expected_digest: &[0; 32],
                expected_server_digests: &wrong,
                server_digests: Default::default(),
            })
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(status.message().contains("changed while approving"));
        // A server the client did not see.
        let status = f
            .approve(&dir, &peer, &[])
            .await
            .map(|_| ())
            .and(
                f.authorizer
                    .approve_policy(Approval {
                        peer: Some(&peer),
                        expected_digest: &[0; 32],
                        expected_server_digests: &wrong,
                        server_digests: [("contoso".to_owned(), [1; 32])].into(),
                    })
                    .await
                    .map(|_| ()),
            )
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(services.prompts(), 1, "only the valid request asked");

        // First approval: through the bootstrap anchor, never grants.
        let request = services.last_request.lock().clone().unwrap();
        assert_eq!(
            request.action(),
            crate::proto::platform::authorize_request::Action::ApprovePolicy
        );
        assert_eq!(request.details["tty"], "/dev/pts/7");
        assert_eq!(request.details["policy_digest"].len(), 64);
        let record = services.stores.strong.lock().record.clone().unwrap();
        assert_eq!(record.generation, 1);
        assert_eq!(record.approval.unwrap().methods, vec!["platform"]);
        assert_eq!(
            services
                .stores
                .weak
                .lock()
                .record
                .as_ref()
                .unwrap()
                .generation,
            1
        );
        let v = f.authorizer.policy().await.unwrap();
        assert_eq!(v.state, PolicyState::Approved);
        assert!(f.authorizer.counts() == (0, 0));

        // Not in the record: the server's roles get the unapproved policy, which asks.
        let prompts = services.prompts();
        f.assume_role("123456789012/ReadOnly", [1; 32])
            .await
            .unwrap();
        assert_eq!(services.prompts(), prompts + 1);
        let resp = f
            .approve(&dir, &peer, &[("contoso", [1; 32])])
            .await
            .unwrap();
        assert_eq!(resp.integrity(), crate::proto::PolicyIntegrity::Approved);
        assert_eq!(
            services
                .stores
                .strong
                .lock()
                .record
                .as_ref()
                .unwrap()
                .generation,
            2
        );
        let prompts = services.prompts();
        f.assume_role("123456789012/ReadOnly", [1; 32])
            .await
            .unwrap();
        assert_eq!(services.prompts(), prompts);

        // Hand edit: tampered, re-approval restores.
        std::fs::write(&policy_path, format!("{READONLY_FREE}\n// edited")).unwrap();
        assert_eq!(
            f.authorizer.policy().await.unwrap().state,
            PolicyState::Tampered
        );
        f.approve(&dir, &peer, &[("contoso", [1; 32])])
            .await
            .unwrap();
        assert_eq!(
            f.authorizer.policy().await.unwrap().state,
            PolicyState::Approved
        );
        assert_eq!(
            services
                .stores
                .strong
                .lock()
                .record
                .as_ref()
                .unwrap()
                .generation,
            3
        );

        // An invalid file is never approved, and nobody is asked.
        std::fs::write(&policy_path, "permit (").unwrap();
        let prompts = services.prompts();
        let status = f.approve(&dir, &peer, &[]).await.unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert_eq!(services.prompts(), prompts);

        // A denial records nothing.
        std::fs::write(&policy_path, READONLY_FREE).unwrap();
        *services.answer.lock() = crate::proto::platform::AuthorizeResponse {
            result: R::Denied.into(),
            reason: String::new(),
            detail: String::new(),
        };
        let status = f.approve(&dir, &peer, &[]).await.unwrap_err();
        assert_eq!(
            crate::proto::AuthorizationError::from_status(&status)
                .unwrap()
                .reason(),
            Reason::Denied
        );
        assert_eq!(
            services
                .stores
                .strong
                .lock()
                .record
                .as_ref()
                .unwrap()
                .generation,
            3
        );
    }

    #[tokio::test]
    async fn test_approve_without_stores() {
        let dir = TempDir::new("nostores");
        std::fs::write(
            crate::policy::files::PolicyFiles::policy_path(&dir.0),
            READONLY_FREE,
        )
        .unwrap();
        let services = MockServices::answering(R::Allowed, "");
        services.stores.strong.lock().available = false;
        services.stores.weak.lock().available = false;
        let f = dir_fixture(&dir, services.clone()).await;
        let status = f.approve(&dir, &peer(10), &[]).await.unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(
            status.message().contains("no integrity store"),
            "{status:?}"
        );
    }

    #[tokio::test]
    async fn test_approve_uses_the_anchor() {
        let dir = TempDir::new("anchor");
        std::fs::write(
            crate::policy::files::PolicyFiles::policy_path(&dir.0),
            READONLY_FREE,
        )
        .unwrap();
        let services = MockServices::answering(R::Allowed, "");
        // The last approval anchored a method this mairu cannot use: the files' own methods do not count.
        let mut record = crate::policy::files::test_support::record_of(&dir.0, 4, &[]);
        record.digest = vec![0; 32];
        record.approval = Some(crate::proto::platform::ApprovalAnchor {
            methods: vec!["ssh-agent".to_owned()],
            ..Default::default()
        });
        services.stores.strong.lock().record = Some(record);
        let f = dir_fixture(&dir, services.clone()).await;
        let status = f.approve(&dir, &peer(10), &[]).await.unwrap_err();
        let refusal = crate::proto::AuthorizationError::from_status(&status).unwrap();
        assert_eq!(refusal.reason(), Reason::Unavailable);
        assert!(refusal.detail.contains("ssh-agent"), "{refusal:?}");
        assert_eq!(services.prompts(), 0);
    }

    #[tokio::test]
    async fn test_one_approval_at_a_time() {
        let dir = TempDir::new("one");
        std::fs::write(
            crate::policy::files::PolicyFiles::policy_path(&dir.0),
            r#"@id("human") permit (principal, action, resource) when { context.presence.verified };"#,
        )
        .unwrap();
        let services =
            MockServices::answering_after(R::Allowed, "", std::time::Duration::from_millis(300));
        let f = dir_fixture(&dir, services.clone()).await;
        *f.process.session.lock() = Some(TTY);
        let peer = peer(10);

        // A credential check while an approval waits is refused, naming the approval's terminal.
        let (approved, refused, second) = tokio::join!(
            f.approve(&dir, &peer, &[]),
            async {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                f.decide(f.peer_pending(20, "r", None)).await
            },
            async {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                f.approve(&dir, &peer, &[]).await
            },
        );
        approved.unwrap();
        let refusal = refused.unwrap_err();
        assert_eq!(refusal.reason(), Reason::CheckPending);
        assert!(refusal.detail.contains("/dev/pts/7"), "{refusal:?}");
        let status = second.unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(
            status
                .message()
                .contains("another policy approval is pending from /dev/pts/7")
        );
        assert_eq!(services.prompts(), 1);

        // An approval while a credential check waits is refused.
        let (checked, approval) =
            tokio::join!(f.decide(f.pending(30, None, "other", None)), async {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                f.approve(&dir, &peer, &[]).await
            },);
        checked.unwrap();
        let status = approval.unwrap_err();
        assert!(
            status
                .message()
                .contains("a credential check is pending from pid 30"),
            "{status:?}"
        );
        // Afterwards both work again.
        f.approve(&dir, &peer, &[]).await.unwrap();
    }

    #[tokio::test]
    async fn test_server_states() {
        use crate::policy::settings::PolicyState;
        let dir = TempDir::new("servers");
        std::fs::write(
            crate::policy::files::PolicyFiles::policy_path(&dir.0),
            READONLY_FREE,
        )
        .unwrap();
        let services = MockServices::answering(R::Allowed, "");
        services.stores.strong.lock().record = Some(crate::policy::files::test_support::record_of(
            &dir.0,
            1,
            &[("contoso", [1; 32])],
        ));
        let f = dir_fixture(&dir, services.clone()).await;
        assert_eq!(
            f.authorizer.policy().await.unwrap().state,
            PolicyState::Approved
        );

        f.assume_role("123456789012/ReadOnly", [1; 32])
            .await
            .unwrap();
        assert_eq!(services.prompts(), 0);
        // A changed server is refused before anything else, without a prompt.
        let refusal = f
            .assume_role("123456789012/ReadOnly", [2; 32])
            .await
            .unwrap_err();
        assert_eq!(refusal.reason(), Reason::Forbidden);
        assert!(
            refusal
                .detail
                .contains("server 'contoso' (https://contoso.awsapps.com/start) changed"),
            "{refusal:?}"
        );
        assert_eq!(services.prompts(), 0);
    }

    #[tokio::test]
    async fn test_unapproved_server() {
        let dir = TempDir::new("newserver");
        std::fs::write(
            crate::policy::files::PolicyFiles::policy_path(&dir.0),
            READONLY_FREE,
        )
        .unwrap();
        let services = MockServices::answering(R::Allowed, "");
        // The record does not hold contoso, so its roles get the built-ins and forbids only.
        services.stores.strong.lock().record = Some(crate::policy::files::test_support::record_of(
            &dir.0,
            1,
            &[],
        ));
        let f = dir_fixture(&dir, services.clone()).await;
        f.assume_role("123456789012/ReadOnly", [1; 32])
            .await
            .unwrap();
        assert_eq!(
            services.prompts(),
            1,
            "the permit does not apply to an unapproved server"
        );
    }

    #[tokio::test]
    async fn test_lockdown() {
        let services = MockServices::answering(R::Allowed, "");
        let f = fixture_with_policy(
            crate::policy::files::PolicyFiles::fixed(
                crate::policy::files::Effective::build_for(
                    crate::policy::settings::PolicyState::Tampered,
                    true,
                    &crate::policy::files::Content::Absent,
                    &crate::policy::files::Content::Absent,
                )
                .unwrap(),
            ),
            services.clone(),
        );
        // A fresh check permits; the session grant it leaves does not.
        f.decide(f.pending(10, Some(TTY), "r", None)).await.unwrap();
        f.decide(f.pending(11, Some(TTY), "r", None)).await.unwrap();
        assert_eq!(services.prompts(), 2);
        // A lease of a running exec still counts.
        let ctx = Some(exec_context("terraform plan", false));
        f.decide(f.pending(12, Some(TTY), "r", ctx.clone()))
            .await
            .unwrap();
        f.decide(f.pending(12, Some(TTY), "r", ctx)).await.unwrap();
        assert_eq!(services.prompts(), 3);
        // AI agents are refused outright.
        let mut p = f.pending(13, Some(TTY), "r", None);
        p.facts.tools.insert("ai-agent".to_owned());
        let refusal = f.decide(p).await.unwrap_err();
        assert_eq!(refusal.reason(), Reason::Forbidden);
        assert_eq!(refusal.policy_ids, vec!["builtin-lockdown-no-ai"]);
        assert_eq!(services.prompts(), 3);
    }

    #[test]
    fn test_gate2_and_sts_of_approved_settings() {
        let settings = crate::policy::files::Content::Text(
            r#"{"version": 1, "sts": {"region": "eu-west-1"}}"#.to_owned(),
        );
        let approved = crate::policy::files::Effective::build_for(
            crate::policy::settings::PolicyState::Approved,
            false,
            &crate::policy::files::Content::Absent,
            &settings,
        )
        .unwrap();
        let services = MockServices::answering(R::Allowed, "");
        let f = fixture_with_policy(crate::policy::files::PolicyFiles::fixed(approved), services);
        let p = f.pending(10, None, "r", None);
        // An unhardened agent runs gate 2 once the policy is approved.
        assert!(p.gate2(false));
        assert_eq!(
            p.sts_target().endpoint,
            "https://sts.eu-west-1.amazonaws.com"
        );
        let unapproved = crate::policy::files::Effective::build(
            false,
            &crate::policy::files::Content::Absent,
            &settings,
        )
        .unwrap();
        let f = fixture_with_policy(
            crate::policy::files::PolicyFiles::fixed(unapproved),
            MockServices::answering(R::Allowed, ""),
        );
        let p = f.pending(10, None, "r", None);
        assert!(!p.gate2(false));
        assert_eq!(p.sts_target(), crate::caller_identity::StsTarget::default());
    }
}
