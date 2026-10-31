//! Gate 1 of `AssumeRole`: decides whether a human must approve a request, asks through the platform helper, and
//! remembers the answer as grants (per terminal session) and leases (per running `mairu exec`).

/// Grants are dropped after this to bound memory; freshness itself is up to the policy.
const GRANT_RETENTION: std::time::Duration = std::time::Duration::from_secs(43200);
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

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

#[derive(Debug, Default)]
struct State {
    grants: std::collections::HashMap<GrantKey, Grant>,
    leases: std::collections::HashMap<LeaseKey, Lease>,
}

impl State {
    fn sweep(&mut self, now: std::time::Duration) {
        self.leases.retain(|_, l| pidfd_alive(&l.pidfd));
        self.grants
            .retain(|_, g| now.saturating_sub(g.created) <= GRANT_RETENTION);
    }
}

type PromptFuture = futures::future::Shared<
    futures::future::BoxFuture<'static, crate::proto::platform::AuthorizeResponse>,
>;
type FlightKey = (u32, u64, [u8; 32]);

struct Shared {
    engine: crate::policy::Engine,
    services: std::sync::Arc<dyn crate::platform::PlatformServices>,
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
            .field("engine", &self.shared.engine)
            .field("hardened", &self.shared.hardened)
            .finish()
    }
}

/// A request as gate 1 sees it.
#[derive(Debug)]
pub struct Request<'a> {
    pub peer: Option<&'a crate::platform::PeerIdentity>,
    pub server: &'a crate::config::Server,
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
}

/// A permitted request. Report what was vended through [`Authorized::vended`].
#[derive(Debug)]
pub struct Authorized {
    shared: std::sync::Arc<Shared>,
    lease: Option<LeaseKey>,
    demand: bool,
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
        engine: crate::policy::Engine,
        services: std::sync::Arc<dyn crate::platform::PlatformServices>,
        hardened: bool,
    ) -> Self {
        let this = Self::with_clock(engine, services, hardened, std::sync::Arc::new(BootClock));
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
                shared.state.lock().sweep(now);
            }
        });
        this
    }

    fn with_clock(
        engine: crate::policy::Engine,
        services: std::sync::Arc<dyn crate::platform::PlatformServices>,
        hardened: bool,
        clock: std::sync::Arc<dyn Clock>,
    ) -> Self {
        Self {
            shared: std::sync::Arc::new(Shared {
                engine,
                services,
                clock,
                hardened,
                state: Default::default(),
                inflight: Default::default(),
            }),
        }
    }

    /// The built-in policy for this process's hardening state.
    pub fn builtin(
        services: std::sync::Arc<dyn crate::platform::PlatformServices>,
    ) -> Result<Self, crate::policy::PolicyError> {
        let hardened = crate::hardening::Hardening::marker().is_some();
        Ok(Self::new(
            crate::policy::Engine::builtin(hardened)?,
            services,
            hardened,
        ))
    }

    /// Live grants and leases.
    pub fn counts(&self) -> (u32, u32) {
        let now = self.shared.clock.now();
        let mut state = self.shared.state.lock();
        state.sweep(now);
        (
            u32::try_from(state.grants.len()).unwrap_or(u32::MAX),
            u32::try_from(state.leases.len()).unwrap_or(u32::MAX),
        )
    }

    /// The methods that could ask a human right now, in order.
    pub async fn methods(&self) -> Vec<String> {
        let mut methods = vec![];
        if self.shared.platform_usable().await.is_ok() {
            methods.push(METHOD_PLATFORM.to_owned());
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

    /// Decides; asks a human when the policy would permit the request after a check and nothing remembered does.
    pub async fn authorize_assume_role(&self, req: Request<'_>) -> Result<Authorized, Refusal> {
        if req
            .user_config
            .is_role_disallowed(req.server, &req.rolespec.role)
        {
            tracing::warn!(
                server_id = req.server.id(),
                role = req.rolespec.role,
                "Refused by disallow_roles"
            );
            return Err(Refusal::new(
                crate::proto::authorization_error::Reason::Forbidden,
                format!(
                    "role '{}' is disallowed by disallow_roles in {}",
                    req.rolespec.role,
                    crate::config::UserConfig::path().display()
                ),
            ));
        }
        let pending = self.shared.pending(&req);
        let result = self.shared.decide(pending.clone()).await;
        match &result {
            Ok(_) => tracing::info!(
                pid = pending.pid,
                session = ?pending.session,
                server_id = pending.server_id,
                rolespec = ?pending.role_key,
                intent = pending.facts.intent,
                "Authorization permitted"
            ),
            Err(e) => tracing::info!(
                pid = pending.pid,
                session = ?pending.session,
                server_id = pending.server_id,
                rolespec = ?pending.role_key,
                intent = pending.facts.intent,
                reason = ?e.reason(),
                detail = e.detail,
                "Authorization refused"
            ),
        }
        result
    }
}

impl Shared {
    fn pending(&self, req: &Request<'_>) -> Pending {
        let platform = crate::platform::process();
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
        );
        pending.pidfd = pidfd;
        pending
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

    async fn decide(self: &std::sync::Arc<Self>, pending: Pending) -> Result<Authorized, Refusal> {
        use crate::proto::authorization_error::Reason;
        let prepared = self.engine.prepare(&pending.facts).map_err(|e| {
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

        // What is remembered: nothing, the lease of this process, the grant of this session.
        {
            let now = self.clock.now();
            let mut state = self.state.lock();
            let has_lease = state
                .leases
                .get(&lease_key)
                .is_some_and(|l| pidfd_alive(&l.pidfd));
            let authorized = |lease: bool| Authorized {
                shared: self.clone(),
                lease: lease.then(|| lease_key.clone()),
                demand: !pending.prefetch,
            };
            if note(
                &self
                    .engine
                    .evaluate(&prepared, &crate::policy::Presence::none()),
            ) {
                return Ok(authorized(has_lease));
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
                if note(&self.engine.evaluate(&prepared, &presence)) {
                    return Ok(authorized(true));
                }
            }
            if let Some(session) = pending.session {
                let key: GrantKey = (session, pending.server_id.clone(), pending.role_key.clone());
                if let Some(grant) = state.grants.get_mut(&key) {
                    let presence = crate::policy::Presence::remembered(
                        crate::policy::Scope::Session,
                        &grant.method,
                        secs(now.saturating_sub(grant.created)),
                        secs(now.saturating_sub(grant.last_used)),
                    );
                    if note(&self.engine.evaluate(&prepared, &presence)) {
                        grant.last_used = now;
                        return Ok(authorized(has_lease));
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
        for method in [METHOD_PLATFORM] {
            if !note(
                &self
                    .engine
                    .evaluate(&prepared, &crate::policy::Presence::fresh(method)),
            ) {
                continue;
            }
            fresh_allowed = true;
            if let Err(e) = self.platform_usable().await {
                tried.push(format!("{method}: {e}"));
                continue;
            }
            let resp = self.prompt(&pending).await;
            use crate::proto::platform::authorize_response::Result as R;
            match resp.result() {
                R::Allowed => {
                    self.record(&pending, &lease_key, method);
                    return Ok(Authorized {
                        shared: self.clone(),
                        lease: (pending.exec && pending.pidfd.is_some()).then_some(lease_key),
                        demand: true,
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
            let mut refusal = Refusal::new(
                Reason::Forbidden,
                format!("refused by policy {}", forbids.join(", ")),
            );
            refusal.policy_ids = forbids;
            return Err(refusal);
        }
        Err(Refusal::new(
            Reason::NotPermitted,
            "no policy permits this role, even after a human check",
        ))
    }

    /// Concurrent identical requests from one process share one prompt. Dropping every waiter cancels it.
    async fn prompt(&self, pending: &Pending) -> crate::proto::platform::AuthorizeResponse {
        use futures::FutureExt;
        let key: FlightKey = (pending.pid, pending.start_time, pending.digest);
        let flight: PromptFuture = {
            let mut inflight = self.inflight.lock();
            inflight.retain(|_, w| w.upgrade().is_some());
            match inflight.get(&key).and_then(|w| w.upgrade()) {
                Some(f) => f,
                None => {
                    let services = self.services.clone();
                    let request = pending.authorize_request();
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
        }
    }

    fn authorize_request(&self) -> crate::proto::platform::AuthorizeRequest {
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
        crate::proto::platform::AuthorizeRequest {
            action: crate::proto::platform::authorize_request::Action::AssumeRole.into(),
            subject: Some(crate::proto::platform::Process {
                pid: self.pid,
                start_time: self.start_time,
                uid: self.uid,
                executable: self
                    .exe
                    .as_ref()
                    .map(|e| {
                        use std::os::unix::ffi::OsStrExt;
                        e.as_os_str().as_bytes().to_vec()
                    })
                    .unwrap_or_default(),
                argv: vec![],
                name: String::new(),
            }),
            message: format!("Provide AWS credentials for {} on {}", f.role, f.server_id),
            details,
        }
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
    }

    impl MockServices {
        fn answering(result: R, reason: &str) -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                facility: crate::proto::platform::AuthorizationFacility::Polkit,
                answer: parking_lot::Mutex::new(crate::proto::platform::AuthorizeResponse {
                    result: result.into(),
                    reason: reason.to_owned(),
                    detail: String::new(),
                }),
                prompts: Default::default(),
                delay: std::time::Duration::ZERO,
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
            _req: crate::proto::platform::AuthorizeRequest,
        ) -> crate::proto::platform::AuthorizeResponse {
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
            _req: crate::proto::platform::RecordIntegrityRequest,
        ) -> crate::proto::platform::RecordIntegrityResponse {
            Default::default()
        }
        async fn verify_integrity(
            &self,
            _req: crate::proto::platform::VerifyIntegrityRequest,
        ) -> crate::proto::platform::VerifyIntegrityResponse {
            Default::default()
        }
    }

    struct Fixture {
        authorizer: Authorizer,
        services: std::sync::Arc<MockServices>,
        clock: std::sync::Arc<TestClock>,
        pidfd: std::sync::Arc<std::os::fd::OwnedFd>,
    }

    const TTY: crate::platform::SessionIdentity = crate::platform::SessionIdentity::Tty {
        sid: 4242,
        leader_start_time: 7,
    };

    fn fixture_with(
        engine: crate::policy::Engine,
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
        Fixture {
            authorizer: Authorizer::with_clock(engine, services.clone(), true, clock.clone()),
            services,
            clock,
            pidfd,
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
        }
    }

    impl Fixture {
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
                user_config: &user_config,
                rolespec: &rs,
                client_context: context.as_ref(),
            };
            let mut p = Pending::new(&req, 1000, session, None, true);
            p.pid = pid;
            p.start_time = 1;
            p.pidfd = Some(self.pidfd.clone());
            p
        }

        async fn decide(&self, pending: Pending) -> Result<Authorized, Refusal> {
            self.authorizer.shared.decide(pending).await
        }
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
}
