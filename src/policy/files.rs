//! `policy.cedar` and `authorization.json` in `config_dir()`, read by the agent itself, verified against the
//! integrity stores, and what is in force for them.

pub const SETTINGS_FILE_NAME: &str = "authorization.json";

/// Files are re-read and re-verified after this even when their metadata looks unchanged.
const TTL: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_FILE_SIZE: u64 = 1024 * 1024;

/// The policy and settings in force for one state of the files.
#[derive(Debug)]
pub struct Effective {
    pub engine: super::Engine,
    pub settings: super::settings::EffectiveSettings,
    pub labels: Vec<crate::tool_detection::ToolLabel>,
    /// `settings.ssh_agent_keys`, parsed.
    pub ssh_agent_keys: Vec<crate::ssh_agent_presence::RegisteredKey>,
    pub state: super::settings::PolicyState,
    /// Content that is ignored, such as dropped policies.
    pub notes: Vec<String>,
}

/// A file's content as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    Absent,
    Text(String),
    Unreadable(String),
}

impl Effective {
    /// Built-ins only, with default settings.
    pub fn builtin(hardened: bool) -> Result<Self, super::PolicyError> {
        Ok(Self::with_engine(super::Engine::builtin(hardened)?))
    }

    pub fn with_engine(engine: super::Engine) -> Self {
        let settings = super::settings::EffectiveSettings::default();
        Self {
            engine,
            labels: settings.labels(),
            ssh_agent_keys: settings.registered_keys(),
            settings,
            state: super::settings::PolicyState::Absent,
            notes: vec![],
        }
    }

    /// The files as if no store held a record: `ABSENT` or `UNAPPROVED`.
    pub fn build(
        hardened: bool,
        policy: &Content,
        settings: &Content,
    ) -> Result<Self, super::PolicyError> {
        use super::settings::PolicyState;
        let state = if *policy == Content::Absent && *settings == Content::Absent {
            PolicyState::Absent
        } else {
            PolicyState::Unapproved
        };
        Self::build_for(
            state,
            hardened,
            policy,
            settings,
            &super::integrity_state::default_anchor(),
        )
    }

    /// What is in force for `state`, with `anchor` the approval anchor in force. An approved policy that no longer
    /// validates, for example after an upgrade, is treated as `UNAPPROVED`, with a note.
    pub fn build_for(
        state: super::settings::PolicyState,
        hardened: bool,
        policy: &Content,
        settings: &Content,
        anchor: &crate::proto::platform::ApprovalAnchor,
    ) -> Result<Self, super::PolicyError> {
        use super::settings::PolicyState;
        match state {
            PolicyState::Absent => Self::builtin(hardened),
            PolicyState::Approved => match Self::approved(hardened, policy, settings)? {
                Ok(effective) => Ok(effective),
                Err(e) => {
                    let mut effective = Self::restricted(
                        PolicyState::Unapproved,
                        hardened,
                        policy,
                        settings,
                        anchor,
                    )?;
                    effective.notes.insert(
                        0,
                        format!(
                            "the approved policy no longer validates, so it is treated as unapproved; fix it and run `mairu policy approve` again: {e}"
                        ),
                    );
                    Ok(effective)
                }
            },
            PolicyState::Unapproved | PolicyState::Tampered => {
                Self::restricted(state, hardened, policy, settings, anchor)
            }
        }
    }

    /// An approved file in full: `policy.cedar` replaces the built-ins. `Err` when the files no longer validate.
    fn approved(
        hardened: bool,
        policy: &Content,
        settings: &Content,
    ) -> Result<Result<Self, String>, super::PolicyError> {
        use super::settings::PolicyState;
        let file_settings = match settings {
            Content::Absent => None,
            Content::Unreadable(e) => return Ok(Err(format!("{SETTINGS_FILE_NAME}: {e}"))),
            Content::Text(source) => match super::settings::AuthorizationSettings::parse(source) {
                Ok(s) => Some(s),
                Err(e) => return Ok(Err(format!("{SETTINGS_FILE_NAME}: {e}"))),
            },
        };
        let engine = match policy {
            Content::Absent => {
                super::Engine::with_user_policies(super::Base::Builtin { hardened }, &[])?
            }
            Content::Unreadable(e) => return Ok(Err(format!("{}: {e}", super::user::FILE_NAME))),
            Content::Text(source) => {
                let file = match super::user::PolicyFile::parse(source) {
                    Ok(f) => f,
                    Err(e) => return Ok(Err(format!("{}: {e}", super::user::FILE_NAME))),
                };
                let errors = file.errors(&super::schema()?);
                if !errors.is_empty() {
                    return Ok(Err(errors.join("; ")));
                }
                match super::Engine::with_user_policies(super::Base::None, &file.policies) {
                    Ok(engine) => engine,
                    Err(e) => return Ok(Err(e.to_string())),
                }
            }
        };
        let notes = vec![];
        let settings = super::settings::EffectiveSettings::effective(
            PolicyState::Approved,
            file_settings.as_ref(),
            &super::integrity_state::default_anchor(),
        );
        Ok(Ok(Self {
            engine,
            labels: settings.labels(),
            ssh_agent_keys: settings.registered_keys(),
            settings,
            state: PolicyState::Approved,
            notes,
        }))
    }

    /// Unapproved content, and lockdown, take only what tightens: the `forbid` policies that validate, label
    /// additions and a shorter grant retention.
    fn restricted(
        state: super::settings::PolicyState,
        hardened: bool,
        policy: &Content,
        settings: &Content,
        anchor: &crate::proto::platform::ApprovalAnchor,
    ) -> Result<Self, super::PolicyError> {
        use super::settings::PolicyState;
        let schema = super::schema()?;
        let while_ = match state {
            PolicyState::Tampered => "in lockdown",
            _ => "while it is unapproved",
        };
        let mut notes = vec![];
        let forbids = match policy {
            Content::Absent => vec![],
            Content::Unreadable(e) => {
                notes.push(format!("ignored {}: {e}", super::user::FILE_NAME));
                vec![]
            }
            Content::Text(source) => {
                let (forbids, mut n) = super::user::PolicyFile::unapproved_forbids(source, &schema);
                notes.append(&mut n);
                forbids
            }
        };
        let file_settings = match settings {
            Content::Absent => None,
            Content::Unreadable(e) => {
                notes.push(format!("ignored {SETTINGS_FILE_NAME}: {e}"));
                None
            }
            Content::Text(source) => match super::settings::AuthorizationSettings::parse(source) {
                Ok(s) => Some(s),
                Err(e) => {
                    notes.push(format!("ignored {SETTINGS_FILE_NAME}: {e}"));
                    None
                }
            },
        };
        if let Some(s) = &file_settings {
            let ignored: Vec<&str> = [
                ("methods", s.methods.is_some()),
                ("approval_methods", s.approval_methods.is_some()),
                ("ssh_agent_keys", s.ssh_agent_keys.is_some()),
                ("sts", s.sts.is_some()),
                ("network", s.network.is_some()),
            ]
            .into_iter()
            .filter_map(|(name, set)| set.then_some(name))
            .collect();
            if !ignored.is_empty() {
                notes.push(format!(
                    "ignored {} of {SETTINGS_FILE_NAME} {while_}",
                    ignored.join(", ")
                ));
            }
        }
        let base = match state {
            PolicyState::Tampered => super::Base::Lockdown,
            _ => super::Base::Builtin { hardened },
        };
        let settings =
            super::settings::EffectiveSettings::effective(state, file_settings.as_ref(), anchor);
        Ok(Self {
            engine: super::Engine::with_user_policies(base, &forbids)?,
            labels: settings.labels(),
            ssh_agent_keys: settings.registered_keys(),
            settings,
            state,
            notes,
        })
    }
}

/// The files as verified against the integrity stores, and what is in force for each server state.
#[derive(Debug)]
pub struct Verified {
    /// The policy's own state; an approved policy that no longer validates counts as `UNAPPROVED`.
    pub state: super::settings::PolicyState,
    pub digest: super::integrity_state::Digest,
    /// In force for the policy's own state.
    pub effective: std::sync::Arc<Effective>,
    /// In force for unapproved servers while the policy is approved.
    unapproved: Option<std::sync::Arc<Effective>>,
    pub stores: Vec<crate::proto::platform::IntegrityStoreResult>,
    /// The record whose anchor and server digests are in force.
    pub record: Option<crate::proto::platform::IntegrityRecord>,
    pub anchor: crate::proto::platform::ApprovalAnchor,
    /// The strong record, for the generation of the next approval.
    pub strong: Option<crate::proto::platform::IntegrityRecord>,
}

impl Verified {
    /// `effective` alone, as if no store were available.
    pub fn fixed(effective: Effective) -> Self {
        Self {
            state: effective.state,
            digest: [0; 32],
            effective: std::sync::Arc::new(effective),
            unapproved: None,
            stores: vec![],
            record: None,
            anchor: super::integrity_state::default_anchor(),
            strong: None,
        }
    }

    pub fn server_state(
        &self,
        server_id: &str,
        digest: &super::integrity_state::Digest,
    ) -> super::integrity_state::ServerState {
        super::integrity_state::ServerState::of(self.record.as_ref(), server_id, digest)
    }

    /// What is in force for a server's roles: the stricter of the policy's state and the server's. `None` for a
    /// changed server, whose roles are refused.
    pub fn for_server(
        &self,
        server: super::integrity_state::ServerState,
    ) -> Option<std::sync::Arc<Effective>> {
        use super::integrity_state::ServerState;
        match server {
            ServerState::Changed => None,
            ServerState::Unapproved => Some(
                self.unapproved
                    .clone()
                    .unwrap_or_else(|| self.effective.clone()),
            ),
            ServerState::Approved => Some(self.effective.clone()),
        }
    }

    /// Notes of the policy's own state, and a warning while in lockdown.
    pub fn notes(&self) -> Vec<String> {
        let mut notes = vec![];
        if self.state == super::settings::PolicyState::Tampered {
            notes.push(LOCKDOWN_WARNING.to_owned());
        }
        notes.extend(self.effective.notes.iter().cloned());
        notes
    }
}

/// What clients print while the policy is `TAMPERED`.
pub const LOCKDOWN_WARNING: &str = "the policy files changed since they were approved, so lockdown applies: every request needs a fresh human check and AI agents are refused; review them and run `mairu policy approve`";

/// `(dev, ino, mtime, size)`, or why there is none.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Key {
    Absent,
    Error(std::io::ErrorKind),
    Meta(u64, u64, i64, i64, u64),
}

impl Key {
    fn of(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Key::Meta(
            meta.dev(),
            meta.ino(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.size(),
        )
    }

    fn stat(path: &std::path::Path) -> Self {
        match std::fs::metadata(path) {
            Ok(meta) => Self::of(&meta),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Key::Absent,
            Err(e) => Key::Error(e.kind()),
        }
    }
}

/// Reads through the open file, so that the key describes exactly what was read.
fn read(path: &std::path::Path) -> (Key, Content) {
    use std::io::Read;
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (Key::Absent, Content::Absent);
        }
        Err(e) => return (Key::Error(e.kind()), Content::Unreadable(e.to_string())),
    };
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => return (Key::Error(e.kind()), Content::Unreadable(e.to_string())),
    };
    let key = Key::of(&meta);
    if !meta.is_file() {
        return (key, Content::Unreadable("not a regular file".to_owned()));
    }
    if meta.len() > MAX_FILE_SIZE {
        return (
            key,
            Content::Unreadable(format!("larger than {MAX_FILE_SIZE} bytes")),
        );
    }
    let mut text = String::new();
    match file.read_to_string(&mut text) {
        Ok(_) => (key, Content::Text(text)),
        Err(e) => (key, Content::Unreadable(e.to_string())),
    }
}

#[derive(Debug)]
struct Cached {
    keys: [Key; 2],
    loaded_at: std::time::Instant,
    verified: Result<std::sync::Arc<Verified>, String>,
}

/// Where integrity records are verified and written: the platform helper, for this uid and record name.
#[derive(Debug, Clone)]
pub struct Stores {
    pub services: std::sync::Arc<dyn crate::platform::PlatformServices>,
    pub uid: u32,
    pub name: String,
}

impl Stores {
    pub async fn verify(
        &self,
        digest: &super::integrity_state::Digest,
    ) -> Vec<crate::proto::platform::IntegrityStoreResult> {
        self.services
            .verify_integrity(crate::proto::platform::VerifyIntegrityRequest {
                name: self.name.clone(),
                uid: self.uid,
                digest: digest.to_vec(),
            })
            .await
            .results
    }

    pub async fn record(
        &self,
        record: crate::proto::platform::IntegrityRecord,
        stores: Vec<crate::proto::platform::IntegrityStoreKind>,
    ) -> Vec<crate::proto::platform::IntegrityStoreResult> {
        self.services
            .record_integrity(crate::proto::platform::RecordIntegrityRequest {
                name: self.name.clone(),
                uid: self.uid,
                record: Some(record),
                stores: stores.into_iter().map(Into::into).collect(),
            })
            .await
            .results
    }
}

/// The verified policy, re-read and re-verified when the files' metadata changes and at least every 5 seconds.
#[derive(Debug)]
pub struct PolicyFiles {
    source: Source,
    cache: tokio::sync::Mutex<Option<Cached>>,
    last: parking_lot::Mutex<Option<std::sync::Arc<Verified>>>,
}

#[derive(Debug)]
enum Source {
    Dir {
        dir: std::path::PathBuf,
        hardened: bool,
        ttl: std::time::Duration,
        stores: Stores,
    },
    Fixed(std::sync::Arc<Verified>),
}

impl PolicyFiles {
    pub fn new(dir: std::path::PathBuf, hardened: bool, stores: Stores) -> Self {
        Self::with_ttl(dir, hardened, stores, TTL)
    }

    fn with_ttl(
        dir: std::path::PathBuf,
        hardened: bool,
        stores: Stores,
        ttl: std::time::Duration,
    ) -> Self {
        Self {
            source: Source::Dir {
                dir,
                hardened,
                ttl,
                stores,
            },
            cache: Default::default(),
            last: Default::default(),
        }
    }

    /// Always `effective`, whatever the files say.
    pub fn fixed(effective: Effective) -> Self {
        Self::fixed_verified(Verified::fixed(effective))
    }

    pub fn fixed_verified(verified: Verified) -> Self {
        let verified = std::sync::Arc::new(verified);
        Self {
            source: Source::Fixed(verified.clone()),
            cache: Default::default(),
            last: parking_lot::Mutex::new(Some(verified)),
        }
    }

    pub fn policy_path(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join(super::user::FILE_NAME)
    }

    pub fn settings_path(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join(SETTINGS_FILE_NAME)
    }

    /// The content of both files, as the agent reads them.
    pub fn read_contents(dir: &std::path::Path) -> (Content, Content) {
        (
            read(&Self::policy_path(dir)).1,
            read(&Self::settings_path(dir)).1,
        )
    }

    /// The stores records are kept in; `None` for a fixed policy.
    pub fn stores(&self) -> Option<&Stores> {
        match &self.source {
            Source::Dir { stores, .. } => Some(stores),
            Source::Fixed(_) => None,
        }
    }

    pub fn dir(&self) -> Option<&std::path::Path> {
        match &self.source {
            Source::Dir { dir, .. } => Some(dir),
            Source::Fixed(_) => None,
        }
    }

    /// The most recently loaded policy, without reading or verifying anything.
    pub fn last(&self) -> Option<std::sync::Arc<Verified>> {
        self.last.lock().clone()
    }

    /// The next [`Self::load`] re-reads and re-verifies.
    pub async fn invalidate(&self) {
        *self.cache.lock().await = None;
    }

    /// The verified policy now. An error means not even the built-ins could be built.
    pub async fn load(&self) -> Result<std::sync::Arc<Verified>, String> {
        let (dir, hardened, ttl, stores) = match &self.source {
            Source::Fixed(verified) => return Ok(verified.clone()),
            Source::Dir {
                dir,
                hardened,
                ttl,
                stores,
            } => (dir, *hardened, *ttl, stores),
        };
        let policy_path = Self::policy_path(dir);
        let settings_path = Self::settings_path(dir);
        let mut cache = self.cache.lock().await;
        if let Some(cached) = cache.as_ref()
            && cached.loaded_at.elapsed() < ttl
            && cached.keys == [Key::stat(&policy_path), Key::stat(&settings_path)]
        {
            return cached.verified.clone();
        }
        let (policy_key, policy) = read(&policy_path);
        let (settings_key, settings) = read(&settings_path);
        let previous = cache
            .as_ref()
            .and_then(|c| c.verified.as_ref().ok())
            .map(|v| (v.state, v.digest));
        let verified = verify(hardened, stores, &policy, &settings)
            .await
            .map(std::sync::Arc::new)
            .map_err(|e| e.to_string());
        match &verified {
            Ok(v) if previous != Some((v.state, v.digest)) => tracing::info!(
                state = v.state.as_str(),
                digest = crate::platform::integrity::hex(&v.digest),
                stores = ?v.stores.iter().map(|r| (r.store(), r.status(), r.detail.as_str())).collect::<Vec<_>>(),
                policies = ?v.effective.engine.policy_ids(),
                notes = ?v.notes(),
                "Authorization policy loaded"
            ),
            Ok(_) => {}
            Err(e) => tracing::error!(err = e, "Failed to build the authorization policy"),
        }
        if let Ok(v) = &verified {
            *self.last.lock() = Some(v.clone());
            crate::network::apply(v.effective.settings.network.as_ref());
        }
        *cache = Some(Cached {
            keys: [policy_key, settings_key],
            loaded_at: std::time::Instant::now(),
            verified: verified.clone(),
        });
        verified
    }
}

/// Verifies the files with the stores, repairs what the stores missed, and builds what is in force.
async fn verify(
    hardened: bool,
    stores: &Stores,
    policy: &Content,
    settings: &Content,
) -> Result<Verified, super::PolicyError> {
    use super::settings::PolicyState;
    let digest = super::integrity_state::policy_digest(policy, settings);
    let results = stores.verify(&digest).await;
    let files_absent = *policy == Content::Absent && *settings == Content::Absent;
    let decision =
        super::integrity_state::Decision::decide(results, &digest, files_absent, hardened);
    if let Some(strong) = &decision.strong
        && !decision.rewrite.is_empty()
    {
        tracing::warn!(stores = ?decision.rewrite, generation = strong.generation, "Restoring the strong record in stores that missed an approval");
        stores
            .record(strong.clone(), decision.rewrite.clone())
            .await;
    }
    if !decision.backfill.is_empty()
        && let Some(record) = &decision.record
    {
        tracing::info!(stores = ?decision.backfill, "Writing the approved record to stores that lack it");
        stores
            .record(record.clone(), decision.backfill.clone())
            .await;
    }
    let effective =
        Effective::build_for(decision.state, hardened, policy, settings, &decision.anchor)?;
    let state = effective.state;
    let unapproved = if state == PolicyState::Approved {
        Some(std::sync::Arc::new(Effective::build_for(
            PolicyState::Unapproved,
            hardened,
            policy,
            settings,
            &decision.anchor,
        )?))
    } else {
        None
    };
    Ok(Verified {
        state,
        digest,
        effective: std::sync::Arc::new(effective),
        unapproved,
        stores: decision.results,
        record: decision.record,
        anchor: decision.anchor,
        strong: decision.strong,
    })
}

/// In-memory integrity stores for tests: one strong and one weak, each unavailable or holding a record.
#[cfg(test)]
pub mod test_support {
    use crate::proto::platform::IntegrityStatus as S;
    use crate::proto::platform::IntegrityStoreKind as K;

    #[derive(Debug, Clone, Default)]
    pub struct Store {
        pub available: bool,
        pub record: Option<crate::proto::platform::IntegrityRecord>,
        pub writes: usize,
    }

    #[derive(Debug, Default)]
    pub struct MemoryStores {
        pub strong: parking_lot::Mutex<Store>,
        pub weak: parking_lot::Mutex<Store>,
    }

    impl MemoryStores {
        pub fn new(strong: bool, weak: bool) -> std::sync::Arc<Self> {
            let this = Self::default();
            this.strong.lock().available = strong;
            this.weak.lock().available = weak;
            std::sync::Arc::new(this)
        }

        fn stores(&self) -> [(K, &parking_lot::Mutex<Store>); 2] {
            [
                (K::ProtectedDirectory, &self.strong),
                (K::SecretService, &self.weak),
            ]
        }

        pub fn verify(
            &self,
            req: crate::proto::platform::VerifyIntegrityRequest,
        ) -> crate::proto::platform::VerifyIntegrityResponse {
            let results = self
                .stores()
                .into_iter()
                .map(|(kind, store)| {
                    let store = store.lock();
                    let status = match (&store.record, store.available) {
                        (_, false) => S::Unavailable,
                        (None, true) => S::NotRecorded,
                        (Some(r), true) if r.digest == req.digest => S::Matched,
                        (Some(_), true) => S::Mismatched,
                    };
                    crate::proto::platform::IntegrityStoreResult {
                        store: kind.into(),
                        status: status.into(),
                        detail: String::new(),
                        stored: store.record.clone().filter(|_| store.available),
                    }
                })
                .collect();
            crate::proto::platform::VerifyIntegrityResponse { results }
        }

        pub fn record(
            &self,
            req: crate::proto::platform::RecordIntegrityRequest,
        ) -> crate::proto::platform::RecordIntegrityResponse {
            let results = self
                .stores()
                .into_iter()
                .filter(|(kind, _)| req.stores.is_empty() || req.stores.contains(&(*kind as i32)))
                .map(|(kind, store)| {
                    let mut store = store.lock();
                    let status = if store.available {
                        store.record = req.record.clone();
                        store.writes += 1;
                        S::Matched
                    } else {
                        S::Unavailable
                    };
                    crate::proto::platform::IntegrityStoreResult {
                        store: kind.into(),
                        status: status.into(),
                        detail: String::new(),
                        stored: None,
                    }
                })
                .collect();
            crate::proto::platform::RecordIntegrityResponse { results }
        }
    }

    #[async_trait::async_trait]
    impl crate::platform::PlatformServices for MemoryStores {
        async fn capabilities(&self) -> crate::proto::platform::Capabilities {
            Default::default()
        }
        async fn authorize(
            &self,
            _req: crate::proto::platform::AuthorizeRequest,
        ) -> crate::proto::platform::AuthorizeResponse {
            crate::proto::platform::AuthorizeResponse::unavailable("test", "")
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
            self.record(req)
        }
        async fn verify_integrity(
            &self,
            req: crate::proto::platform::VerifyIntegrityRequest,
        ) -> crate::proto::platform::VerifyIntegrityResponse {
            self.verify(req)
        }
    }

    pub fn stores(
        services: std::sync::Arc<dyn crate::platform::PlatformServices>,
    ) -> super::Stores {
        super::Stores {
            services,
            uid: 1000,
            name: "policy".to_owned(),
        }
    }

    /// A record of the files in `dir` as they are now, with every server digest given.
    pub fn record_of(
        dir: &std::path::Path,
        generation: u64,
        servers: &[(&str, super::super::integrity_state::Digest)],
    ) -> crate::proto::platform::IntegrityRecord {
        let (policy, settings) = super::PolicyFiles::read_contents(dir);
        crate::proto::platform::IntegrityRecord {
            digest: super::super::integrity_state::policy_digest(&policy, &settings).to_vec(),
            approval: Some(super::super::integrity_state::default_anchor()),
            generation,
            server_digests: servers
                .iter()
                .map(|(id, d)| (id.to_string(), d.to_vec()))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("mairu-test-policy-{name}-{}", std::process::id()));
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

    fn ids(e: &Effective) -> Vec<String> {
        let mut ids = e.engine.policy_ids();
        ids.sort();
        ids
    }

    #[test]
    fn test_absent() {
        let e = Effective::build(true, &Content::Absent, &Content::Absent).unwrap();
        assert_eq!(e.state, super::super::settings::PolicyState::Absent);
        assert_eq!(ids(&e), ids(&Effective::builtin(true).unwrap()));
        assert!(e.notes.is_empty());
    }

    #[test]
    fn test_unapproved_forbid_only() {
        let policy = Content::Text(
            r#"
            @id("allow-all") permit (principal, action, resource);
            @id("no-prod") forbid (principal, action, resource in Mairu::Account::"999999999999");
            "#
            .to_owned(),
        );
        let e = Effective::build(true, &policy, &Content::Absent).unwrap();
        assert_eq!(e.state, super::super::settings::PolicyState::Unapproved);
        assert!(ids(&e).contains(&"no-prod".to_owned()));
        assert!(!ids(&e).contains(&"allow-all".to_owned()));
        assert!(e.engine.text().contains(r#"@id("no-prod")"#));
        assert!(!e.engine.text().contains("allow-all"));
        assert_eq!(e.notes.len(), 1);

        // The effective text parses back into the same policy set.
        let reparsed = super::super::Engine::from_text(e.engine.text()).unwrap();
        let mut reparsed_ids = reparsed.policy_ids();
        reparsed_ids.sort();
        assert_eq!(reparsed_ids, ids(&e));

        // On an unhardened agent the forbid applies beside builtin-unhardened.
        let e = Effective::build(false, &policy, &Content::Absent).unwrap();
        assert!(ids(&e).contains(&"builtin-unhardened".to_owned()));
        assert!(ids(&e).contains(&"no-prod".to_owned()));
    }

    #[test]
    fn test_unapproved_settings() {
        let settings = Content::Text(
            serde_json::json!({
                "version": 1,
                "methods": ["platform"],
                "tool_detection": {"ci": {"env_names": ["CI"]}},
                "grant_retention_secs": 600,
                "sts": {"region": "eu-west-1"},
            })
            .to_string(),
        );
        let e = Effective::build(true, &Content::Absent, &settings).unwrap();
        assert_eq!(e.state, super::super::settings::PolicyState::Unapproved);
        assert_eq!(e.settings.grant_retention_secs, 600);
        assert!(e.labels.iter().any(|l| l.name == "ci"));
        assert_eq!(
            e.notes,
            vec!["ignored methods, sts of authorization.json while it is unapproved"]
        );

        let e = Effective::build(
            true,
            &Content::Absent,
            &Content::Text(r#"{"version": 1, "typo": true}"#.to_owned()),
        )
        .unwrap();
        assert_eq!(e.state, super::super::settings::PolicyState::Unapproved);
        assert_eq!(e.settings, Default::default());
        assert!(e.notes[0].starts_with("ignored authorization.json: unknown field"));
    }

    #[test]
    fn test_unreadable() {
        let e = Effective::build(
            true,
            &Content::Unreadable("permission denied".to_owned()),
            &Content::Absent,
        )
        .unwrap();
        assert_eq!(e.state, super::super::settings::PolicyState::Unapproved);
        assert_eq!(e.notes, vec!["ignored policy.cedar: permission denied"]);
    }

    fn files(dir: &TempDir, stores: &std::sync::Arc<test_support::MemoryStores>) -> PolicyFiles {
        PolicyFiles::with_ttl(
            dir.0.clone(),
            true,
            test_support::stores(stores.clone()),
            std::time::Duration::from_secs(5),
        )
    }

    #[tokio::test]
    async fn test_cache() {
        let dir = TempDir::new("cache");
        let stores = test_support::MemoryStores::new(true, true);
        let files = files(&dir, &stores);
        let path = PolicyFiles::policy_path(&dir.0);
        async fn has(files: &PolicyFiles, id: &str) -> bool {
            files
                .load()
                .await
                .unwrap()
                .effective
                .engine
                .policy_ids()
                .contains(&id.to_owned())
        }
        assert!(!has(&files, "aaaa").await);
        assert_eq!(
            files.load().await.unwrap().state,
            super::super::settings::PolicyState::Absent
        );

        std::fs::write(
            &path,
            r#"@id("aaaa") forbid (principal, action, resource);"#,
        )
        .unwrap();
        // A changed (dev, ino, mtime, size) is seen at once.
        assert!(has(&files, "aaaa").await);

        // An edit that keeps every key is seen only after the TTL.
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            f.write_all(br#"@id("bbbb") forbid (principal, action, resource);"#)
                .unwrap();
            f.set_modified(mtime).unwrap();
        }
        assert!(has(&files, "aaaa").await);
        files.invalidate().await;
        assert!(has(&files, "bbbb").await);
        let files = PolicyFiles::with_ttl(
            dir.0.clone(),
            true,
            test_support::stores(stores.clone()),
            std::time::Duration::ZERO,
        );
        assert!(has(&files, "bbbb").await);

        std::fs::remove_file(&path).unwrap();
        assert!(!has(&files, "bbbb").await);
    }

    const APPROVED_POLICY: &str = r#"
        @id("allow-readonly") permit (principal, action == Mairu::Action::"AssumeRole", resource == Mairu::Role::"contoso:123456789012/ReadOnly");
        @id("no-prod") forbid (principal, action, resource in Mairu::Account::"999999999999");
    "#;

    #[tokio::test]
    async fn test_approved_and_tampered() {
        use super::super::settings::PolicyState;
        let dir = TempDir::new("approved");
        let stores = test_support::MemoryStores::new(true, true);
        let files = PolicyFiles::with_ttl(
            dir.0.clone(),
            true,
            test_support::stores(stores.clone()),
            std::time::Duration::ZERO,
        );
        std::fs::write(PolicyFiles::policy_path(&dir.0), APPROVED_POLICY).unwrap();
        std::fs::write(
            PolicyFiles::settings_path(&dir.0),
            r#"{"version": 1, "grant_retention_secs": 86400, "sts": {"region": "eu-west-1"}}"#,
        )
        .unwrap();
        let v = files.load().await.unwrap();
        assert_eq!(v.state, PolicyState::Unapproved);
        assert!(!ids(&v.effective).contains(&"allow-readonly".to_owned()));

        stores.strong.lock().record =
            Some(test_support::record_of(&dir.0, 1, &[("contoso", [1; 32])]));
        let v = files.load().await.unwrap();
        assert_eq!(v.state, PolicyState::Approved);
        // The approved file replaces the built-ins.
        let approved = ids(&v.effective);
        assert!(approved.contains(&"allow-readonly".to_owned()));
        assert!(!approved.contains(&"builtin-human".to_owned()));
        assert!(approved.contains(&"builtin-use-credentials".to_owned()));
        assert_eq!(v.effective.settings.grant_retention_secs, 86400);
        assert!(v.effective.settings.sts.is_some());
        // Backfilled into the weak store.
        assert_eq!(stores.weak.lock().record, stores.strong.lock().record);

        use super::super::integrity_state::ServerState;
        assert_eq!(v.server_state("contoso", &[1; 32]), ServerState::Approved);
        assert_eq!(v.server_state("contoso", &[2; 32]), ServerState::Changed);
        assert_eq!(v.server_state("new", &[1; 32]), ServerState::Unapproved);
        assert!(v.for_server(ServerState::Changed).is_none());
        let unapproved = v.for_server(ServerState::Unapproved).unwrap();
        assert_eq!(unapproved.state, PolicyState::Unapproved);
        assert!(!ids(&unapproved).contains(&"allow-readonly".to_owned()));
        assert!(ids(&unapproved).contains(&"no-prod".to_owned()));

        // Deleting only the weak copy: still approved, and written again.
        stores.weak.lock().record = None;
        assert_eq!(files.load().await.unwrap().state, PolicyState::Approved);
        assert!(stores.weak.lock().record.is_some());

        // Altering only the weak copy on a hardened host.
        stores.weak.lock().record.as_mut().unwrap().digest = vec![0; 32];
        let v = files.load().await.unwrap();
        assert_eq!(v.state, PolicyState::Tampered);
        assert_eq!(v.notes()[0], LOCKDOWN_WARNING);
        let lockdown = ids(&v.effective);
        assert!(lockdown.contains(&"builtin-lockdown".to_owned()));
        assert!(lockdown.contains(&"builtin-lockdown-no-ai".to_owned()));
        assert!(lockdown.contains(&"no-prod".to_owned()));
        assert!(!lockdown.contains(&"allow-readonly".to_owned()));
        assert!(!lockdown.contains(&"builtin-human".to_owned()));
        assert_eq!(
            v.effective.settings.grant_retention_secs,
            super::super::settings::DEFAULT_GRANT_RETENTION_SECS
        );
        // Not repaired silently.
        assert_eq!(
            stores.weak.lock().record.as_ref().unwrap().digest,
            vec![0; 32]
        );
        stores.weak.lock().record = stores.strong.lock().record.clone();

        // Editing a file after approval.
        std::fs::write(
            PolicyFiles::policy_path(&dir.0),
            format!("{APPROVED_POLICY}\n@id(\"more\") permit (principal, action, resource);"),
        )
        .unwrap();
        let v = files.load().await.unwrap();
        assert_eq!(v.state, PolicyState::Tampered);
        // The server digests and anchor of the record still count.
        assert_eq!(v.server_state("contoso", &[2; 32]), ServerState::Changed);
        assert!(v.for_server(ServerState::Unapproved).unwrap().state == PolicyState::Tampered);
    }

    #[tokio::test]
    async fn test_schema_drift() {
        use super::super::settings::PolicyState;
        let dir = TempDir::new("drift");
        let stores = test_support::MemoryStores::new(true, false);
        let files = PolicyFiles::with_ttl(
            dir.0.clone(),
            true,
            test_support::stores(stores.clone()),
            std::time::Duration::ZERO,
        );
        std::fs::write(
            PolicyFiles::policy_path(&dir.0),
            r#"@id("future") permit (principal, action, resource) when { context.future_attribute == 1 };
               @id("no-prod") forbid (principal, action, resource in Mairu::Account::"999999999999");"#,
        )
        .unwrap();
        stores.strong.lock().record = Some(test_support::record_of(&dir.0, 1, &[]));
        let v = files.load().await.unwrap();
        assert_eq!(v.state, PolicyState::Unapproved);
        assert!(
            v.notes()[0].contains("no longer validates"),
            "{:?}",
            v.notes()
        );
        assert!(ids(&v.effective).contains(&"no-prod".to_owned()));
        assert!(!ids(&v.effective).contains(&"future".to_owned()));
    }

    #[tokio::test]
    async fn test_record_without_files() {
        use super::super::settings::PolicyState;
        let dir = TempDir::new("nofiles");
        let stores = test_support::MemoryStores::new(true, true);
        stores.strong.lock().record = Some(test_support::record_of(&dir.0, 1, &[]));
        let files = files(&dir, &stores);
        // The record is of the absent files, so it matches.
        assert_eq!(files.load().await.unwrap().state, PolicyState::Approved);
        stores.strong.lock().record.as_mut().unwrap().digest = vec![3; 32];
        files.invalidate().await;
        assert_eq!(files.load().await.unwrap().state, PolicyState::Tampered);
    }

    #[tokio::test]
    async fn test_unhardened_weak_store() {
        use super::super::settings::PolicyState;
        let dir = TempDir::new("weak");
        std::fs::write(PolicyFiles::policy_path(&dir.0), APPROVED_POLICY).unwrap();
        let stores = test_support::MemoryStores::new(false, true);
        stores.weak.lock().record = Some(test_support::record_of(&dir.0, 1, &[]));
        let unhardened =
            PolicyFiles::new(dir.0.clone(), false, test_support::stores(stores.clone()));
        assert_eq!(
            unhardened.load().await.unwrap().state,
            PolicyState::Approved
        );
        let hardened = PolicyFiles::new(dir.0.clone(), true, test_support::stores(stores.clone()));
        assert_eq!(
            hardened.load().await.unwrap().state,
            PolicyState::Unapproved
        );
    }

    #[tokio::test]
    async fn test_directory_is_unreadable() {
        let dir = TempDir::new("dir");
        std::fs::create_dir(PolicyFiles::policy_path(&dir.0)).unwrap();
        let stores = test_support::MemoryStores::new(true, true);
        let v = files(&dir, &stores).load().await.unwrap();
        assert_eq!(v.notes(), vec!["ignored policy.cedar: not a regular file"]);
    }
}
