//! `policy.cedar` and `authorization.json` in `config_dir()`, read by the agent itself, and what is in force for
//! them.

pub const SETTINGS_FILE_NAME: &str = "authorization.json";

/// Files are re-read after this even when their metadata looks unchanged.
const TTL: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_FILE_SIZE: u64 = 1024 * 1024;

/// The policy and settings in force for one state of the files.
#[derive(Debug)]
pub struct Effective {
    pub engine: super::Engine,
    pub settings: super::settings::EffectiveSettings,
    pub labels: Vec<crate::tool_detection::ToolLabel>,
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
            settings,
            state: super::settings::PolicyState::Absent,
            notes: vec![],
        }
    }

    /// Unapproved content contributes only what tightens: the `forbid` policies that validate, label additions and
    /// a shorter grant retention.
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
        let schema = super::schema()?;
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
                ("sts", s.sts.is_some()),
                ("network", s.network.is_some()),
            ]
            .into_iter()
            .filter_map(|(name, set)| set.then_some(name))
            .collect();
            if !ignored.is_empty() {
                notes.push(format!(
                    "ignored {} of {SETTINGS_FILE_NAME} while it is unapproved",
                    ignored.join(", ")
                ));
            }
        }
        let settings = super::settings::EffectiveSettings::effective(state, file_settings.as_ref());
        Ok(Self {
            engine: super::Engine::with_user_policies(hardened, &forbids)?,
            labels: settings.labels(),
            settings,
            state,
            notes,
        })
    }
}

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
    effective: Result<std::sync::Arc<Effective>, String>,
}

/// The effective policy, re-read when the files' metadata changes and at least every 5 seconds.
#[derive(Debug)]
pub struct PolicyFiles {
    source: Source,
    cache: parking_lot::Mutex<Option<Cached>>,
}

#[derive(Debug)]
enum Source {
    Dir {
        dir: std::path::PathBuf,
        hardened: bool,
        ttl: std::time::Duration,
    },
    Fixed(std::sync::Arc<Effective>),
}

impl PolicyFiles {
    pub fn new(dir: std::path::PathBuf, hardened: bool) -> Self {
        Self {
            source: Source::Dir {
                dir,
                hardened,
                ttl: TTL,
            },
            cache: Default::default(),
        }
    }

    /// Always `effective`, whatever the files say.
    pub fn fixed(effective: Effective) -> Self {
        Self {
            source: Source::Fixed(std::sync::Arc::new(effective)),
            cache: Default::default(),
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

    /// The effective policy now. An error means not even the built-ins could be built.
    pub fn load(&self) -> Result<std::sync::Arc<Effective>, String> {
        let (dir, hardened, ttl) = match &self.source {
            Source::Fixed(effective) => return Ok(effective.clone()),
            Source::Dir { dir, hardened, ttl } => (dir, *hardened, *ttl),
        };
        let policy_path = Self::policy_path(dir);
        let settings_path = Self::settings_path(dir);
        let mut cache = self.cache.lock();
        if let Some(cached) = cache.as_ref()
            && cached.loaded_at.elapsed() < ttl
            && cached.keys == [Key::stat(&policy_path), Key::stat(&settings_path)]
        {
            return cached.effective.clone();
        }
        let (policy_key, policy) = read(&policy_path);
        let (settings_key, settings) = read(&settings_path);
        let changed = cache.as_ref().is_none_or(|c| {
            c.keys != [policy_key.clone(), settings_key.clone()] || c.effective.is_err()
        });
        let effective = Effective::build(hardened, &policy, &settings)
            .map(std::sync::Arc::new)
            .map_err(|e| e.to_string());
        match &effective {
            Ok(e) if changed => tracing::info!(
                state = e.state.as_str(),
                policies = ?e.engine.policy_ids(),
                notes = ?e.notes,
                "Authorization policy loaded"
            ),
            Ok(_) => {}
            Err(e) => tracing::error!(err = e, "Failed to build the authorization policy"),
        }
        *cache = Some(Cached {
            keys: [policy_key, settings_key],
            loaded_at: std::time::Instant::now(),
            effective: effective.clone(),
        });
        effective
    }

    #[cfg(test)]
    fn with_ttl(dir: std::path::PathBuf, hardened: bool, ttl: std::time::Duration) -> Self {
        Self {
            source: Source::Dir { dir, hardened, ttl },
            cache: Default::default(),
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

    #[test]
    fn test_cache() {
        let dir = TempDir::new("cache");
        let files = PolicyFiles::new(dir.0.clone(), true);
        let path = PolicyFiles::policy_path(&dir.0);
        let has = |files: &PolicyFiles, id: &str| {
            files
                .load()
                .unwrap()
                .engine
                .policy_ids()
                .contains(&id.to_owned())
        };
        assert!(!has(&files, "aaaa"));
        assert_eq!(
            files.load().unwrap().state,
            super::super::settings::PolicyState::Absent
        );

        std::fs::write(
            &path,
            r#"@id("aaaa") forbid (principal, action, resource);"#,
        )
        .unwrap();
        // A changed (dev, ino, mtime, size) is seen at once.
        assert!(has(&files, "aaaa"));

        // An edit that keeps every key is seen only after the TTL.
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        let rewrite = || {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            f.write_all(br#"@id("bbbb") forbid (principal, action, resource);"#)
                .unwrap();
            f.set_modified(mtime).unwrap();
        };
        rewrite();
        assert!(has(&files, "aaaa"));
        let files = PolicyFiles::with_ttl(dir.0.clone(), true, std::time::Duration::ZERO);
        assert!(has(&files, "bbbb"));

        std::fs::remove_file(&path).unwrap();
        assert!(!has(&files, "bbbb"));
    }

    #[test]
    fn test_ttl_reload() {
        let dir = TempDir::new("ttl");
        let path = PolicyFiles::policy_path(&dir.0);
        std::fs::write(
            &path,
            r#"@id("aaaa") forbid (principal, action, resource);"#,
        )
        .unwrap();
        let files = PolicyFiles::with_ttl(dir.0.clone(), true, std::time::Duration::from_secs(1));
        assert!(
            files
                .load()
                .unwrap()
                .engine
                .policy_ids()
                .contains(&"aaaa".to_owned())
        );
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
        assert!(
            files
                .load()
                .unwrap()
                .engine
                .policy_ids()
                .contains(&"aaaa".to_owned())
        );
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(
            files
                .load()
                .unwrap()
                .engine
                .policy_ids()
                .contains(&"bbbb".to_owned())
        );
    }

    #[test]
    fn test_directory_is_unreadable() {
        let dir = TempDir::new("dir");
        std::fs::create_dir(PolicyFiles::policy_path(&dir.0)).unwrap();
        let e = PolicyFiles::new(dir.0.clone(), true).load().unwrap();
        assert_eq!(e.notes, vec!["ignored policy.cedar: not a regular file"]);
    }
}
