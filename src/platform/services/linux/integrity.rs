//! Integrity stores on Linux: the protected directory under `/var/lib/mairu` (strong) and an item in the default
//! Secret Service collection (weak).

const SECRET_SERVICE_NAME: &str = "org.freedesktop.secrets";
const APPLICATION: &str = "co.0w0.mairu";
const SECRET_SERVICE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

type StoreResult = crate::proto::platform::IntegrityStoreResult;

fn result(
    store: crate::proto::platform::IntegrityStoreKind,
    status: crate::proto::platform::IntegrityStatus,
    detail: impl Into<String>,
    stored: Option<crate::proto::platform::IntegrityRecord>,
) -> StoreResult {
    StoreResult {
        store: store.into(),
        status: status.into(),
        detail: detail.into(),
        stored,
    }
}

/// What a store holds for a name, compared with `digest`.
fn compare(
    store: crate::proto::platform::IntegrityStoreKind,
    held: Result<Option<Vec<u8>>, String>,
    digest: &[u8],
) -> StoreResult {
    use crate::proto::platform::IntegrityStatus as S;
    match held {
        Err(e) => result(store, S::Unavailable, e, None),
        Ok(None) => result(store, S::NotRecorded, "", None),
        Ok(Some(bytes)) => match crate::proto::platform::IntegrityRecord::from_json(&bytes) {
            // An unreadable record still disagrees with the files.
            Err(e) => result(store, S::Mismatched, format!("invalid record: {e}"), None),
            Ok(record) if record.digest == digest => result(store, S::Matched, "", Some(record)),
            Ok(record) => result(store, S::Mismatched, "", Some(record)),
        },
    }
}

/// `/var/lib/mairu/users/<uid>/<name>.record`, reachable only with the marker gid.
#[derive(Debug)]
pub struct ProtectedDirectory {
    root: std::path::PathBuf,
}

impl Default for ProtectedDirectory {
    fn default() -> Self {
        Self {
            root: crate::platform::integrity::PROTECTED_DIRECTORY.into(),
        }
    }
}

impl ProtectedDirectory {
    const KIND: crate::proto::platform::IntegrityStoreKind =
        crate::proto::platform::IntegrityStoreKind::ProtectedDirectory;

    /// Usable only by a hardened helper, and only when `/var/lib/mairu` and its `users` are `root:mairu` without
    /// "other" bits on a local filesystem.
    pub fn available(&self) -> Result<(), String> {
        let marker = crate::hardening::Hardening::marker()
            .ok_or("the helper is not hardened")?
            .as_raw();
        crate::hardening::with_privileged_gid(|| Ok(self.check_dirs(marker)))
            .map_err(|e| e.to_string())?
    }

    fn check_dirs(&self, marker: u32) -> Result<(), String> {
        for dir in [self.root.clone(), self.root.join("users")] {
            let meta =
                std::fs::symlink_metadata(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            check_dir_meta(&dir, &meta, marker)?;
        }
        let fs = nix::sys::statfs::statfs(&self.root)
            .map_err(|e| format!("{}: {e}", self.root.display()))?;
        if fs.filesystem_type() == nix::sys::statfs::FUSE_SUPER_MAGIC {
            return Err(format!("{} is on a FUSE filesystem", self.root.display()));
        }
        Ok(())
    }

    pub fn verify(&self, uid: u32, name: &str, digest: &[u8]) -> StoreResult {
        let held = self.available().and_then(|()| {
            crate::hardening::with_privileged_gid(|| Ok(read_record(&self.root, uid, name)))
                .map_err(|e| e.to_string())?
        });
        compare(Self::KIND, held, digest)
    }

    pub fn record(&self, uid: u32, name: &str, json: &str) -> StoreResult {
        use crate::proto::platform::IntegrityStatus as S;
        if let Err(e) = self.available() {
            return result(Self::KIND, S::Unavailable, e, None);
        }
        let written = crate::hardening::with_privileged_gid(|| {
            Ok(write_record(&self.root, uid, name, json.as_bytes()))
        })
        .map_err(|e| e.to_string())
        .and_then(|r| r);
        match written {
            Ok(()) => result(Self::KIND, S::Matched, "", None),
            Err(e) => result(
                Self::KIND,
                S::Unavailable,
                format!("write failed: {e}"),
                None,
            ),
        }
    }
}

fn check_dir_meta(
    dir: &std::path::Path,
    meta: &std::fs::Metadata,
    marker: u32,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    if meta.uid() != 0 || meta.gid() != marker {
        return Err(format!(
            "{} is owned by {}:{}, not root:{}",
            dir.display(),
            meta.uid(),
            meta.gid(),
            crate::hardening::MARKER_GROUP_NAME
        ));
    }
    if meta.mode() & 0o007 != 0 {
        return Err(format!(
            "{} has permissions for others (mode {:04o})",
            dir.display(),
            meta.mode() & 0o7777
        ));
    }
    Ok(())
}

/// The user's directory, when it is a real directory of this uid.
fn user_directory(root: &std::path::Path, uid: u32) -> Result<Option<std::path::PathBuf>, String> {
    use std::os::unix::fs::MetadataExt;
    let dir = crate::platform::integrity::user_directory(root, uid);
    match std::fs::symlink_metadata(&dir) {
        Ok(meta) if meta.is_dir() && meta.uid() == uid => Ok(Some(dir)),
        Ok(_) => Err(format!(
            "{} is not a directory owned by uid {uid}",
            dir.display()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", dir.display())),
    }
}

fn read_record(root: &std::path::Path, uid: u32, name: &str) -> Result<Option<Vec<u8>>, String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    if user_directory(root, uid)?.is_none() {
        return Ok(None);
    }
    let path = crate::platform::integrity::record_path(root, uid, name);
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let mut bytes = vec![];
    file.take(crate::platform::integrity::MAX_RECORD_SIZE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Some(bytes))
}

/// Temp file, fsync, rename, fsync of the directory: a reader sees the old record or the new one.
fn write_record(root: &std::path::Path, uid: u32, name: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    let dir = match user_directory(root, uid)? {
        Some(dir) => dir,
        None => {
            let dir = crate::platform::integrity::user_directory(root, uid);
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
            // Drops the setgid bit inherited from `users`.
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("{}: {e}", dir.display()))?;
            user_directory(root, uid)?.ok_or("the user directory vanished")?
        }
    };
    let path = crate::platform::integrity::record_path(root, uid, name);
    let tmp = dir.join(format!(".{name}.record.tmp"));
    let io = |e: std::io::Error| format!("{}: {e}", tmp.display());
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    drop(file);
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    std::fs::File::open(&dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("{}: {e}", dir.display()))
}

#[derive(Debug, serde::Serialize, serde::Deserialize, zbus::Type)]
struct Secret {
    session: zbus::OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Service",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets"
)]
trait SecretService {
    fn open_session(
        &self,
        algorithm: &str,
        input: &zbus::Variant<'_>,
    ) -> zbus::Result<(zbus::OwnedVariant, zbus::OwnedObjectPath)>;

    fn read_alias(&self, name: &str) -> zbus::Result<zbus::OwnedObjectPath>;

    fn get_secrets(
        &self,
        items: &[zbus::OwnedObjectPath],
        session: &zbus::ObjectPath<'_>,
    ) -> zbus::Result<std::collections::HashMap<zbus::OwnedObjectPath, Secret>>;
}

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Collection",
    default_service = "org.freedesktop.secrets"
)]
trait SecretCollection {
    fn search_items(
        &self,
        attributes: &std::collections::HashMap<&str, &str>,
    ) -> zbus::Result<Vec<zbus::OwnedObjectPath>>;

    fn create_item(
        &self,
        properties: std::collections::HashMap<&str, zbus::Variant<'_>>,
        secret: &Secret,
        replace: bool,
    ) -> zbus::Result<(zbus::OwnedObjectPath, zbus::OwnedObjectPath)>;

    #[zbus(property)]
    fn locked(&self) -> zbus::Result<bool>;
}

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Session",
    default_service = "org.freedesktop.secrets"
)]
trait SecretSession {
    fn close(&self) -> zbus::Result<()>;
}

/// The default collection, unlocked, with a plain-transfer session. The record is not secret, so nothing is
/// encrypted in transit.
struct Keyring {
    service: SecretServiceProxy<'static>,
    collection: SecretCollectionProxy<'static>,
    session: zbus::OwnedObjectPath,
    conn: zbus::Connection,
}

impl Keyring {
    async fn open() -> Result<Self, String> {
        let address = crate::platform::services::session_bus::default_address()?;
        let conn = zbus::connection::Builder::address(address.as_str())
            .build()
            .await
            .map_err(|e| format!("cannot connect to the session bus: {e}"))?;
        let dbus = zbus::fdo::DBusProxy::new(&conn)
            .await
            .map_err(|e| e.to_string())?;
        let name = zbus::names::WellKnownName::from_static_str_unchecked(SECRET_SERVICE_NAME);
        // Never activates a keyring daemon, which could then ask to unlock.
        if !dbus
            .name_has_owner(name.into())
            .await
            .map_err(|e| e.to_string())?
        {
            return Err(format!("{SECRET_SERVICE_NAME} is not running"));
        }
        let service = SecretServiceProxy::builder(&conn)
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await
            .map_err(|e| e.to_string())?;
        let default = service
            .read_alias("default")
            .await
            .map_err(|e| format!("ReadAlias: {e}"))?;
        if default.as_str() == "/" {
            return Err("there is no default collection".to_owned());
        }
        let collection = SecretCollectionProxy::builder(&conn)
            .path(default)
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await
            .map_err(|e| e.to_string())?;
        if collection
            .locked()
            .await
            .map_err(|e| format!("Locked: {e}"))?
        {
            return Err("the default collection is locked".to_owned());
        }
        let (_, session) = service
            .open_session("plain", &zbus::Variant::from(""))
            .await
            .map_err(|e| format!("OpenSession: {e}"))?;
        Ok(Self {
            service,
            collection,
            session,
            conn,
        })
    }

    async fn close(self) {
        if let Ok(proxy) = SecretSessionProxy::builder(&self.conn)
            .path(self.session.clone())
            .build()
            .await
        {
            let _ = proxy.close().await;
        }
    }

    async fn read(&self, attributes: &Attributes) -> Result<Option<Vec<u8>>, String> {
        let items = self
            .collection
            .search_items(&attributes.as_map())
            .await
            .map_err(|e| format!("SearchItems: {e}"))?;
        if items.is_empty() {
            return Ok(None);
        }
        let mut secrets = self
            .service
            .get_secrets(&items, &self.session.as_ref())
            .await
            .map_err(|e| format!("GetSecrets: {e}"))?;
        let mut values = items
            .iter()
            .filter_map(|i| secrets.remove(i).map(|s| s.value));
        let first = values.next().ok_or("the item is locked")?;
        if values.any(|v| v != first) {
            return Err(format!("{} items disagree", items.len()));
        }
        Ok(Some(first))
    }

    async fn write(&self, attributes: &Attributes, json: &str) -> Result<(), String> {
        let mut properties = std::collections::HashMap::new();
        properties.insert(
            "org.freedesktop.Secret.Item.Label",
            zbus::Variant::from(attributes.label()),
        );
        properties.insert(
            "org.freedesktop.Secret.Item.Attributes",
            zbus::Variant::from(attributes.as_map()),
        );
        let secret = Secret {
            session: self.session.clone(),
            parameters: vec![],
            value: json.as_bytes().to_vec(),
            content_type: "application/json".to_owned(),
        };
        let (_, prompt) = self
            .collection
            .create_item(properties, &secret, true)
            .await
            .map_err(|e| format!("CreateItem: {e}"))?;
        if prompt.as_str() != "/" {
            return Err("the keyring asked for a prompt, which mairu never answers".to_owned());
        }
        Ok(())
    }
}

/// The item's attributes: `{application, kind, name, uid}`.
struct Attributes {
    name: String,
    uid: String,
}

impl Attributes {
    fn new(uid: u32, name: &str) -> Self {
        Self {
            name: name.to_owned(),
            uid: uid.to_string(),
        }
    }

    fn as_map(&self) -> std::collections::HashMap<&str, &str> {
        [
            ("application", APPLICATION),
            ("kind", "policy-record"),
            ("name", self.name.as_str()),
            ("uid", self.uid.as_str()),
        ]
        .into()
    }

    fn label(&self) -> String {
        format!("mairu {} record (uid {})", self.name, self.uid)
    }
}

/// The item in the default Secret Service collection. Same-user code can read and rewrite it.
#[derive(Debug, Default)]
pub struct SecretService;

impl SecretService {
    const KIND: crate::proto::platform::IntegrityStoreKind =
        crate::proto::platform::IntegrityStoreKind::SecretService;

    async fn with_keyring<T>(
        f: impl AsyncFnOnce(&Keyring) -> Result<T, String>,
    ) -> Result<T, String> {
        let run = async {
            let keyring = Keyring::open().await?;
            let retval = f(&keyring).await;
            keyring.close().await;
            retval
        };
        tokio::time::timeout(SECRET_SERVICE_TIMEOUT, run)
            .await
            .unwrap_or_else(|_| Err("the Secret Service did not answer in time".to_owned()))
    }

    pub async fn available(&self) -> Result<(), String> {
        Self::with_keyring(async |_| Ok(())).await
    }

    pub async fn verify(&self, uid: u32, name: &str, digest: &[u8]) -> StoreResult {
        let attributes = Attributes::new(uid, name);
        let held = Self::with_keyring(async |k| k.read(&attributes).await).await;
        compare(Self::KIND, held, digest)
    }

    pub async fn record(&self, uid: u32, name: &str, json: &str) -> StoreResult {
        use crate::proto::platform::IntegrityStatus as S;
        let attributes = Attributes::new(uid, name);
        match Self::with_keyring(async |k| k.write(&attributes, json).await).await {
            Ok(()) => result(Self::KIND, S::Matched, "", None),
            Err(e) => result(Self::KIND, S::Unavailable, e, None),
        }
    }
}

/// Both stores, in authority order.
#[derive(Debug, Default)]
pub struct Stores {
    pub protected_directory: ProtectedDirectory,
    pub secret_service: SecretService,
}

impl Stores {
    pub async fn available(&self) -> Vec<crate::proto::platform::IntegrityStoreKind> {
        let mut kinds = vec![];
        if self.protected_directory.available().is_ok() {
            kinds.push(ProtectedDirectory::KIND);
        }
        if self.secret_service.available().await.is_ok() {
            kinds.push(SecretService::KIND);
        }
        kinds
    }

    pub async fn verify(
        &self,
        req: crate::proto::platform::VerifyIntegrityRequest,
    ) -> crate::proto::platform::VerifyIntegrityResponse {
        if !crate::platform::integrity::valid_name(&req.name) {
            return crate::proto::platform::VerifyIntegrityResponse { results: vec![] };
        }
        let results = vec![
            self.protected_directory
                .verify(req.uid, &req.name, &req.digest),
            self.secret_service
                .verify(req.uid, &req.name, &req.digest)
                .await,
        ];
        crate::proto::platform::VerifyIntegrityResponse { results }
    }

    pub async fn record(
        &self,
        req: crate::proto::platform::RecordIntegrityRequest,
    ) -> crate::proto::platform::RecordIntegrityResponse {
        let Some(record) = req.record.as_ref() else {
            return crate::proto::platform::RecordIntegrityResponse { results: vec![] };
        };
        if !crate::platform::integrity::valid_name(&req.name) {
            return crate::proto::platform::RecordIntegrityResponse { results: vec![] };
        }
        let json = record.to_json();
        let wanted = |kind: crate::proto::platform::IntegrityStoreKind| {
            req.stores.is_empty() || req.stores.contains(&(kind as i32))
        };
        let mut results = vec![];
        if wanted(ProtectedDirectory::KIND) {
            results.push(self.protected_directory.record(req.uid, &req.name, &json));
        }
        if wanted(SecretService::KIND) {
            results.push(self.secret_service.record(req.uid, &req.name, &json).await);
        }
        tracing::info!(
            name = req.name,
            generation = record.generation,
            results = ?results.iter().map(|r| (r.store(), r.status(), r.detail.as_str())).collect::<Vec<_>>(),
            "Recorded integrity"
        );
        crate::proto::platform::RecordIntegrityResponse { results }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::platform::IntegrityStatus as S;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "mairu-test-integrity-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(path.join("users")).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn record(digest: u8) -> crate::proto::platform::IntegrityRecord {
        crate::proto::platform::IntegrityRecord {
            digest: vec![digest; 32],
            approval: Some(Default::default()),
            generation: 3,
            server_digests: Default::default(),
        }
    }

    #[test]
    fn test_write_and_read_record() {
        use std::os::unix::fs::PermissionsExt;
        let root = TempDir::new("rw");
        let uid = nix::unistd::geteuid().as_raw();
        let kind = ProtectedDirectory::KIND;
        assert_eq!(
            compare(kind, read_record(&root.0, uid, "policy"), &[1; 32]).status(),
            S::NotRecorded
        );
        write_record(&root.0, uid, "policy", record(1).to_json().as_bytes()).unwrap();
        let dir = crate::platform::integrity::user_directory(&root.0, uid);
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let path = crate::platform::integrity::record_path(&root.0, uid, "policy");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let matched = compare(kind, read_record(&root.0, uid, "policy"), &[1; 32]);
        assert_eq!(matched.status(), S::Matched);
        assert_eq!(matched.stored, Some(record(1)));
        assert_eq!(
            compare(kind, read_record(&root.0, uid, "policy"), &[2; 32]).status(),
            S::Mismatched
        );
        // Overwrites in place.
        write_record(&root.0, uid, "policy", record(2).to_json().as_bytes()).unwrap();
        assert_eq!(
            compare(kind, read_record(&root.0, uid, "policy"), &[2; 32]).status(),
            S::Matched
        );
        assert_eq!(
            compare(kind, read_record(&root.0, uid, "policy-dev"), &[2; 32]).status(),
            S::NotRecorded
        );
        std::fs::write(&path, b"junk").unwrap();
        assert_eq!(
            compare(kind, read_record(&root.0, uid, "policy"), &[2; 32]).status(),
            S::Mismatched
        );
    }

    #[test]
    fn test_record_symlink_refused() {
        let root = TempDir::new("symlink");
        let uid = nix::unistd::geteuid().as_raw();
        let dir = crate::platform::integrity::user_directory(&root.0, uid);
        std::fs::create_dir(&dir).unwrap();
        std::os::unix::fs::symlink(
            "/etc/passwd",
            crate::platform::integrity::record_path(&root.0, uid, "policy"),
        )
        .unwrap();
        assert!(read_record(&root.0, uid, "policy").is_err());

        let other = TempDir::new("symlink-dir");
        std::os::unix::fs::symlink(
            &root.0,
            crate::platform::integrity::user_directory(&other.0, uid),
        )
        .unwrap();
        assert!(read_record(&other.0, uid, "policy").is_err());
        assert!(write_record(&other.0, uid, "policy", b"{}").is_err());
    }

    #[test]
    fn test_check_dir_meta() {
        let root = TempDir::new("meta");
        let meta = std::fs::metadata(&root.0).unwrap();
        // Owned by the test user, not root.
        assert!(
            check_dir_meta(&root.0, &meta, 0)
                .unwrap_err()
                .contains("not root")
        );
        let file = root.0.join("file");
        std::fs::write(&file, b"").unwrap();
        let meta = std::fs::metadata(&file).unwrap();
        assert!(
            check_dir_meta(&file, &meta, 0)
                .unwrap_err()
                .contains("not a directory")
        );
    }

    #[test]
    fn test_unhardened_protected_directory_is_unavailable() {
        let store = ProtectedDirectory::default();
        assert!(store.available().is_err());
        assert_eq!(
            store.verify(1000, "policy", &[0; 32]).status(),
            S::Unavailable
        );
        assert_eq!(store.record(1000, "policy", "{}").status(), S::Unavailable);
    }
}
