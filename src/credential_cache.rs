#[derive(Debug, Clone)]
pub struct CachedCredential {
    pub rolespec: crate::proto::Rolespec,
    pub credentials: std::sync::Arc<crate::client::AssumeRoleResponse>,
}

/// Per-server credential cache
#[derive(Clone)]
pub struct CredentialCache {
    items: std::sync::Arc<
        std::sync::RwLock<std::collections::HashMap<crate::proto::Rolespec, CachedCredential>>,
    >,
}

impl std::fmt::Debug for CredentialCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialCache").finish()
    }
}

/// If a cached credential is being expired after this duration, then discard a cache instead
/// of returning it. Aligned to the minimum session duration permitted at sts:AssumeRole.
const RENEW_CREDENTIALS_BEFORE_SEC: i64 = 900;

impl CredentialCache {
    pub fn new() -> Self {
        Self {
            items: std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    pub fn clear(&self) {
        let mut items = self.items.write().unwrap();
        items.clear();
    }

    pub fn store(
        &self,
        rolespec: crate::proto::Rolespec,
        credentials: &crate::client::AssumeRoleResponse,
    ) {
        if credentials.mairu.no_cache {
            return;
        }

        let mut items = self.items.write().unwrap();
        let item = CachedCredential {
            rolespec: rolespec.clone(),
            credentials: std::sync::Arc::new(credentials.to_owned()),
        };
        items.insert(rolespec, item);
    }

    pub fn get(&self, rolespec: &crate::proto::Rolespec) -> Option<CachedCredential> {
        let items = self.items.read().unwrap();
        items
            .get(rolespec)
            .filter(|v| {
                let now = chrono::Utc::now();
                let thres = chrono::Duration::seconds(RENEW_CREDENTIALS_BEFORE_SEC);
                let result = now < (v.credentials.expiration - thres);
                if !result {
                    tracing::debug!(cached_credential = ?v, "cached entry hit, but not using as it's being expired");
                }
                result
            })
            .cloned()
    }
}

impl Default for CredentialCache {
    fn default() -> Self {
        Self::new()
    }
}
