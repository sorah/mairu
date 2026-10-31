#[derive(Debug, Clone)]
pub struct CachedCredential {
    pub rolespec: crate::proto::Rolespec,
    pub credentials: std::sync::Arc<crate::client::AssumeRoleResponse>,
    /// Who the credentials belong to, once asked; a hardened agent asks before vending them.
    pub caller: Option<crate::caller_identity::Caller>,
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
        credentials: std::sync::Arc<crate::client::AssumeRoleResponse>,
        caller: Option<crate::caller_identity::Caller>,
    ) {
        if credentials.mairu.no_cache {
            return;
        }

        let mut items = self.items.write().unwrap();
        let item = CachedCredential {
            rolespec: rolespec.clone(),
            credentials,
            caller,
        };
        items.insert(rolespec, item);
    }

    /// Records the caller of a cached entry, if it still holds the same credentials.
    pub fn set_caller(
        &self,
        rolespec: &crate::proto::Rolespec,
        credentials: &std::sync::Arc<crate::client::AssumeRoleResponse>,
        caller: crate::caller_identity::Caller,
    ) {
        let mut items = self.items.write().unwrap();
        if let Some(item) = items.get_mut(rolespec)
            && std::sync::Arc::ptr_eq(&item.credentials, credentials)
        {
            item.caller = Some(caller);
        }
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
