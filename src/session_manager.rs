#[derive(Debug, Clone)]
pub struct Session {
    pub id: u32,
    pub token: std::sync::Arc<crate::token::ServerToken>,
    pub credential_cache: crate::credential_cache::CredentialCache,
}

impl Session {
    #[inline]
    pub fn server(&self) -> &crate::config::Server {
        // TODO: utilize this more
        &self.token.server
    }
}

impl From<&Session> for crate::proto::Session {
    fn from(item: &Session) -> crate::proto::Session {
        crate::proto::Session {
            id: item.id,
            server_id: item.token.server.id().to_owned(),
            server_url: item.token.server.url.to_string(),
            expires_at: item
                .token
                .expires_at
                .map(|t| std::time::SystemTime::from(t).into()),
            refreshable: item.token.refresh_token.is_some(),
        }
    }
}

#[derive(Clone)]
pub struct SessionManager {
    items: std::sync::Arc<parking_lot::RwLock<Vec<Session>>>,
    next_id: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

const MAX_ITEMS: u64 = 4294967295; // u32::MAX

impl SessionManager {
    pub fn new() -> Self {
        Self {
            items: std::sync::Arc::new(parking_lot::RwLock::new(Vec::new())),
            next_id: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    pub fn list(&self) -> Vec<Session> {
        let items = self.items.read();
        let mut result = Vec::with_capacity(items.len());
        for item in items.iter() {
            result.push(item.clone());
        }
        result
    }

    pub fn get(&self, query: &str) -> crate::Result<Session> {
        tracing::trace!(query = ?query, "Attempting to get");
        let items = self.items.read();
        let mut candidate = None;
        for (i, item) in items.iter().enumerate() {
            if query == item.token.server.id() {
                tracing::trace!(token = ?item.token, "Providing a token");
                return Ok(item.clone());
            }
            if query == item.token.server.url.as_str() {
                if candidate.is_some() {
                    return Err(crate::Error::UserError(format!(
                        "Server URL '{}' is ambiguous; Use id to specify",
                        query
                    )));
                }
                candidate = Some(i);
            }
        }
        if let Some(i) = candidate {
            tracing::trace!(token = ?items[i].token, "Providing a token");
            return Ok(items[i].clone());
        }
        Err(crate::Error::UserError(
            "specified server not found or not logged in".to_owned(),
        ))
    }

    pub fn add(&self, token: crate::token::ServerToken) -> crate::Result<Session> {
        tracing::trace!(token = ?token, "Attempting to add");
        let mut items = self.items.write();

        // Update if a token for the same server exists
        if let Some(i) = find_item_for_update(&items, &token) {
            let item = items.get_mut(i).unwrap();
            tracing::info!(token = ?token, id = ?item.id, "Storing updated token");
            item.token = std::sync::Arc::new(token);
            item.credential_cache.clear();
            return Ok(item.clone());
        }

        // Otherwise, add as a new server
        if u64::try_from(items.len()).unwrap() == MAX_ITEMS {
            // unlikely to happen but to prevent from having dupe ids
            tracing::error!("too many server tokens to hold");
            return Err(crate::Error::AuthError(
                "too many server tokens to hold".to_owned(),
            ));
        }
        for item in items.iter() {
            if item.token.server.id() == token.server.id() {
                tracing::warn!(token = ?token, "Rejecting due to a duplicate with the existing server token");
                return Err(crate::Error::AuthError(format!(
                    "Server is duplicate or ambiguous ({}); If server id is unspecified, then specify .id in a configuration. If you have changed configuration file name for the server, then remove a existing token from agent first",
                    token.server.id()
                )));
            }
        }

        tracing::info!(token = ?token, "Storing new token");
        let session = Session {
            id: self
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            token: std::sync::Arc::new(token),
            credential_cache: crate::credential_cache::CredentialCache::new(),
        };
        let retval = session.clone();
        items.push(session);

        Ok(retval)
    }

    pub fn remove(&self, query: &str) -> bool {
        use std::str::FromStr;
        let id = u32::from_str(query).ok();

        tracing::trace!(query = ?query, "Attempting to remove");
        let mut items = self.items.write();
        for (i, item) in items.iter().enumerate() {
            if id == Some(item.id)
                || query == item.token.server.id()
                || query == item.token.server.url.as_str()
            {
                tracing::info!(token = ?item.token, "Discarding a token");
                items.remove(i);
                return true;
            }
        }
        false
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

fn find_item_for_update(items: &[Session], token: &crate::token::ServerToken) -> Option<usize> {
    for (i, item) in items.iter().enumerate() {
        if item.token.server.config_path() == token.server.config_path()
            && item.token.server.id() == token.server.id()
            && item.token.server.url == token.server.url
        {
            return Some(i);
        }
    }
    None
}
