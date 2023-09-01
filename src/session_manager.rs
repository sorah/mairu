#[derive(Debug)]
struct Session {
    id: u32,
    token: std::sync::Arc<crate::token::ServerToken>,
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
        }
    }
}

#[derive(Clone)]
pub struct SessionManager {
    items: std::sync::Arc<std::sync::RwLock<Vec<Session>>>,
    next_id: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

const MAX_ITEMS: u64 = 4294967295; // u32::MAX

impl SessionManager {
    pub fn new() -> Self {
        Self {
            items: std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
            next_id: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    pub fn list(&self) -> Vec<crate::proto::Session> {
        let items = self.items.read().unwrap();
        let mut result = Vec::with_capacity(items.len());
        for item in items.iter() {
            result.push(item.into());
        }
        result
    }

    pub fn get(&self, query: &str) -> crate::Result<std::sync::Arc<crate::token::ServerToken>> {
        tracing::trace!(query = ?query, "Attempting to get");
        let items = self.items.read().unwrap();
        let mut candidate = None;
        for (i, item) in items.iter().enumerate() {
            if query == item.token.server.id() {
                tracing::info!(token = ?item.token, "Providing a token");
                return Ok(item.token.clone());
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
            tracing::info!(token = ?items[i].token, "Providing a token");
            return Ok(items[i].token.clone());
        }
        Err(crate::Error::UserError(
            "specified server not found".to_owned(),
        ))
    }

    pub fn add(&self, token: crate::token::ServerToken) -> crate::Result<()> {
        tracing::trace!(token = ?token, "Attempting to add");
        let mut items = self.items.write().unwrap();

        // Update if a token for the same server exists
        if let Some(i) = find_item_for_update(&items, &token) {
            let item = items.get_mut(i).unwrap();
            tracing::info!(token = ?token, id = ?item.id, "Storing updated token");
            item.token = std::sync::Arc::new(token);
            return Ok(());
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
                return Err(crate::Error::AuthError(format!("Server is duplicate or ambiguous ({}); If server id is unspecified, then specify .id in a configuration. If you have changed configuration file name for the server, then remove a existing token from agent first", token.server.id())));
            }
        }

        tracing::info!(token = ?token, "Storing new token");
        items.push(Session {
            id: self
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            token: std::sync::Arc::new(token),
        });

        Ok(())
    }

    pub fn remove(&self, query: &str) -> bool {
        use std::str::FromStr;
        let id = u32::from_str(query).ok();

        tracing::trace!(query = ?query, "Attempting to remove");
        let mut items = self.items.write().unwrap();
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
        if item.token.server.config_path == token.server.config_path
            && item.token.server.id() == token.server.id()
            && item.token.server.url == token.server.url
        {
            return Some(i);
        }
    }
    None
}
