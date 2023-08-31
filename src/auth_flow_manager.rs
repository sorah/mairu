pub const MAX_ITEMS: usize = 15;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum AuthFlow {
    Nop,
    OAuthCode(crate::oauth_code::OAuthCodeFlow),
}

impl AuthFlow {
    pub fn handle(&self) -> &str {
        match self {
            AuthFlow::Nop => "",
            AuthFlow::OAuthCode(f) => &f.handle,
        }
    }
}

#[derive(Clone)]
pub struct AuthFlowManager {
    list: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<AuthFlow>>>,
}

impl AuthFlowManager {
    pub fn new() -> Self {
        Self {
            list: std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
        }
    }

    pub fn store(&self, flow: AuthFlow) {
        let mut list = self.list.lock().unwrap();
        if list.len() == MAX_ITEMS {
            list.pop_front();
        }
        list.push_back(flow);
    }

    pub fn retrieve<'a>(&'a self, handle: &str) -> Option<AuthFlowRetrieval<'a>> {
        let mut cand = None;
        {
            let mut list = self.list.lock().unwrap();
            for (i, flow) in list.iter().enumerate() {
                if flow.handle() == handle {
                    cand = Some(list.swap_remove_front(i).unwrap());
                    break;
                }
            }
        }

        if let Some(item) = cand {
            return Some(AuthFlowRetrieval {
                inner: Some(item),
                manager: self,
            });
        }
        None
    }
}

impl Default for AuthFlowManager {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AuthFlowRetrieval<'a> {
    inner: Option<AuthFlow>,
    manager: &'a AuthFlowManager,
}

impl<'a> AuthFlowRetrieval<'a> {
    pub fn mark_as_done(mut self) {
        self.inner = None;
    }

    pub fn into_inner(mut self) -> AuthFlow {
        self.inner.take().unwrap()
    }
}

impl<'a> std::ops::Deref for AuthFlowRetrieval<'a> {
    type Target = AuthFlow;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap()
    }
}

impl<'a> std::convert::AsRef<AuthFlow> for AuthFlowRetrieval<'a> {
    fn as_ref(&self) -> &AuthFlow {
        self.inner.as_ref().unwrap()
    }
}

impl<'a> std::ops::Drop for AuthFlowRetrieval<'a> {
    fn drop(&mut self) {
        if let Some(x) = self.inner.take() {
            self.manager.store(x);
        }
    }
}
