pub const MAX_ITEMS: usize = 15;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum AuthFlow {
    Nop,
    OAuthCode(crate::oauth_code::OAuthCodeFlow),
    OAuthDeviceCode(crate::oauth_device_code::OAuthDeviceCodeFlow),
    AwsSsoDevice(crate::oauth_awssso_device_code::AwsSsoDeviceFlow),
    AwsSsoCode(crate::oauth_awssso_code::AwsSsoCodeFlow),
}

impl AuthFlow {
    pub fn handle(&self) -> &str {
        match self {
            AuthFlow::Nop => "",
            AuthFlow::OAuthCode(f) => &f.handle,
            AuthFlow::OAuthDeviceCode(f) => &f.handle,
            AuthFlow::AwsSsoDevice(f) => &f.handle,
            AuthFlow::AwsSsoCode(f) => &f.handle,
        }
    }
}

#[derive(Clone)]
pub struct AuthFlowManager {
    list: std::sync::Arc<parking_lot::Mutex<std::collections::VecDeque<AuthFlow>>>,
}

impl AuthFlowManager {
    pub fn new() -> Self {
        Self {
            list: std::sync::Arc::new(parking_lot::Mutex::new(std::collections::VecDeque::new())),
        }
    }

    pub fn store(&self, flow: AuthFlow) {
        let mut list = self.list.lock();
        if list.len() == MAX_ITEMS {
            let item = list.pop_front();
            tracing::warn!(discarded_flow = ?item, "Too many ongoing authentication flows, discarding the oldest one");
        }
        list.push_back(flow);
    }

    pub fn retrieve<'a>(&'a self, handle: &str) -> Option<AuthFlowRetrieval<'a>> {
        let mut cand = None;
        {
            let mut list = self.list.lock();
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

impl AuthFlowRetrieval<'_> {
    pub fn mark_as_done(mut self) {
        self.inner = None;
    }

    pub fn into_inner(mut self) -> AuthFlow {
        self.inner.take().unwrap()
    }
}

impl std::ops::Deref for AuthFlowRetrieval<'_> {
    type Target = AuthFlow;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap()
    }
}

impl std::convert::AsRef<AuthFlow> for AuthFlowRetrieval<'_> {
    fn as_ref(&self) -> &AuthFlow {
        self.inner.as_ref().unwrap()
    }
}

impl std::ops::Drop for AuthFlowRetrieval<'_> {
    fn drop(&mut self) {
        if let Some(x) = self.inner.take() {
            self.manager.store(x);
        }
    }
}
