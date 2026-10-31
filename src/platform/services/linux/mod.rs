//! Linux services: authorization through polkit, integrity records in the protected directory and Secret
//! Service, and notifications and opening URLs on the client's session bus.

pub mod integrity;
pub mod notify;
pub mod open_url;
pub mod polkit;

#[derive(Debug)]
pub struct LinuxServices;

static STORES: std::sync::LazyLock<integrity::Stores> = std::sync::LazyLock::new(Default::default);

#[async_trait::async_trait]
impl crate::platform::PlatformServices for LinuxServices {
    async fn capabilities(
        &self,
        req: crate::proto::platform::GetCapabilitiesRequest,
    ) -> crate::proto::platform::Capabilities {
        let mut caps = crate::platform::services::fallback::FallbackServices
            .capabilities(Default::default())
            .await;
        caps.notes.clear();
        caps.integrity_stores = STORES
            .available()
            .await
            .into_iter()
            .map(Into::into)
            .collect();
        match polkit::Authority::probe().await {
            Ok(()) => {
                caps.authorization = crate::proto::platform::AuthorizationFacility::Polkit.into();
            }
            Err(u) => {
                caps.authorization = crate::proto::platform::AuthorizationFacility::None.into();
                caps.notes
                    .push(format!("polkit unavailable: {}: {}", u.reason, u.detail));
            }
        }
        caps.notifications = false;
        caps.open_url = false;
        if let Some(session) = &req.session {
            match crate::platform::services::session_bus::Target::for_hint(session) {
                Err(e) => caps
                    .notes
                    .push(format!("notifications and open_url disabled: {e}")),
                Ok(target) => {
                    if let Some(ignored) = &target.ignored_hint {
                        caps.notes.push(format!("ignored the client's {ignored}"));
                    }
                    if let Err(e) = &target.address {
                        caps.notes.push(format!("session bus unreachable: {e}"));
                    }
                    match notify::available(&target).await {
                        Ok(()) => caps.notifications = true,
                        Err(e) => caps.notes.push(format!("notifications unavailable: {e}")),
                    }
                    match open_url::available(&target).await {
                        Ok(()) => caps.open_url = true,
                        Err(e) => caps.notes.push(format!("open_url unavailable: {e}")),
                    }
                }
            }
        }
        caps
    }

    async fn authorize(
        &self,
        req: crate::proto::platform::AuthorizeRequest,
    ) -> crate::proto::platform::AuthorizeResponse {
        polkit::authorize(req).await
    }

    async fn notify(
        &self,
        req: crate::proto::platform::NotifyRequest,
    ) -> crate::proto::platform::NotifyResponse {
        notify::notify(req).await
    }

    async fn open_url(
        &self,
        req: crate::proto::platform::OpenUrlRequest,
    ) -> crate::proto::platform::OpenUrlResponse {
        open_url::open_url(req).await
    }

    async fn record_integrity(
        &self,
        req: crate::proto::platform::RecordIntegrityRequest,
    ) -> crate::proto::platform::RecordIntegrityResponse {
        STORES.record(req).await
    }

    async fn verify_integrity(
        &self,
        req: crate::proto::platform::VerifyIntegrityRequest,
    ) -> crate::proto::platform::VerifyIntegrityResponse {
        STORES.verify(req).await
    }
}
