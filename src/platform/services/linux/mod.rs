//! Linux services: authorization through polkit, integrity records in the protected directory and Secret
//! Service, notifications and opening URLs on the client's session bus, and on WSL2 opening URLs in the Windows
//! browser.

pub mod integrity;
pub mod notify;
pub mod open_url;
pub mod polkit;
pub mod wsl;

/// On WSL2, WSLg's display never selects a Linux-side `open_url` backend.
fn wsl2_interop() -> Option<crate::platform::process::linux::wsl::Interop> {
    match crate::platform::process::linux::wsl::Wsl::detect() {
        Some(crate::platform::process::linux::wsl::Wsl::Wsl2 { interop }) => Some(interop),
        _ => None,
    }
}

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
        let Some(session) = &req.session else {
            return caps;
        };
        let wsl2 = wsl2_interop();
        let target = crate::platform::services::session_bus::Target::for_hint(session);
        match (&target, wsl2) {
            (Err(e), None) => caps
                .notes
                .push(format!("notifications and open_url disabled: {e}")),
            (Err(e), Some(_)) => caps.notes.push(format!("notifications unavailable: {e}")),
            (Ok(target), _) => {
                if let Some(ignored) = &target.ignored_hint {
                    caps.notes.push(format!("ignored the client's {ignored}"));
                }
                if let Err(e) = &target.address {
                    caps.notes.push(format!("session bus unreachable: {e}"));
                }
                match notify::available(target).await {
                    Ok(()) => caps.notifications = true,
                    Err(e) => caps.notes.push(format!("notifications unavailable: {e}")),
                }
            }
        }
        let open_url = match (&target, wsl2) {
            (_, Some(interop)) => Some(wsl::available(session, interop).await),
            (Ok(target), None) => Some(open_url::available(target).await),
            (Err(_), None) => None,
        };
        match open_url {
            Some(Ok(())) => caps.open_url = true,
            Some(Err(e)) => caps.notes.push(format!("open_url unavailable: {e}")),
            None => {}
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
        match wsl2_interop() {
            Some(interop) => wsl::open_url(req, interop).await,
            None => open_url::open_url(req).await,
        }
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
