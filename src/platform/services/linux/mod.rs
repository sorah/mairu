//! Linux services: authorization through polkit, and integrity records in the protected directory and Secret
//! Service. The other services are those of `FallbackServices`.

pub mod integrity;
pub mod polkit;

#[derive(Debug)]
pub struct LinuxServices;

static STORES: std::sync::LazyLock<integrity::Stores> = std::sync::LazyLock::new(Default::default);

#[async_trait::async_trait]
impl crate::platform::PlatformServices for LinuxServices {
    async fn capabilities(&self) -> crate::proto::platform::Capabilities {
        let mut caps = crate::platform::services::fallback::FallbackServices
            .capabilities()
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
        crate::platform::services::fallback::FallbackServices
            .notify(req)
            .await
    }

    async fn open_url(
        &self,
        req: crate::proto::platform::OpenUrlRequest,
    ) -> crate::proto::platform::OpenUrlResponse {
        crate::platform::services::fallback::FallbackServices
            .open_url(req)
            .await
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
