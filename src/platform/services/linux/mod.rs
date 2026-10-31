//! Linux services: authorization through polkit. The other services are those of `FallbackServices`.

pub mod polkit;

#[derive(Debug)]
pub struct LinuxServices;

#[async_trait::async_trait]
impl crate::platform::PlatformServices for LinuxServices {
    async fn capabilities(&self) -> crate::proto::platform::Capabilities {
        let mut caps = crate::platform::services::fallback::FallbackServices
            .capabilities()
            .await;
        caps.notes.clear();
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
        crate::platform::services::fallback::FallbackServices
            .record_integrity(req)
            .await
    }

    async fn verify_integrity(
        &self,
        req: crate::proto::platform::VerifyIntegrityRequest,
    ) -> crate::proto::platform::VerifyIntegrityResponse {
        crate::platform::services::fallback::FallbackServices
            .verify_integrity(req)
            .await
    }
}
