//! Platforms and services without a backend: authorization is unavailable, and there are no integrity stores and
//! no notifications.

#[derive(Debug)]
pub struct FallbackServices;

/// `AuthorizeResponse.reason` when the OS has no authorization facility mairu can use.
pub const REASON_NO_FACILITY: &str = "no-authorization-facility";

#[async_trait::async_trait]
impl crate::platform::PlatformServices for FallbackServices {
    async fn capabilities(
        &self,
        _req: crate::proto::platform::GetCapabilitiesRequest,
    ) -> crate::proto::platform::Capabilities {
        let process = crate::platform::process();
        crate::proto::platform::Capabilities {
            peer_verification: process.peer_verification().into(),
            authorization: crate::proto::platform::AuthorizationFacility::None.into(),
            integrity_stores: vec![],
            notifications: false,
            open_url: cfg!(target_os = "macos"),
            notes: vec!["no platform service backends on this OS yet".to_owned()],
        }
    }

    async fn authorize(
        &self,
        _req: crate::proto::platform::AuthorizeRequest,
    ) -> crate::proto::platform::AuthorizeResponse {
        crate::proto::platform::AuthorizeResponse::unavailable(
            REASON_NO_FACILITY,
            "no authorization facility on this OS",
        )
    }

    async fn notify(
        &self,
        _req: crate::proto::platform::NotifyRequest,
    ) -> crate::proto::platform::NotifyResponse {
        crate::proto::platform::NotifyResponse { delivered: false }
    }

    async fn open_url(
        &self,
        req: crate::proto::platform::OpenUrlRequest,
    ) -> crate::proto::platform::OpenUrlResponse {
        open_url(req).await
    }

    async fn record_integrity(
        &self,
        _req: crate::proto::platform::RecordIntegrityRequest,
    ) -> crate::proto::platform::RecordIntegrityResponse {
        crate::proto::platform::RecordIntegrityResponse { results: vec![] }
    }

    async fn verify_integrity(
        &self,
        _req: crate::proto::platform::VerifyIntegrityRequest,
    ) -> crate::proto::platform::VerifyIntegrityResponse {
        crate::proto::platform::VerifyIntegrityResponse { results: vec![] }
    }
}

#[cfg(target_os = "macos")]
async fn open_url(
    req: crate::proto::platform::OpenUrlRequest,
) -> crate::proto::platform::OpenUrlResponse {
    let url = match req.checked_url() {
        Ok(u) => u,
        Err(detail) => return crate::proto::platform::OpenUrlResponse::failed(detail),
    };
    let status = tokio::task::spawn_blocking(move || {
        crate::hardening::command("/usr/bin/open")
            .arg(url.as_str())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
    })
    .await;
    match status {
        Ok(Ok(s)) if s.success() => crate::proto::platform::OpenUrlResponse {
            opened: true,
            detail: String::new(),
        },
        Ok(Ok(s)) => crate::proto::platform::OpenUrlResponse::failed(format!(
            "/usr/bin/open exited with {s}"
        )),
        Ok(Err(e)) => crate::proto::platform::OpenUrlResponse::failed(format!(
            "failed to run /usr/bin/open: {e}"
        )),
        Err(e) => crate::proto::platform::OpenUrlResponse::failed(e.to_string()),
    }
}

#[cfg(not(target_os = "macos"))]
async fn open_url(
    req: crate::proto::platform::OpenUrlRequest,
) -> crate::proto::platform::OpenUrlResponse {
    let detail = match req.checked_url() {
        Ok(_) => "opening URLs is not supported on this OS yet".to_owned(),
        Err(detail) => detail,
    };
    crate::proto::platform::OpenUrlResponse::failed(detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::PlatformServices;

    #[tokio::test]
    async fn test_fallback_fails_closed() {
        let resp = FallbackServices
            .authorize(crate::proto::platform::AuthorizeRequest::default())
            .await;
        assert_eq!(
            resp.result(),
            crate::proto::platform::authorize_response::Result::Unavailable
        );
        assert_eq!(resp.reason, REASON_NO_FACILITY);
        let verify = FallbackServices
            .verify_integrity(crate::proto::platform::VerifyIntegrityRequest::default())
            .await;
        assert!(verify.results.is_empty());
        let caps = FallbackServices.capabilities(Default::default()).await;
        assert_eq!(
            caps.authorization(),
            crate::proto::platform::AuthorizationFacility::None
        );
        assert!(caps.integrity_stores.is_empty());
        assert!(!caps.notifications);
    }
}
