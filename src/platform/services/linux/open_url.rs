//! Opening URLs through the desktop portal's `OpenURI` on the client's session bus, falling back to `xdg-open`.

const PORTAL_NAME: &str = "org.freedesktop.portal.Desktop";
const XDG_OPEN: &str = "xdg-open";
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[zbus::proxy(
    interface = "org.freedesktop.portal.OpenURI",
    default_service = "org.freedesktop.portal.Desktop",
    default_path = "/org/freedesktop/portal/desktop"
)]
trait OpenUri {
    #[zbus(name = "OpenURI")]
    fn open_uri(
        &self,
        parent_window: &str,
        uri: &str,
        options: std::collections::HashMap<&str, zbus::Variant<'_>>,
    ) -> zbus::Result<zbus::OwnedObjectPath>;
}

/// Whether the portal is on the target's bus, or `xdg-open` is on `PATH`.
pub async fn available(
    target: &crate::platform::services::session_bus::Target,
) -> Result<(), String> {
    let portal = async {
        let conn = target.connect().await?;
        match crate::platform::services::session_bus::name_available(&conn, PORTAL_NAME).await? {
            true => Ok(()),
            false => Err(format!("no desktop portal ({PORTAL_NAME})")),
        }
    };
    let portal = tokio::time::timeout(TIMEOUT, portal)
        .await
        .unwrap_or_else(|_| Err("the session bus did not answer in time".to_owned()));
    match portal {
        Ok(()) => Ok(()),
        Err(e) if find_xdg_open().is_some() => {
            tracing::trace!(err = e, "Falling back to xdg-open");
            Ok(())
        }
        Err(e) => Err(format!("{e}, and no {XDG_OPEN} on PATH")),
    }
}

pub async fn open_url(
    req: crate::proto::platform::OpenUrlRequest,
) -> crate::proto::platform::OpenUrlResponse {
    let url = match req.checked_url() {
        Ok(u) => u,
        Err(detail) => return crate::proto::platform::OpenUrlResponse::failed(detail),
    };
    let target = match req
        .session
        .as_ref()
        .ok_or_else(|| "no session hint".to_owned())
        .and_then(crate::platform::services::session_bus::Target::for_hint)
    {
        Ok(t) => t,
        Err(e) => return crate::proto::platform::OpenUrlResponse::failed(e),
    };
    if let Some(ignored) = &target.ignored_hint {
        tracing::info!(reason = ignored, "Ignoring the session hint's bus address");
    }
    let portal = tokio::time::timeout(TIMEOUT, open_with_portal(&target, &url))
        .await
        .unwrap_or_else(|_| Err("the desktop portal did not answer in time".to_owned()));
    let portal_err = match portal {
        Ok(()) => {
            tracing::debug!("Opened a URL through the desktop portal");
            return crate::proto::platform::OpenUrlResponse {
                opened: true,
                detail: "desktop portal".to_owned(),
            };
        }
        Err(e) => e,
    };
    tracing::debug!(
        err = portal_err,
        "The desktop portal failed; trying xdg-open"
    );
    match open_with_xdg_open(&target, &url).await {
        Ok(()) => crate::proto::platform::OpenUrlResponse {
            opened: true,
            detail: XDG_OPEN.to_owned(),
        },
        Err(e) => crate::proto::platform::OpenUrlResponse::failed(format!("{portal_err}; {e}")),
    }
}

async fn open_with_portal(
    target: &crate::platform::services::session_bus::Target,
    url: &url::Url,
) -> Result<(), String> {
    let conn = target.connect().await?;
    let proxy = OpenUriProxy::builder(&conn)
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
        .map_err(|e| e.to_string())?;
    proxy
        .open_uri("", url.as_str(), Default::default())
        .await
        .map(|_| ())
        .map_err(|e| format!("OpenURI: {e}"))
}

fn find_xdg_open() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(XDG_OPEN))
        .find(|p| p.is_file())
}

/// Waits at most [`TIMEOUT`]; a browser started by `xdg-open` may keep it running, so that counts as opened.
async fn open_with_xdg_open(
    target: &crate::platform::services::session_bus::Target,
    url: &url::Url,
) -> Result<(), String> {
    let program = find_xdg_open().ok_or_else(|| format!("no {XDG_OPEN} on PATH"))?;
    let mut cmd = crate::hardening::command(&program);
    cmd.arg(url.as_str())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY");
    if let Some(display) = &target.display {
        cmd.env("DISPLAY", display);
    }
    if let Some(display) = &target.wayland_display {
        cmd.env("WAYLAND_DISPLAY", display);
    }
    match &target.address {
        Ok(address) => cmd.env("DBUS_SESSION_BUS_ADDRESS", address),
        Err(_) => cmd.env_remove("DBUS_SESSION_BUS_ADDRESS"),
    };
    let mut child = tokio::process::Command::from(cmd)
        .spawn()
        .map_err(|e| format!("failed to run {}: {e}", program.display()))?;
    match tokio::time::timeout(TIMEOUT, child.wait()).await {
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(format!("{} exited with {status}", program.display())),
        Ok(Err(e)) => Err(format!("{}: {e}", program.display())),
        Err(_) => {
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_refusals() {
        let session = Some(crate::proto::platform::SessionHint {
            display: ":0".to_owned(),
            ..Default::default()
        });
        let resp = open_url(crate::proto::platform::OpenUrlRequest {
            url: "file:///etc/passwd".to_owned(),
            session: session.clone(),
        })
        .await;
        assert!(!resp.opened);
        assert!(resp.detail.contains("file:"), "{}", resp.detail);

        let resp = open_url(crate::proto::platform::OpenUrlRequest {
            url: "https://example.com/".to_owned(),
            session: Some(crate::proto::platform::SessionHint {
                ssh: true,
                ..Default::default()
            }),
        })
        .await;
        assert!(!resp.opened);
        assert!(resp.detail.contains("SSH"), "{}", resp.detail);
    }
}
