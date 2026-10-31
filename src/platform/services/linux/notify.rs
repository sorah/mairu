//! Desktop notifications through `org.freedesktop.Notifications` on the client's session bus.

const NAME: &str = "org.freedesktop.Notifications";
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: std::collections::HashMap<&str, zbus::Variant<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;
}

/// Whether a notification daemon is running or can be activated on the target's bus.
pub async fn available(
    target: &crate::platform::services::session_bus::Target,
) -> Result<(), String> {
    let run = async {
        let conn = target.connect().await?;
        match crate::platform::services::session_bus::name_available(&conn, NAME).await? {
            true => Ok(()),
            false => Err(format!(
                "no notification daemon ({NAME}) on the session bus"
            )),
        }
    };
    tokio::time::timeout(TIMEOUT, run)
        .await
        .unwrap_or_else(|_| Err("the session bus did not answer in time".to_owned()))
}

pub async fn notify(
    mut req: crate::proto::platform::NotifyRequest,
) -> crate::proto::platform::NotifyResponse {
    req.truncate();
    let target = match req
        .session
        .as_ref()
        .ok_or_else(|| "no session hint".to_owned())
        .and_then(crate::platform::services::session_bus::Target::for_hint)
    {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!(
                event = req.event,
                reason = e,
                "Not delivering a notification"
            );
            return crate::proto::platform::NotifyResponse { delivered: false };
        }
    };
    if let Some(ignored) = &target.ignored_hint {
        tracing::info!(reason = ignored, "Ignoring the session hint's bus address");
    }
    match tokio::time::timeout(TIMEOUT, deliver(&target, &req)).await {
        Ok(Ok(id)) => {
            tracing::debug!(event = req.event, id, "Delivered a notification");
            crate::proto::platform::NotifyResponse { delivered: true }
        }
        Ok(Err(e)) => {
            tracing::debug!(
                event = req.event,
                err = e,
                "Failed to deliver a notification"
            );
            crate::proto::platform::NotifyResponse { delivered: false }
        }
        Err(_) => {
            tracing::debug!(
                event = req.event,
                "The notification daemon did not answer in time"
            );
            crate::proto::platform::NotifyResponse { delivered: false }
        }
    }
}

async fn deliver(
    target: &crate::platform::services::session_bus::Target,
    req: &crate::proto::platform::NotifyRequest,
) -> Result<u32, String> {
    let conn = target.connect().await?;
    let proxy = NotificationsProxy::builder(&conn)
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
        .map_err(|e| e.to_string())?;
    let mut hints = std::collections::HashMap::new();
    hints.insert("urgency", zbus::Variant::from(urgency_byte(req.urgency())));
    proxy
        .notify("mairu", 0, "", &req.title, &req.body, &[], hints, -1)
        .await
        .map_err(|e| format!("Notify: {e}"))
}

/// The `urgency` hint of the Desktop Notifications Specification.
fn urgency_byte(urgency: crate::proto::platform::notify_request::Urgency) -> u8 {
    use crate::proto::platform::notify_request::Urgency;
    match urgency {
        Urgency::Low => 0,
        Urgency::Unspecified | Urgency::Normal => 1,
        Urgency::Critical => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_urgency_byte() {
        use crate::proto::platform::notify_request::Urgency;
        assert_eq!(urgency_byte(Urgency::Low), 0);
        assert_eq!(urgency_byte(Urgency::Unspecified), 1);
        assert_eq!(urgency_byte(Urgency::Normal), 1);
        assert_eq!(urgency_byte(Urgency::Critical), 2);
    }

    /// A session bus from `dbus-daemon`, when installed.
    struct TestBus {
        child: std::process::Child,
        dir: std::path::PathBuf,
        address: String,
    }

    impl TestBus {
        async fn start(name: &str) -> Option<Self> {
            let dir = std::env::temp_dir()
                .join(format!("mairu-test-notify-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let socket = dir.join("bus");
            let address = format!("unix:path={}", socket.display());
            // No service directories, so nothing on the host can be activated.
            let config = dir.join("bus.conf");
            std::fs::write(
                &config,
                format!(
                    "<busconfig><type>session</type><listen>{address}</listen>\
                     <policy context=\"default\"><allow send_destination=\"*\"/><allow receive_sender=\"*\"/><allow own=\"*\"/></policy>\
                     </busconfig>"
                ),
            )
            .unwrap();
            let child = match std::process::Command::new("dbus-daemon")
                .arg(format!("--config-file={}", config.display()))
                .args(["--nofork", "--nopidfile"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("skipping: dbus-daemon: {e}");
                    return None;
                }
            };
            let bus = Self {
                child,
                dir,
                address,
            };
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            while !socket.exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "dbus-daemon did not start"
                );
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Some(bus)
        }

        fn target(&self) -> crate::platform::services::session_bus::Target {
            crate::platform::services::session_bus::Target {
                address: Ok(self.address.clone()),
                display: Some(":0".to_owned()),
                wayland_display: None,
                ignored_hint: None,
            }
        }
    }

    impl Drop for TestBus {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    type Received = std::sync::Arc<std::sync::Mutex<Vec<(String, String, String, Option<u8>)>>>;

    struct StubDaemon(Received);

    #[zbus::interface(name = "org.freedesktop.Notifications")]
    impl StubDaemon {
        #[allow(clippy::too_many_arguments)]
        fn notify(
            &self,
            app_name: String,
            _replaces_id: u32,
            _app_icon: String,
            summary: String,
            body: String,
            _actions: Vec<String>,
            hints: std::collections::HashMap<String, zbus::OwnedVariant>,
            _expire_timeout: i32,
        ) -> u32 {
            let urgency = hints
                .get("urgency")
                .and_then(|v| u8::try_from(v.clone()).ok());
            self.0
                .lock()
                .unwrap()
                .push((app_name, summary, body, urgency));
            42
        }
    }

    #[tokio::test]
    async fn test_stub_notification_daemon() {
        let Some(bus) = TestBus::start("stub").await else {
            return;
        };
        let target = bus.target();
        let err = available(&target).await.unwrap_err();
        assert!(err.contains("no notification daemon"), "{err}");

        let received = Received::default();
        let _daemon = zbus::connection::Builder::address(bus.address.as_str())
            .name(NAME)
            .serve_at(
                "/org/freedesktop/Notifications",
                StubDaemon(received.clone()),
            )
            .build()
            .await
            .unwrap();
        available(&target).await.unwrap();
        let req = crate::proto::platform::NotifyRequest {
            title: "mairu: login required".to_owned(),
            body: "b".repeat(2000),
            urgency: crate::proto::platform::notify_request::Urgency::Critical.into(),
            event: "login-required".to_owned(),
            session: None,
        };
        let mut truncated = req.clone();
        truncated.truncate();
        assert_eq!(deliver(&target, &truncated).await, Ok(42));
        let received = received.lock().unwrap().clone();
        assert_eq!(
            received,
            vec![(
                "mairu".to_owned(),
                "mairu: login required".to_owned(),
                "b".repeat(crate::proto::platform::MAX_NOTIFICATION_BODY),
                Some(2)
            )]
        );
    }

    #[tokio::test]
    async fn test_refused_hint_is_not_delivered() {
        let req = crate::proto::platform::NotifyRequest {
            title: "t".to_owned(),
            session: Some(crate::proto::platform::SessionHint {
                ssh: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!notify(req).await.delivered);
        assert!(!notify(Default::default()).await.delivered);
    }
}
