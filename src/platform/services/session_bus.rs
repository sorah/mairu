//! How the helper's Linux backends reach the user's session bus. Any same-user process can claim names on it, so
//! every reply is untrusted.

/// `$DBUS_SESSION_BUS_ADDRESS` on an unhardened helper, otherwise `$XDG_RUNTIME_DIR/bus`.
pub fn default_address() -> Result<String, String> {
    default_address_for(
        crate::hardening::Hardening::marker().is_some(),
        std::env::var("DBUS_SESSION_BUS_ADDRESS").ok(),
        runtime_dir(),
    )
}

fn runtime_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|d| !d.is_empty())
        .map(std::path::PathBuf::from)
}

fn default_address_for(
    hardened: bool,
    env: Option<String>,
    runtime_dir: Option<std::path::PathBuf>,
) -> Result<String, String> {
    if !hardened && let Some(address) = env.filter(|a| !a.is_empty()) {
        return Ok(address);
    }
    let socket = runtime_dir.ok_or("XDG_RUNTIME_DIR is not set")?.join("bus");
    if !socket.exists() {
        return Err(format!("no session bus at {}", socket.display()));
    }
    Ok(format!("unix:path={}", socket.display()))
}

/// The session bus a client's request is delivered on, and the display it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub address: Result<String, String>,
    pub display: Option<String>,
    pub wayland_display: Option<String>,
    /// Why the hint's own bus address was not used.
    pub ignored_hint: Option<String>,
}

impl Target {
    /// Refuses a hint of SSH without a display, or of no display at all, so that nothing appears in another
    /// session.
    pub fn for_hint(hint: &crate::proto::platform::SessionHint) -> Result<Self, String> {
        Self::for_hint_in(
            hint,
            runtime_dir().as_deref(),
            nix::unistd::geteuid().as_raw(),
            default_address,
        )
    }

    fn for_hint_in(
        hint: &crate::proto::platform::SessionHint,
        runtime_dir: Option<&std::path::Path>,
        uid: u32,
        default: impl FnOnce() -> Result<String, String>,
    ) -> Result<Self, String> {
        if let Some(refusal) = hint.refusal() {
            return Err(refusal.to_owned());
        }
        let (address, ignored_hint) = if hint.dbus_session_bus_address.is_empty() {
            (default(), None)
        } else {
            match hint_address(&hint.dbus_session_bus_address, runtime_dir, uid) {
                Ok(a) => (Ok(a), None),
                Err(e) => (default(), Some(e)),
            }
        };
        Ok(Self {
            address,
            display: display_value(&hint.display),
            wayland_display: display_value(&hint.wayland_display),
            ignored_hint,
        })
    }

    pub async fn connect(&self) -> Result<zbus::Connection, String> {
        let address = self.address.as_ref().map_err(Clone::clone)?;
        zbus::connection::Builder::address(address.as_str())
            .build()
            .await
            .map_err(|e| format!("cannot connect to the session bus: {e}"))
    }
}

/// A hint's address is honored only as `unix:path=` naming a socket of this uid under `$XDG_RUNTIME_DIR`, so that
/// it cannot point the helper at an arbitrary socket or a TCP address.
fn hint_address(
    address: &str,
    runtime_dir: Option<&std::path::Path>,
    uid: u32,
) -> Result<String, String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let refuse = |why: &str| Err(format!("session bus address {address:?} {why}"));
    let Some(rest) = address.strip_prefix("unix:path=") else {
        return refuse("is not unix:path=");
    };
    let mut parts = rest.split(',');
    let path = parts.next().unwrap_or_default();
    if parts.any(|p| !p.starts_with("guid=")) || rest.contains(';') {
        return refuse("has unsupported parts");
    }
    // D-Bus escapes would let the path differ from what is checked here.
    if path.contains('%') {
        return refuse("has escaped characters");
    }
    let Some(runtime_dir) = runtime_dir else {
        return refuse("cannot be checked without XDG_RUNTIME_DIR");
    };
    let canonical = std::fs::canonicalize(path).map_err(|e| format!("{path}: {e}"))?;
    let root = std::fs::canonicalize(runtime_dir)
        .map_err(|e| format!("{}: {e}", runtime_dir.display()))?;
    if !canonical.starts_with(&root) {
        return refuse(&format!("is not under {}", runtime_dir.display()));
    }
    let meta = std::fs::symlink_metadata(&canonical).map_err(|e| format!("{path}: {e}"))?;
    if !meta.file_type().is_socket() {
        return refuse("is not a socket");
    }
    if meta.uid() != uid {
        return refuse(&format!("is owned by uid {}", meta.uid()));
    }
    Ok(format!("unix:path={}", canonical.display()))
}

/// `DISPLAY` and `WAYLAND_DISPLAY` values, as passed to `xdg-open`.
fn display_value(value: &str) -> Option<String> {
    let ok = !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".:/_-".contains(&b));
    ok.then(|| value.to_owned())
}

/// Whether a name is owned or can be activated on the bus, without activating it.
pub async fn name_available(conn: &zbus::Connection, name: &'static str) -> Result<bool, String> {
    let dbus = zbus::fdo::DBusProxy::new(conn)
        .await
        .map_err(|e| e.to_string())?;
    let wk = zbus::names::WellKnownName::from_static_str_unchecked(name);
    if dbus
        .name_has_owner(wk.into())
        .await
        .map_err(|e| e.to_string())?
    {
        return Ok(true);
    }
    let activatable = dbus
        .list_activatable_names()
        .await
        .map_err(|e| e.to_string())?;
    Ok(activatable.iter().any(|n| n.as_str() == name))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "mairu-test-session-bus-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn uid() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    fn hint(display: &str, address: &str) -> crate::proto::platform::SessionHint {
        crate::proto::platform::SessionHint {
            display: display.to_owned(),
            wayland_display: String::new(),
            dbus_session_bus_address: address.to_owned(),
            ssh: false,
        }
    }

    #[test]
    fn test_default_address() {
        let root = TempDir::new("default");
        let env = Some("unix:path=/tmp/fake".to_owned());
        assert_eq!(
            default_address_for(false, env.clone(), None).unwrap(),
            "unix:path=/tmp/fake"
        );
        assert!(default_address_for(true, env.clone(), Some(root.0.clone())).is_err());
        std::fs::write(root.0.join("bus"), b"").unwrap();
        assert_eq!(
            default_address_for(true, env, Some(root.0.clone())).unwrap(),
            format!("unix:path={}/bus", root.0.display())
        );
        assert!(default_address_for(true, None, None).is_err());
    }

    #[test]
    fn test_hint_address_socket_under_runtime_dir() {
        let root = TempDir::new("socket");
        let socket = root.0.join("bus");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let canonical = std::fs::canonicalize(&socket).unwrap();
        let address = format!("unix:path={}", socket.display());
        assert_eq!(
            hint_address(&address, Some(&root.0), uid()).unwrap(),
            format!("unix:path={}", canonical.display())
        );
        assert!(hint_address(&format!("{address},guid=0123abcd"), Some(&root.0), uid()).is_ok());
        assert!(
            hint_address(&address, Some(&root.0), uid() + 1)
                .unwrap_err()
                .contains("owned by")
        );
        assert!(hint_address(&address, None, uid()).is_err());
    }

    #[test]
    fn test_hint_address_refusals() {
        let root = TempDir::new("refusals");
        let other = TempDir::new("refusals-other");
        let socket = other.0.join("bus");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let file = root.0.join("file");
        std::fs::write(&file, b"").unwrap();
        let link = root.0.join("link");
        std::os::unix::fs::symlink(&socket, &link).unwrap();
        let refused = |address: String| hint_address(&address, Some(&root.0), uid()).is_err();
        assert!(refused("tcp:host=127.0.0.1,port=1234".to_owned()));
        assert!(refused("unix:abstract=/tmp/dbus-x".to_owned()));
        assert!(refused(format!("unix:path={}", socket.display())));
        assert!(refused(format!("unix:path={}", link.display())));
        assert!(refused(format!("unix:path={}", file.display())));
        assert!(refused(format!(
            "unix:path={}/../{}/bus",
            root.0.display(),
            other.0.file_name().unwrap().to_string_lossy()
        )));
        assert!(refused(format!("unix:path={}%2fbus", root.0.display())));
        assert!(refused(format!(
            "unix:path={},noncefile=/x",
            file.display()
        )));
        assert!(refused(format!(
            "unix:path={};tcp:host=127.0.0.1,port=1",
            file.display()
        )));
    }

    #[test]
    fn test_target_for_hint() {
        let root = TempDir::new("target");
        let default = || Ok("unix:path=/default".to_owned());
        let target = Target::for_hint_in(&hint(":0", ""), Some(&root.0), uid(), default).unwrap();
        assert_eq!(target.address.as_deref(), Ok("unix:path=/default"));
        assert_eq!(target.display.as_deref(), Some(":0"));
        assert_eq!(target.ignored_hint, None);

        let target = Target::for_hint_in(
            &hint(":0", "tcp:host=example.com,port=1"),
            Some(&root.0),
            uid(),
            default,
        )
        .unwrap();
        assert_eq!(target.address.as_deref(), Ok("unix:path=/default"));
        assert!(target.ignored_hint.is_some());

        let socket = root.0.join("bus");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let address = format!("unix:path={}", socket.display());
        let target =
            Target::for_hint_in(&hint(":0", &address), Some(&root.0), uid(), default).unwrap();
        assert_eq!(
            target.address.unwrap(),
            format!(
                "unix:path={}",
                std::fs::canonicalize(&socket).unwrap().display()
            )
        );

        let mut ssh = hint("", &address);
        ssh.ssh = true;
        assert!(Target::for_hint_in(&ssh, Some(&root.0), uid(), default).is_err());
        assert!(Target::for_hint_in(&hint("", ""), Some(&root.0), uid(), default).is_err());
    }

    #[test]
    fn test_display_value() {
        assert_eq!(display_value(":0").as_deref(), Some(":0"));
        assert_eq!(
            display_value("localhost:10.0").as_deref(),
            Some("localhost:10.0")
        );
        assert_eq!(display_value("wayland-1").as_deref(), Some("wayland-1"));
        assert_eq!(display_value(""), None);
        assert_eq!(display_value(":0 $(id)"), None);
        assert_eq!(display_value(&"a".repeat(300)), None);
    }
}
