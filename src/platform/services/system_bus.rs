//! How the helper's Linux backends reach services on the system bus.

/// The system bus socket a hardened helper connects to, regardless of the environment.
pub const PINNED_SOCKET: &str = "/run/dbus/system_bus_socket";

/// `AuthorizeResponse.reason` for a bus or authority that is not owned by root.
pub const REASON_UNTRUSTED_AUTHORITY: &str = "untrusted-authority";

/// A system bus or authority on it that the helper must not trust.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("untrusted authority: {0}")]
pub struct UntrustedAuthority(pub String);

impl UntrustedAuthority {
    pub fn into_authorize_response(self) -> crate::proto::platform::AuthorizeResponse {
        crate::proto::platform::AuthorizeResponse::unavailable(REASON_UNTRUSTED_AUTHORITY, self.0)
    }
}

/// The D-Bus address of the system bus. `DBUS_SYSTEM_BUS_ADDRESS` is attacker-controllable environment, so a
/// hardened helper ignores it and connects to [`PINNED_SOCKET`].
pub fn address() -> Result<String, UntrustedAuthority> {
    let hardened = crate::hardening::Hardening::marker().is_some();
    let env = std::env::var("DBUS_SYSTEM_BUS_ADDRESS").ok();
    address_for(hardened, env, std::path::Path::new(PINNED_SOCKET))
}

fn address_for(
    hardened: bool,
    env: Option<String>,
    socket: &std::path::Path,
) -> Result<String, UntrustedAuthority> {
    if !hardened {
        return Ok(env.unwrap_or_else(|| format!("unix:path={}", socket.display())));
    }
    let dir = socket.parent().ok_or_else(|| {
        UntrustedAuthority(format!("{} has no parent directory", socket.display()))
    })?;
    check_socket_dir(dir)?;
    Ok(format!("unix:path={}", socket.display()))
}

/// The directory holding the system bus socket must be a root-owned directory that only root can write to.
pub fn check_socket_dir(dir: &std::path::Path) -> Result<(), UntrustedAuthority> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(dir)
        .map_err(|e| UntrustedAuthority(format!("{}: {e}", dir.display())))?;
    if !meta.is_dir() {
        return Err(UntrustedAuthority(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    if meta.uid() != 0 {
        return Err(UntrustedAuthority(format!(
            "{} is owned by uid {}, not root",
            dir.display(),
            meta.uid()
        )));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(UntrustedAuthority(format!(
            "{} is writable by group or others (mode {:o})",
            dir.display(),
            meta.mode() & 0o7777
        )));
    }
    Ok(())
}

/// The owner of an authority's well-known name, from `org.freedesktop.DBus.GetConnectionUnixUser`, must be root.
pub fn check_authority_owner(name: &str, owner_uid: u32) -> Result<(), UntrustedAuthority> {
    if owner_uid != 0 {
        return Err(UntrustedAuthority(format!(
            "{name} is owned by uid {owner_uid}, not root"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_unhardened_honors_env() {
        let socket = std::path::Path::new(PINNED_SOCKET);
        assert_eq!(
            address_for(false, Some("unix:path=/tmp/fake".to_owned()), socket).unwrap(),
            "unix:path=/tmp/fake"
        );
        assert_eq!(
            address_for(false, None, socket).unwrap(),
            "unix:path=/run/dbus/system_bus_socket"
        );
    }

    #[test]
    fn test_address_hardened_ignores_env() {
        let socket = std::path::Path::new("/bus_socket");
        assert_eq!(
            address_for(true, Some("unix:path=/tmp/fake".to_owned()), socket).unwrap(),
            "unix:path=/bus_socket"
        );
    }

    #[test]
    fn test_address_hardened_refuses_writable_dir() {
        // The temporary directory is world-writable or owned by the user.
        let socket = std::env::temp_dir().join("bus_socket");
        assert!(address_for(true, None, &socket).is_err());
    }

    #[test]
    fn test_check_socket_dir_missing() {
        assert!(check_socket_dir(std::path::Path::new("/nonexistent-mairu-test")).is_err());
    }

    #[test]
    fn test_check_authority_owner() {
        assert!(check_authority_owner("org.freedesktop.PolicyKit1", 0).is_ok());
        let resp = check_authority_owner("org.freedesktop.PolicyKit1", 1000)
            .unwrap_err()
            .into_authorize_response();
        assert_eq!(
            resp.result(),
            crate::proto::platform::authorize_response::Result::Unavailable
        );
        assert_eq!(resp.reason, REASON_UNTRUSTED_AUTHORITY);
    }
}
