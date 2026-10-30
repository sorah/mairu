//! `CheckAuthorization` against the polkit authority on the system bus.

pub const ACTION_ASSUME_ROLE: &str = "co.0w0.mairu.assume-role";
pub const ACTION_APPROVE_POLICY: &str = "co.0w0.mairu.approve-policy";

/// `AuthorizeResponse.reason` values of this backend.
pub const REASON_NO_AUTHENTICATION_AGENT: &str = "no-authentication-agent";
pub const REASON_ACTION_NOT_INSTALLED: &str = "polkit-action-not-installed";
pub const REASON_UNAVAILABLE: &str = "polkit-unavailable";
pub const REASON_TIMEOUT: &str = "timeout";

const AUTHORITY_NAME: &str = "org.freedesktop.PolicyKit1";
/// The system user distributions run polkitd as.
const AUTHORITY_USER: &str = "polkitd";
const CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Why the authority cannot be asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unavailable {
    pub reason: &'static str,
    pub detail: String,
}

impl Unavailable {
    fn new(reason: &'static str, detail: impl std::fmt::Display) -> Self {
        Self {
            reason,
            detail: detail.to_string(),
        }
    }

    fn into_response(self) -> crate::proto::platform::AuthorizeResponse {
        crate::proto::platform::AuthorizeResponse::unavailable(self.reason, self.detail)
    }
}

impl From<crate::platform::services::system_bus::UntrustedAuthority> for Unavailable {
    fn from(e: crate::platform::services::system_bus::UntrustedAuthority) -> Self {
        Self::new(
            crate::platform::services::system_bus::REASON_UNTRUSTED_AUTHORITY,
            e.0,
        )
    }
}

/// The authority, addressed by the unique name whose owner was checked, so that a later owner of the well-known
/// name is never asked.
pub struct Authority {
    proxy: zbus_polkit::policykit1::AuthorityProxy<'static>,
}

impl Authority {
    pub async fn connect() -> Result<Self, Unavailable> {
        tokio::time::timeout(CONNECT_TIMEOUT, Self::connect_inner())
            .await
            .unwrap_or_else(|_| {
                Err(Unavailable::new(
                    REASON_UNAVAILABLE,
                    "the system bus did not answer in time",
                ))
            })
    }

    /// Connects and checks the authority's owner.
    pub async fn probe() -> Result<(), Unavailable> {
        Self::connect().await.map(|_| ())
    }

    async fn connect_inner() -> Result<Self, Unavailable> {
        let unavailable = |what: &str, e: zbus::Error| {
            Unavailable::new(REASON_UNAVAILABLE, format!("{what}: {e}"))
        };
        let address = crate::platform::services::system_bus::address()?;
        let conn = zbus::connection::Builder::address(address.as_str())
            .build()
            .await
            .map_err(|e| unavailable(&format!("cannot connect to {address}"), e))?;
        let dbus = zbus::fdo::DBusProxy::new(&conn)
            .await
            .map_err(|e| unavailable("org.freedesktop.DBus", e))?;
        let name = zbus::names::WellKnownName::from_static_str_unchecked(AUTHORITY_NAME);
        let owner = match dbus.get_name_owner(name.clone().into()).await {
            Ok(owner) => owner,
            Err(_) => {
                // polkitd is usually bus-activated.
                dbus.start_service_by_name(name.clone(), 0)
                    .await
                    .map_err(|e| {
                        unavailable(&format!("cannot start {AUTHORITY_NAME}"), e.into())
                    })?;
                dbus.get_name_owner(name.into())
                    .await
                    .map_err(|e| unavailable(&format!("{AUTHORITY_NAME} has no owner"), e.into()))?
            }
        };
        let owner_uid = dbus
            .get_connection_unix_user(owner.as_ref().into())
            .await
            .map_err(|e| {
                unavailable(
                    &format!("cannot identify the owner of {AUTHORITY_NAME}"),
                    e.into(),
                )
            })?;
        crate::platform::services::system_bus::check_authority_owner(
            AUTHORITY_NAME,
            owner_uid,
            &crate::platform::services::system_bus::trusted_owner_uids(AUTHORITY_USER),
        )?;
        let proxy = zbus_polkit::policykit1::AuthorityProxy::builder(&conn)
            .destination(owner.into_inner())
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await
            .map_err(|e| unavailable("cannot address the authority", e))?;
        Ok(Self { proxy })
    }
}

/// Cancels the check on drop unless disarmed, such as when the agent dropped the call.
struct CancelOnDrop {
    proxy: zbus_polkit::policykit1::AuthorityProxy<'static>,
    cancellation_id: String,
    armed: bool,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let proxy = self.proxy.clone();
        let id = std::mem::take(&mut self.cancellation_id);
        tracing::info!(cancellation_id = id, "Cancelling a pending polkit check");
        tokio::spawn(async move {
            if let Err(e) = proxy.cancel_check_authorization(&id).await {
                tracing::debug!(err = %e, "CancelCheckAuthorization failed");
            }
        });
    }
}

pub async fn authorize(
    req: crate::proto::platform::AuthorizeRequest,
) -> crate::proto::platform::AuthorizeResponse {
    use crate::proto::platform::authorize_request::Action;
    let action_id = match req.action() {
        Action::AssumeRole => ACTION_ASSUME_ROLE,
        Action::ApprovePolicy => ACTION_APPROVE_POLICY,
        Action::Unspecified => {
            return Unavailable::new(REASON_UNAVAILABLE, "no action given").into_response();
        }
    };
    let Some(process) = req.subject else {
        return Unavailable::new(REASON_UNAVAILABLE, "no subject given").into_response();
    };
    let authority = match Authority::connect().await {
        Ok(a) => a,
        Err(u) => return u.into_response(),
    };
    let subject = match zbus_polkit::policykit1::Subject::new_for_pid(
        process.pid,
        Some(process.start_time),
        Some(process.uid),
    ) {
        Ok(s) => s,
        Err(e) => return Unavailable::new(REASON_UNAVAILABLE, e).into_response(),
    };
    // polkit refuses details from callers other than root and the action's owners.
    let details: std::collections::HashMap<&str, &str> = if nix::unistd::geteuid().is_root() {
        req.details
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    } else {
        Default::default()
    };
    let cancellation_id = cancellation_id(process.pid);
    let mut guard = CancelOnDrop {
        proxy: authority.proxy.clone(),
        cancellation_id: cancellation_id.clone(),
        armed: true,
    };
    tracing::info!(
        action_id,
        subject_pid = process.pid,
        message = req.message,
        "Checking polkit authorization"
    );
    let call = authority.proxy.check_authorization(
        &subject,
        action_id,
        &details,
        zbus_polkit::policykit1::CheckAuthorizationFlags::ALLOW_USER_INTERACTION,
        &cancellation_id,
    );
    let outcome = match tokio::time::timeout(CHECK_TIMEOUT, call).await {
        Err(_) => {
            return crate::proto::platform::AuthorizeResponse {
                result: crate::proto::platform::authorize_response::Result::Cancelled.into(),
                reason: REASON_TIMEOUT.to_owned(),
                detail: format!("no answer within {} s", CHECK_TIMEOUT.as_secs()),
            };
        }
        Ok(outcome) => outcome,
    };
    guard.armed = false;
    let resp = match outcome {
        Ok(result) => map_result(result.is_authorized, result.is_challenge, &result.details),
        Err(zbus::Error::MethodError(name, description, _)) => {
            map_error(name.as_str(), description.as_deref())
        }
        Err(e) => Unavailable::new(REASON_UNAVAILABLE, e).into_response(),
    };
    tracing::info!(action_id, subject_pid = process.pid, result = ?resp.result(), reason = resp.reason, "polkit answered");
    resp
}

fn cancellation_id(pid: u32) -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("mairu-{pid}-{hex}")
}

/// A check with user interaction allowed is a challenge only when no authentication agent could take it.
fn map_result(
    is_authorized: bool,
    is_challenge: bool,
    details: &std::collections::HashMap<String, String>,
) -> crate::proto::platform::AuthorizeResponse {
    use crate::proto::platform::authorize_response::Result as R;
    let (result, reason, detail) = if is_authorized {
        (R::Allowed, "", "")
    } else if details.get("polkit.dismissed").map(String::as_str) == Some("true") {
        (
            R::Cancelled,
            "dismissed",
            "the authentication dialog was dismissed",
        )
    } else if is_challenge {
        (
            R::Unavailable,
            REASON_NO_AUTHENTICATION_AGENT,
            "polkit has no authentication agent for this process",
        )
    } else {
        (R::Denied, "", "")
    };
    crate::proto::platform::AuthorizeResponse {
        result: result.into(),
        reason: reason.to_owned(),
        detail: detail.to_owned(),
    }
}

fn map_error(name: &str, description: Option<&str>) -> crate::proto::platform::AuthorizeResponse {
    let description = description.unwrap_or_default();
    if name == "org.freedesktop.PolicyKit1.Error.Failed"
        && description.contains("is not registered")
    {
        return Unavailable::new(REASON_ACTION_NOT_INSTALLED, description).into_response();
    }
    Unavailable::new(REASON_UNAVAILABLE, format!("{name}: {description}")).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::platform::authorize_response::Result as R;

    #[test]
    fn test_map_result() {
        let none = std::collections::HashMap::new();
        assert_eq!(map_result(true, false, &none).result(), R::Allowed);
        assert_eq!(map_result(false, false, &none).result(), R::Denied);
        let no_agent = map_result(false, true, &none);
        assert_eq!(no_agent.result(), R::Unavailable);
        assert_eq!(no_agent.reason, REASON_NO_AUTHENTICATION_AGENT);
        let dismissed: std::collections::HashMap<String, String> =
            [("polkit.dismissed".to_owned(), "true".to_owned())].into();
        assert_eq!(map_result(false, false, &dismissed).result(), R::Cancelled);
    }

    #[test]
    fn test_map_error() {
        let resp = map_error(
            "org.freedesktop.PolicyKit1.Error.Failed",
            Some("Action co.0w0.mairu.assume-role is not registered"),
        );
        assert_eq!(resp.reason, REASON_ACTION_NOT_INSTALLED);
        let resp = map_error("org.freedesktop.DBus.Error.ServiceUnknown", None);
        assert_eq!(resp.result(), R::Unavailable);
        assert_eq!(resp.reason, REASON_UNAVAILABLE);
    }

    #[test]
    fn test_cancellation_id_unique() {
        assert_ne!(cancellation_id(1), cancellation_id(1));
    }
}
