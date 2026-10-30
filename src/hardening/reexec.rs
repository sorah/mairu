//! Hands an unhardened invocation over to the hardened copy, so that one binary serves every installation.

const REEXEC_FROM: &str = "MAIRU_HARDENED_REEXEC_FROM";
const REEXEC_VERSION: &str = "MAIRU_HARDENED_REEXEC_VERSION";
const NO_REEXEC: &str = "MAIRU_NO_HARDENED_REEXEC";
pub const README_HARDENING_URL: &str = "https://github.com/sorah/mairu#hardening";

/// What an unhardened copy told the hardened copy it exec'd. Only feeds a message.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Origin {
    from: Option<std::path::PathBuf>,
    version: Option<String>,
}

/// Runs right after classification, while the process is single-threaded. Execs the hardened copy when this
/// process is unhardened and a valid one exists. Returns whether to suggest hardening, which waits for logging.
pub fn reexec_hardened_if_available() -> bool {
    let origin = take_origin();
    match crate::hardening::Hardening::state() {
        crate::hardening::HardeningState::Hardened { .. } => {
            if let Some(message) = origin.and_then(|o| o.skew_message()) {
                eprint!("{message}");
            }
            return false;
        }
        crate::hardening::HardeningState::Misconfigured { .. } => return false,
        crate::hardening::HardeningState::Unhardened { .. } => {}
    }
    if origin.is_some() {
        eprintln!(
            ":: mairu :: The hardened copy did not run hardened; continuing unhardened. Run `mairu doctor` for details."
        );
        return false;
    }
    if std::env::args_os().nth(1).as_deref() == Some("harden".as_ref()) {
        return false;
    }
    let home = crate::hardening::home::HardenHome::for_client();
    match find_candidate(&home) {
        Some(candidate) if reexec_enabled() => {
            exec(&candidate);
            false
        }
        Some(_) => false,
        None => true,
    }
}

/// The first valid re-exec candidate.
pub fn find_candidate(home: &crate::hardening::home::HardenHome) -> Option<std::path::PathBuf> {
    let marker = marker_group_gid()?;
    home.candidates()
        .iter()
        .find_map(|c| crate::hardening::candidate::hardened_candidate(c, marker).ok())
}

/// The gid of the group named `mairu`. An unhardened process has no grant to read it from.
pub fn marker_group_gid() -> Option<u32> {
    nix::unistd::Group::from_name(crate::hardening::MARKER_GROUP_NAME)
        .ok()
        .flatten()
        .map(|g| g.gid.as_raw())
}

/// The dev profile turns re-exec off, so a contributor's debug build never hands over. Resolved without caching,
/// as logging is not set up yet.
fn reexec_enabled() -> bool {
    let profile =
        crate::config::Profile::resolve(false, std::env::var("MAIRU_PROFILE").ok().as_deref());
    std::env::var_os(NO_REEXEC).is_none_or(|v| v != "1") && profile != crate::config::Profile::Dev
}

fn exec(candidate: &std::path::Path) {
    use std::os::unix::process::CommandExt;
    let own = own_exe().unwrap_or_default();
    let err = std::process::Command::new(candidate)
        .args(std::env::args_os().skip(1))
        .env(REEXEC_FROM, own)
        .env(REEXEC_VERSION, crate::version::VERSION)
        .exec();
    eprintln!(
        ":: mairu :: Could not run the hardened copy {} ({err}); continuing unhardened",
        candidate.display()
    );
}

fn take_origin() -> Option<Origin> {
    let from = std::env::var_os(REEXEC_FROM);
    let version = std::env::var_os(REEXEC_VERSION);
    if from.is_none() && version.is_none() {
        return None;
    }
    // SAFETY: called from main before any other thread exists.
    unsafe {
        std::env::remove_var(REEXEC_FROM);
        std::env::remove_var(REEXEC_VERSION);
    }
    Some(Origin {
        from: from.map(Into::into),
        version: version.and_then(|v| v.into_string().ok()),
    })
}

impl Origin {
    fn skew_message(&self) -> Option<String> {
        let own = own_exe()?;
        skew_message(
            &own,
            crate::version::VERSION,
            self.from.as_deref()?,
            self.version.as_deref()?,
        )
    }
}

fn skew_message(
    hardened: &std::path::Path,
    hardened_version: &str,
    from: &std::path::Path,
    from_version: &str,
) -> Option<String> {
    if hardened_version == from_version {
        return None;
    }
    let mut message = format!(
        ":: mairu :: Using hardened mairu {hardened_version} ({}) instead of mairu {from_version} ({}).\n",
        hardened.display(),
        from.display()
    );
    // A downgrade would be refused, so the command is only offered for a newer copy.
    if !crate::version::at_least(hardened_version, from_version) {
        message.push_str(&format!(
            ":: mairu :: To update the hardened copy, run: sudo {} harden --from {}\n",
            hardened.display(),
            from.display()
        ));
    }
    Some(message)
}

/// How to run `mairu harden <args>` as root: a `sudo` command when this executable cannot be replaced by the
/// user's processes, otherwise a pointer to the README.
pub fn harden_instruction(args: &str) -> String {
    let safe = own_exe().and_then(|exe| crate::hardening::candidate::root_owned_file(&exe).ok());
    match safe {
        Some(exe) => format!("run: sudo {} harden{args}", exe.display()),
        None => format!(
            "this mairu is in a location your programs can modify, so harden from a trusted copy instead; see {README_HARDENING_URL}"
        ),
    }
}

fn own_exe() -> Option<std::path::PathBuf> {
    std::env::current_exe().and_then(std::fs::canonicalize).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> &std::path::Path {
        std::path::Path::new(s)
    }

    #[test]
    fn test_skew_message_same_version() {
        assert_eq!(
            skew_message(
                p("/usr/local/libexec/mairu/mairu"),
                "0.13.0",
                p("/home/u/.cargo/bin/mairu"),
                "0.13.0"
            ),
            None
        );
    }

    #[test]
    fn test_skew_message_newer_user_copy() {
        assert_eq!(
            skew_message(
                p("/usr/local/libexec/mairu/mairu"),
                "0.13.0",
                p("/home/u/.local/share/mise/installs/mairu/0.14.0/mairu"),
                "0.14.0"
            )
            .unwrap(),
            ":: mairu :: Using hardened mairu 0.13.0 (/usr/local/libexec/mairu/mairu) instead of mairu 0.14.0 (/home/u/.local/share/mise/installs/mairu/0.14.0/mairu).\n\
             :: mairu :: To update the hardened copy, run: sudo /usr/local/libexec/mairu/mairu harden --from /home/u/.local/share/mise/installs/mairu/0.14.0/mairu\n"
        );
    }

    #[test]
    fn test_skew_message_older_user_copy() {
        let message = skew_message(
            p("/usr/local/libexec/mairu/mairu"),
            "0.14.0",
            p("/home/u/.cargo/bin/mairu"),
            "0.13.0",
        )
        .unwrap();
        assert!(message.starts_with(":: mairu :: Using hardened mairu 0.14.0"));
        assert!(!message.contains("sudo"));
    }

    #[test]
    fn test_take_origin_unsets() {
        // SAFETY: no other test touches these variables.
        unsafe {
            std::env::set_var(REEXEC_FROM, "/home/u/.cargo/bin/mairu");
            std::env::set_var(REEXEC_VERSION, "0.14.0");
        }
        assert_eq!(
            take_origin(),
            Some(Origin {
                from: Some("/home/u/.cargo/bin/mairu".into()),
                version: Some("0.14.0".to_owned()),
            })
        );
        assert!(std::env::var_os(REEXEC_FROM).is_none());
        assert!(std::env::var_os(REEXEC_VERSION).is_none());
        assert_eq!(take_origin(), None);
    }
}
