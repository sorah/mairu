//! Suggests `mairu harden` on hosts without a hardened copy, at most once per period.

const DISABLE_ENV: &str = "MAIRU_NO_HARDEN_SUGGESTION";
const STATE_FILE: &str = "harden-suggestion.json";
const FALLBACK_INTERVAL_SECS: u64 = 3600;

/// A terminal session: the session id of the controlling terminal and the start time of its leader.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSession {
    pub sid: i32,
    pub start_time: u64,
}

impl TerminalSession {
    pub fn current() -> Option<Self> {
        let stat = crate::platform::process::linux::procfs::Stat::read(std::process::id()).ok()?;
        if stat.tty_nr == 0 || stat.session <= 0 {
            return None;
        }
        let leader =
            crate::platform::process::linux::procfs::Stat::read(stat.session as u32).ok()?;
        Some(Self {
            sid: stat.session,
            start_time: leader.start_time,
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
struct SuggestionState {
    last_shown: chrono::DateTime<chrono::Utc>,
    session: Option<TerminalSession>,
}

/// Prints the suggestion to a terminal when it is due. Skipped when the state file cannot be written, so that a
/// failure never turns into a suggestion on every invocation.
pub fn maybe_show() {
    use std::io::IsTerminal;
    if !std::io::stderr().is_terminal() {
        return;
    }
    let config = crate::config::UserConfig::load_sync()
        .map(|c| c.harden_suggestion)
        .unwrap_or_default();
    if !enabled(std::env::var_os(DISABLE_ENV).as_deref(), &config) {
        return;
    }
    // `mairu harden` refuses WSL1.
    if crate::platform::process::linux::wsl::Wsl::detect()
        == Some(crate::platform::process::linux::wsl::Wsl::Wsl1)
    {
        return;
    }
    let path = crate::config::state_dir().join(STATE_FILE);
    let previous = std::fs::read(&path)
        .ok()
        .and_then(|data| serde_json::from_slice::<SuggestionState>(&data).ok());
    let session = TerminalSession::current();
    let now = chrono::Utc::now();
    if !due(&config, previous.as_ref(), now, session) {
        return;
    }
    let state = SuggestionState {
        last_shown: now,
        session,
    };
    if write_state(&path, &state).is_err() {
        return;
    }
    eprint!(
        "{}",
        message(
            &crate::hardening::reexec::harden_instruction(""),
            config.interval_secs
        )
    );
}

fn enabled(
    disable_env: Option<&std::ffi::OsStr>,
    config: &crate::config::HardenSuggestionConfig,
) -> bool {
    config.enabled && disable_env.is_none_or(|v| v != "1")
}

fn due(
    config: &crate::config::HardenSuggestionConfig,
    previous: Option<&SuggestionState>,
    now: chrono::DateTime<chrono::Utc>,
    session: Option<TerminalSession>,
) -> bool {
    let Some(previous) = previous else {
        return true;
    };
    let interval = match (config.interval_secs, session) {
        (0, Some(session)) => return previous.session != Some(session),
        (0, None) => FALLBACK_INTERVAL_SECS,
        (secs, _) => secs,
    };
    let elapsed = now.signed_duration_since(previous.last_shown);
    // A last_shown in the future means the clock moved back.
    elapsed < chrono::TimeDelta::zero()
        || elapsed >= chrono::TimeDelta::seconds(i64::try_from(interval).unwrap_or(i64::MAX))
}

fn write_state(path: &std::path::Path, state: &SuggestionState) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, serde_json::to_vec(state)?)
}

fn message(instruction: &str, interval_secs: u64) -> String {
    let again = match interval_secs {
        0 => "in the next terminal session".to_owned(),
        s if s % 3600 == 0 => plural(s / 3600, "hour"),
        s if s % 60 == 0 => plural(s / 60, "minute"),
        s => plural(s, "second"),
    };
    let again = if interval_secs == 0 {
        again
    } else {
        format!("in {again}")
    };
    format!(
        ":: mairu :: Harden mairu to protect your AWS credentials from other programs: {instruction}\n\
         :: mairu :: This reminder shows again {again}. To turn it off, set {DISABLE_ENV}=1 or \
         \"harden_suggestion\": {{\"enabled\": false}} in {}\n",
        crate::config::UserConfig::path().display()
    )
}

fn plural(n: u64, unit: &str) -> String {
    if n == 1 {
        format!("1 {unit}")
    } else {
        format!("{n} {unit}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(interval_secs: u64) -> crate::config::HardenSuggestionConfig {
        crate::config::HardenSuggestionConfig {
            enabled: true,
            interval_secs,
        }
    }

    fn at(secs: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
    }

    const SESSION: TerminalSession = TerminalSession {
        sid: 4242,
        start_time: 8812345,
    };

    fn shown(secs: i64, session: Option<TerminalSession>) -> SuggestionState {
        SuggestionState {
            last_shown: at(secs),
            session,
        }
    }

    #[test]
    fn test_enabled() {
        assert!(enabled(None, &config(3600)));
        assert!(enabled(Some("0".as_ref()), &config(3600)));
        assert!(!enabled(Some("1".as_ref()), &config(3600)));
        let disabled = crate::config::HardenSuggestionConfig {
            enabled: false,
            interval_secs: 3600,
        };
        assert!(!enabled(None, &disabled));
    }

    #[test]
    fn test_first_time() {
        assert!(due(&config(3600), None, at(0), Some(SESSION)));
        assert!(due(&config(0), None, at(0), None));
    }

    #[test]
    fn test_interval() {
        let previous = shown(0, Some(SESSION));
        assert!(!due(
            &config(3600),
            Some(&previous),
            at(3599),
            Some(SESSION)
        ));
        assert!(due(&config(3600), Some(&previous), at(3600), Some(SESSION)));
        // Counted across terminals.
        let other = TerminalSession { sid: 1, ..SESSION };
        assert!(!due(&config(3600), Some(&previous), at(60), Some(other)));
    }

    #[test]
    fn test_clock_moved_back() {
        let previous = shown(100, Some(SESSION));
        assert!(due(&config(3600), Some(&previous), at(0), Some(SESSION)));
    }

    #[test]
    fn test_once_per_session() {
        let previous = shown(0, Some(SESSION));
        assert!(!due(&config(0), Some(&previous), at(86400), Some(SESSION)));
        let restarted = TerminalSession {
            start_time: 9999999,
            ..SESSION
        };
        assert!(due(&config(0), Some(&previous), at(1), Some(restarted)));
        let other = TerminalSession { sid: 1, ..SESSION };
        assert!(due(&config(0), Some(&previous), at(1), Some(other)));
    }

    #[test]
    fn test_once_per_session_without_session() {
        let previous = shown(0, None);
        assert!(!due(&config(0), Some(&previous), at(60), None));
        assert!(due(&config(0), Some(&previous), at(3600), None));
    }

    #[test]
    fn test_unwritable_state() {
        let state = shown(0, None);
        assert!(
            write_state(
                std::path::Path::new("/proc/self/harden-suggestion.json"),
                &state
            )
            .is_err()
        );
    }

    #[test]
    fn test_state_roundtrip() {
        let state = shown(0, Some(SESSION));
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"sid\":4242"));
        assert_eq!(
            serde_json::from_str::<SuggestionState>(&json).unwrap(),
            state
        );
    }

    #[test]
    fn test_message() {
        let m = message("run: sudo /usr/bin/x harden", 3600);
        assert!(m.starts_with(
            ":: mairu :: Harden mairu to protect your AWS credentials from other programs: run: sudo /usr/bin/x harden\n"
        ));
        assert!(m.contains("shows again in 1 hour."));
        assert!(message("x", 0).contains("shows again in the next terminal session."));
        assert!(message("x", 7200).contains("in 2 hours."));
        assert!(message("x", 90).contains("in 90 seconds."));
    }
}
