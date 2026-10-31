//! Whether this is WSL1 or WSL2, and on WSL2 whether Windows interop is enabled. Interop makes root reachable to
//! code running as the user (`wsl.exe -u root`).

const OSRELEASE: &str = "/proc/sys/kernel/osrelease";
const RUN_WSL: &str = "/run/WSL";
const BINFMT_ENTRIES: [&str; 2] = [
    "/proc/sys/fs/binfmt_misc/WSLInterop",
    "/proc/sys/fs/binfmt_misc/WSLInterop-late",
];
pub const WSL_CONF: &str = "/etc/wsl.conf";
const WSL2_KERNEL: &str = "microsoft-standard-WSL2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wsl {
    Wsl1,
    Wsl2 { interop: Interop },
}

impl Wsl {
    /// Reads the host's files; on WSL2 again on every call, so a changed interop shows up after a restart.
    pub fn detect() -> Option<Self> {
        Facts::read().classify()
    }

    /// `None` on WSL1, which has no interop to speak of.
    pub fn interop_enabled(self) -> Option<bool> {
        match self {
            Wsl::Wsl2 { interop } => Some(interop.enabled()),
            Wsl::Wsl1 => None,
        }
    }

    pub fn version(self) -> u8 {
        match self {
            Wsl::Wsl1 => 1,
            Wsl::Wsl2 { .. } => 2,
        }
    }

    /// Facts for `GetAgentStatus` notes and `mairu doctor` warnings.
    pub fn notes(self) -> Vec<String> {
        let interop = match self {
            Wsl::Wsl1 => {
                return vec![
                    "WSL1 translates system calls instead of running a Linux kernel, so mairu cannot be hardened here; use WSL2"
                        .to_owned(),
                ];
            }
            Wsl::Wsl2 { interop } => interop,
        };
        let mut notes = vec![];
        if interop.enabled() {
            notes.push(format!(
                "WSL2 interop is enabled (integrated profile), so any program running as you can become root through `wsl.exe -u root` and bypass mairu; it is a guardrail here, not a boundary. Disable interop in {WSL_CONF} for the isolated profile"
            ));
        }
        if interop == Interop::EnabledPendingRestart {
            notes.push(format!(
                "{WSL_CONF} disables interop but changed after this distribution started; restart it from Windows with `wsl.exe --terminate <distro>`"
            ));
        }
        notes.push("on WSL2 the Windows account, and every other distribution with interop enabled, can become root in this distribution; they are outside what mairu protects against".to_owned());
        notes
    }
}

/// How to switch to the isolated profile; `distro` is `$WSL_DISTRO_NAME` when known.
pub fn disable_interop_instructions(distro: Option<&str>) -> String {
    format!(
        "To isolate this distribution, add to {WSL_CONF}:\n\n  [interop]\n  enabled = false\n  appendWindowsPath = false\n\nand restart it from Windows: wsl.exe --terminate {}\n",
        distro.filter(|d| !d.is_empty()).unwrap_or("<distro>")
    )
}

impl std::fmt::Display for Wsl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Wsl::Wsl1 => write!(f, "WSL1"),
            Wsl::Wsl2 { interop } => write!(f, "WSL2, interop {interop}, {}", interop.profile()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interop {
    /// A `WSLInterop` binfmt entry is enabled, and wsl.conf does not disable interop.
    Enabled,
    /// wsl.conf disables interop, but changed after the distribution started, so it may not be in effect yet.
    EnabledPendingRestart,
    /// `[interop] enabled = false` in wsl.conf, unchanged since the distribution started.
    DisabledByConfig,
    /// No `WSLInterop` binfmt entry is enabled.
    DisabledBinfmt,
}

impl Interop {
    pub fn enabled(self) -> bool {
        matches!(self, Interop::Enabled | Interop::EnabledPendingRestart)
    }

    pub fn profile(self) -> Profile {
        if self.enabled() {
            Profile::Integrated
        } else {
            Profile::Isolated
        }
    }
}

impl std::fmt::Display for Interop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Interop::Enabled => write!(f, "enabled"),
            Interop::EnabledPendingRestart => write!(
                f,
                "enabled (disabled in {WSL_CONF}, which takes a restart of the distribution)"
            ),
            Interop::DisabledByConfig => write!(f, "disabled ({WSL_CONF})"),
            Interop::DisabledBinfmt => write!(f, "disabled (no WSLInterop binfmt entry)"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Integrated,
    Isolated,
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Profile::Integrated => write!(f, "integrated profile"),
            Profile::Isolated => write!(f, "isolated profile"),
        }
    }
}

/// Everything detection looks at.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub osrelease: Option<String>,
    pub run_wsl: bool,
    /// The contents of the `WSLInterop` and `WSLInterop-late` entries that exist.
    pub binfmt: Vec<String>,
    pub wsl_conf: Option<String>,
    /// Whether wsl.conf was last modified before this distribution's init started; `None` when unknown.
    pub wsl_conf_predates_start: Option<bool>,
}

impl Facts {
    pub fn read() -> Self {
        let osrelease = std::fs::read_to_string(OSRELEASE).ok();
        if !osrelease
            .as_deref()
            .is_some_and(|r| r.to_ascii_lowercase().contains("microsoft"))
        {
            return Self {
                osrelease,
                ..Default::default()
            };
        }
        let conf = std::fs::metadata(WSL_CONF).and_then(|m| m.modified()).ok();
        Self {
            osrelease,
            run_wsl: std::path::Path::new(RUN_WSL).is_dir(),
            binfmt: BINFMT_ENTRIES
                .iter()
                .filter_map(|p| std::fs::read_to_string(p).ok())
                .collect(),
            wsl_conf: std::fs::read_to_string(WSL_CONF).ok(),
            wsl_conf_predates_start: conf
                .zip(distribution_start())
                .map(|(modified, started)| modified < started),
        }
    }

    pub fn classify(&self) -> Option<Wsl> {
        let release = self.osrelease.as_deref()?.trim();
        if release.contains(WSL2_KERNEL) {
            return self.run_wsl.then(|| Wsl::Wsl2 {
                interop: self.interop(),
            });
        }
        release
            .to_ascii_lowercase()
            .contains("microsoft")
            .then_some(Wsl::Wsl1)
    }

    /// binfmt_misc is shared across the WSL2 VM, so an enabled entry does not show that this distribution has
    /// interop; a disabling wsl.conf that predates the distribution's start does.
    fn interop(&self) -> Interop {
        let binfmt_enabled = self
            .binfmt
            .iter()
            .any(|e| e.lines().next().map(str::trim) == Some("enabled"));
        if !binfmt_enabled {
            return Interop::DisabledBinfmt;
        }
        match self.wsl_conf.as_deref().and_then(conf_interop_enabled) {
            Some(false) if self.wsl_conf_predates_start == Some(true) => Interop::DisabledByConfig,
            Some(false) => Interop::EnabledPendingRestart,
            _ => Interop::Enabled,
        }
    }
}

/// `[interop] enabled` in wsl.conf; the last occurrence wins, as in an INI file.
pub fn conf_interop_enabled(conf: &str) -> Option<bool> {
    let mut section = String::new();
    let mut enabled = None;
    for line in conf.lines() {
        let line = line.split(['#', ';']).next().unwrap_or_default().trim();
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_ascii_lowercase();
            continue;
        }
        if section != "interop" {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !key.trim().eq_ignore_ascii_case("enabled") {
            continue;
        }
        match value.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" => enabled = Some(true),
            "false" | "no" | "0" => enabled = Some(false),
            _ => {}
        }
    }
    enabled
}

/// When this distribution's init (pid 1 of its pid namespace) started.
fn distribution_start() -> Option<std::time::SystemTime> {
    let started = super::procfs::Stat::read(1).ok()?.start_time;
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let btime: u64 = stat
        .lines()
        .find_map(|l| l.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()?;
    let ticks = nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK)
        .ok()
        .flatten()
        .and_then(|t| u64::try_from(t).ok())
        .filter(|t| *t > 0)?;
    Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(btime + started / ticks))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WSL2_RELEASE: &str = "6.6.87.2-microsoft-standard-WSL2\n";

    fn wsl2(binfmt: &[&str], conf: Option<&str>, predates: Option<bool>) -> Facts {
        Facts {
            osrelease: Some(WSL2_RELEASE.to_owned()),
            run_wsl: true,
            binfmt: binfmt.iter().map(|s| (*s).to_owned()).collect(),
            wsl_conf: conf.map(ToOwned::to_owned),
            wsl_conf_predates_start: predates,
        }
    }

    const ENABLED: &str = "enabled\ninterpreter /init\nflags: PF\noffset 0\nmagic 4d5a\n";
    const DISABLED: &str = "disabled\ninterpreter /init\nflags: PF\noffset 0\nmagic 4d5a\n";
    const CONF_OFF: &str =
        "[boot]\nsystemd=true\n\n[interop]\nenabled = false\nappendWindowsPath = false\n";

    #[test]
    fn test_not_wsl() {
        let facts = Facts {
            osrelease: Some("6.12.0-arch1-1\n".to_owned()),
            run_wsl: true,
            binfmt: vec![ENABLED.to_owned()],
            ..Default::default()
        };
        assert_eq!(facts.classify(), None);
        assert_eq!(Facts::default().classify(), None);
    }

    #[test]
    fn test_wsl2_kernel_without_run_wsl() {
        let facts = Facts {
            run_wsl: false,
            ..wsl2(&[ENABLED], None, None)
        };
        assert_eq!(facts.classify(), None);
    }

    #[test]
    fn test_wsl1() {
        for release in ["4.4.0-19041-Microsoft\n", "4.4.0-22621-microsoft"] {
            let facts = Facts {
                osrelease: Some(release.to_owned()),
                ..Default::default()
            };
            assert_eq!(facts.classify(), Some(Wsl::Wsl1), "{release}");
        }
    }

    #[test]
    fn test_wsl2_interop_binfmt() {
        let cases: [(&[&str], Interop); 6] = [
            (&[ENABLED], Interop::Enabled),
            (&[DISABLED], Interop::DisabledBinfmt),
            (&[], Interop::DisabledBinfmt),
            // WSLInterop-late, as on distributions with systemd.
            (&[DISABLED, ENABLED], Interop::Enabled),
            (&["enabled"], Interop::Enabled),
            (&[""], Interop::DisabledBinfmt),
        ];
        for (binfmt, expected) in cases {
            assert_eq!(
                wsl2(binfmt, None, None).classify(),
                Some(Wsl::Wsl2 { interop: expected }),
                "{binfmt:?}"
            );
        }
    }

    #[test]
    fn test_wsl2_interop_disabled_by_conf() {
        assert_eq!(
            wsl2(&[ENABLED], Some(CONF_OFF), Some(true)).classify(),
            Some(Wsl::Wsl2 {
                interop: Interop::DisabledByConfig
            })
        );
        for predates in [Some(false), None] {
            assert_eq!(
                wsl2(&[ENABLED], Some(CONF_OFF), predates).classify(),
                Some(Wsl::Wsl2 {
                    interop: Interop::EnabledPendingRestart
                }),
                "{predates:?}"
            );
        }
        assert_eq!(
            wsl2(&[ENABLED], Some("[interop]\nenabled=true\n"), Some(true)).classify(),
            Some(Wsl::Wsl2 {
                interop: Interop::Enabled
            })
        );
        assert_eq!(
            wsl2(&[DISABLED], Some("[interop]\nenabled=true\n"), Some(true)).classify(),
            Some(Wsl::Wsl2 {
                interop: Interop::DisabledBinfmt
            })
        );
    }

    #[test]
    fn test_conf_interop_enabled() {
        assert_eq!(conf_interop_enabled(CONF_OFF), Some(false));
        assert_eq!(conf_interop_enabled(""), None);
        assert_eq!(conf_interop_enabled("[boot]\nenabled=false\n"), None);
        assert_eq!(
            conf_interop_enabled("[Interop]\n  Enabled = FALSE # off\n"),
            Some(false)
        );
        assert_eq!(
            conf_interop_enabled("[interop]\nenabled=false\n[interop]\nenabled=true\n"),
            Some(true)
        );
        assert_eq!(conf_interop_enabled("[interop]\n# enabled=false\n"), None);
        assert_eq!(conf_interop_enabled("[interop]\nenabled=maybe\n"), None);
        assert_eq!(conf_interop_enabled("[interop]\nenabledx=false\n"), None);
    }

    #[test]
    fn test_interop_enabled_and_profile() {
        assert_eq!(Wsl::Wsl1.interop_enabled(), None);
        for (interop, enabled, profile) in [
            (Interop::Enabled, true, Profile::Integrated),
            (Interop::EnabledPendingRestart, true, Profile::Integrated),
            (Interop::DisabledByConfig, false, Profile::Isolated),
            (Interop::DisabledBinfmt, false, Profile::Isolated),
        ] {
            assert_eq!(Wsl::Wsl2 { interop }.interop_enabled(), Some(enabled));
            assert_eq!(interop.profile(), profile);
        }
    }

    #[test]
    fn test_disable_interop_instructions() {
        let text = disable_interop_instructions(Some("Ubuntu-26.04"));
        assert!(text.contains("enabled = false"), "{text}");
        assert!(text.contains("wsl.exe --terminate Ubuntu-26.04"), "{text}");
        assert!(disable_interop_instructions(None).contains("--terminate <distro>"));
        assert!(disable_interop_instructions(Some("")).contains("--terminate <distro>"));
    }

    #[test]
    fn test_notes() {
        let integrated = Wsl::Wsl2 {
            interop: Interop::Enabled,
        }
        .notes();
        assert_eq!(integrated.len(), 2);
        assert!(integrated[0].contains("wsl.exe -u root"), "{integrated:?}");
        assert!(integrated[1].contains("Windows account"), "{integrated:?}");
        let isolated = Wsl::Wsl2 {
            interop: Interop::DisabledByConfig,
        }
        .notes();
        assert_eq!(isolated.len(), 1);
        assert!(isolated[0].contains("Windows account"), "{isolated:?}");
        let pending = Wsl::Wsl2 {
            interop: Interop::EnabledPendingRestart,
        }
        .notes();
        assert!(
            pending.iter().any(|n| n.contains("--terminate")),
            "{pending:?}"
        );
        assert!(Wsl::Wsl1.notes()[0].contains("WSL1"));
    }
}
