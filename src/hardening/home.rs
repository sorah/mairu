//! The harden home: the prefix `mairu harden` installs the hardened copy under, and where clients look for it.

pub const DEFAULT_HARDEN_HOME: &str = "/usr/local";
pub const HARDEN_HOME_ENV: &str = "MAIRU_HARDEN_HOME";
/// Where distribution packages install the hardened binary.
pub const DISTRO_BINARY: &str = "/usr/bin/mairu";
const MANIFEST_NAME: &str = ".harden-manifest";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardenHomeSource {
    Flag,
    Environment,
    Config,
    Default,
}

impl std::fmt::Display for HardenHomeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            HardenHomeSource::Flag => "--home",
            HardenHomeSource::Environment => HARDEN_HOME_ENV,
            HardenHomeSource::Config => "harden_home in config.json",
            HardenHomeSource::Default => "default",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardenHome {
    pub path: std::path::PathBuf,
    pub source: HardenHomeSource,
}

impl HardenHome {
    /// The first value set wins. A relative path is ignored with a warning.
    pub fn resolve(
        flag: Option<&std::path::Path>,
        env: Option<&std::ffi::OsStr>,
        config: Option<&std::path::Path>,
    ) -> Self {
        let values = [
            (flag, HardenHomeSource::Flag),
            (env.map(std::path::Path::new), HardenHomeSource::Environment),
            (config, HardenHomeSource::Config),
        ];
        for (value, source) in values {
            let Some(path) = value.filter(|p| !p.as_os_str().is_empty()) else {
                continue;
            };
            if path.is_absolute() {
                return Self {
                    path: path.to_owned(),
                    source,
                };
            }
            eprintln!(
                ":: mairu :: Ignoring the harden home {} from {source}: not an absolute path",
                path.display()
            );
        }
        Self {
            path: DEFAULT_HARDEN_HOME.into(),
            source: HardenHomeSource::Default,
        }
    }

    /// As a client resolves it: `MAIRU_HARDEN_HOME`, then its own config.json.
    pub fn for_client() -> Self {
        let config = crate::config::UserConfig::load_sync()
            .ok()
            .and_then(|c| c.harden_home);
        Self::resolve(
            None,
            std::env::var_os(HARDEN_HOME_ENV).as_deref(),
            config.as_deref(),
        )
    }

    pub fn libexec_dir(&self) -> std::path::PathBuf {
        self.path.join("libexec").join("mairu")
    }

    pub fn binary(&self) -> std::path::PathBuf {
        self.libexec_dir().join("mairu")
    }

    pub fn manifest(&self) -> std::path::PathBuf {
        self.libexec_dir().join(MANIFEST_NAME)
    }

    /// Re-exec candidates, in order.
    pub fn candidates(&self) -> [std::path::PathBuf; 2] {
        [self.binary(), DISTRO_BINARY.into()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> &std::path::Path {
        std::path::Path::new(s)
    }

    #[test]
    fn test_default() {
        let home = HardenHome::resolve(None, None, None);
        assert_eq!(home.path, p("/usr/local"));
        assert_eq!(home.source, HardenHomeSource::Default);
        assert_eq!(home.binary(), p("/usr/local/libexec/mairu/mairu"));
        assert_eq!(
            home.manifest(),
            p("/usr/local/libexec/mairu/.harden-manifest")
        );
    }

    #[test]
    fn test_precedence() {
        let home = HardenHome::resolve(Some(p("/a")), Some("/b".as_ref()), Some(p("/c")));
        assert_eq!(
            (home.path.as_path(), home.source),
            (p("/a"), HardenHomeSource::Flag)
        );
        let home = HardenHome::resolve(None, Some("/b".as_ref()), Some(p("/c")));
        assert_eq!(
            (home.path.as_path(), home.source),
            (p("/b"), HardenHomeSource::Environment)
        );
        let home = HardenHome::resolve(None, None, Some(p("/c")));
        assert_eq!(
            (home.path.as_path(), home.source),
            (p("/c"), HardenHomeSource::Config)
        );
    }

    #[test]
    fn test_relative_and_empty_ignored() {
        let home = HardenHome::resolve(None, Some("opt".as_ref()), Some(p("/c")));
        assert_eq!(home.source, HardenHomeSource::Config);
        let home = HardenHome::resolve(None, Some("".as_ref()), Some(p("rel")));
        assert_eq!(home.source, HardenHomeSource::Default);
    }
}
