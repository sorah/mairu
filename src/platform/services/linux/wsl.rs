//! Opening URLs in the Windows default browser through WSL2 interop.

const WSLPATH: &str = "/usr/bin/wslpath";
const RUNDLL32: &str = r"C:\Windows\System32\rundll32.exe";
const EXPLORER: &str = r"C:\Windows\explorer.exe";
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The Windows programs that open a URL, as paths in this distribution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Launchers {
    pub rundll32: Option<std::path::PathBuf>,
    pub explorer: Option<std::path::PathBuf>,
}

/// One way to open a URL: a program and its argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub program: std::path::PathBuf,
    pub args: Vec<String>,
    /// explorer.exe exits 1 even when it opened the URL.
    pub check_status: bool,
}

impl Launchers {
    /// Runs `wslpath` off the async workers.
    pub async fn locate() -> Self {
        tokio::task::spawn_blocking(|| Self::locate_with(std::path::Path::new(WSLPATH)))
            .await
            .unwrap_or_default()
    }

    fn locate_with(wslpath: &std::path::Path) -> Self {
        Self {
            rundll32: windows_path(wslpath, RUNDLL32),
            explorer: windows_path(wslpath, EXPLORER),
        }
    }

    /// rundll32.exe first, explorer.exe as the fallback. The URL is always its own argv element: `cmd.exe /c start`
    /// would split it at `&`.
    pub fn attempts(&self, url: &url::Url) -> Vec<Attempt> {
        let mut attempts = vec![];
        if let Some(program) = &self.rundll32 {
            attempts.push(Attempt {
                program: program.clone(),
                args: vec![
                    "url.dll,FileProtocolHandler".to_owned(),
                    url.as_str().to_owned(),
                ],
                check_status: true,
            });
        }
        if let Some(program) = &self.explorer {
            attempts.push(Attempt {
                program: program.clone(),
                args: vec![url.as_str().to_owned()],
                check_status: false,
            });
        }
        attempts
    }
}

/// A Windows path translated by `wslpath`, when the file exists.
fn windows_path(wslpath: &std::path::Path, windows: &str) -> Option<std::path::PathBuf> {
    let output = crate::hardening::command(wslpath)
        .args(["-u", windows])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .inspect_err(|e| tracing::debug!(err = %e, "Failed to run wslpath"))
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = std::path::PathBuf::from(String::from_utf8(output.stdout).ok()?.trim_end());
    (path.is_absolute() && path.is_file()).then_some(path)
}

/// Why the Windows browser cannot be used for this client, if it cannot.
fn refusal(
    hint: &crate::proto::platform::SessionHint,
    interop: crate::platform::process::linux::wsl::Interop,
) -> Option<String> {
    if !interop.enabled() {
        Some("WSL2 interop is disabled (isolated profile)".to_owned())
    } else if hint.ssh {
        Some("the client is in an SSH session, away from the Windows desktop".to_owned())
    } else {
        None
    }
}

pub async fn available(
    hint: &crate::proto::platform::SessionHint,
    interop: crate::platform::process::linux::wsl::Interop,
) -> Result<(), String> {
    if let Some(refusal) = refusal(hint, interop) {
        return Err(refusal);
    }
    let launchers = Launchers::locate().await;
    if launchers.rundll32.is_none() && launchers.explorer.is_none() {
        return Err(no_launchers());
    }
    Ok(())
}

fn no_launchers() -> String {
    format!("neither {RUNDLL32} nor {EXPLORER} was found through {WSLPATH}")
}

pub async fn open_url(
    req: crate::proto::platform::OpenUrlRequest,
    interop: crate::platform::process::linux::wsl::Interop,
) -> crate::proto::platform::OpenUrlResponse {
    let url = match req.checked_url() {
        Ok(u) => u,
        Err(detail) => return crate::proto::platform::OpenUrlResponse::failed(detail),
    };
    let hint = req.session.unwrap_or_default();
    if let Some(refusal) = refusal(&hint, interop) {
        return crate::proto::platform::OpenUrlResponse::failed(refusal);
    }
    let socket = interop_socket(&hint.wsl_interop);
    let attempts = Launchers::locate().await.attempts(&url);
    if attempts.is_empty() {
        return crate::proto::platform::OpenUrlResponse::failed(no_launchers());
    }
    open_with(&attempts, socket.as_deref()).await
}

async fn open_with(
    attempts: &[Attempt],
    interop_socket: Option<&std::path::Path>,
) -> crate::proto::platform::OpenUrlResponse {
    let mut errors = vec![];
    for attempt in attempts {
        match run(attempt, interop_socket).await {
            Ok(()) => {
                let name = attempt
                    .program
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                tracing::debug!(program = name, "Opened a URL in the Windows browser");
                return crate::proto::platform::OpenUrlResponse {
                    opened: true,
                    detail: name,
                };
            }
            Err(e) => errors.push(e),
        }
    }
    crate::proto::platform::OpenUrlResponse::failed(errors.join("; "))
}

/// Waits at most [`TIMEOUT`]; a launcher still running then counts as opened.
async fn run(attempt: &Attempt, interop_socket: Option<&std::path::Path>) -> Result<(), String> {
    let mut cmd = crate::hardening::command(&attempt.program);
    cmd.args(&attempt.args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .env_remove("WSL_INTEROP");
    if let Some(socket) = interop_socket {
        cmd.env("WSL_INTEROP", socket);
    }
    let program = attempt.program.display();
    let mut child = tokio::process::Command::from(cmd)
        .spawn()
        .map_err(|e| format!("failed to run {program}: {e}"))?;
    match tokio::time::timeout(TIMEOUT, child.wait()).await {
        Ok(Ok(status)) if status.success() || !attempt.check_status => Ok(()),
        Ok(Ok(status)) => Err(format!("{program} exited with {status}")),
        Ok(Err(e)) => Err(format!("{program}: {e}")),
        Err(_) => {
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
            Ok(())
        }
    }
}

/// The client's `$WSL_INTEROP`, honored only as a socket at `/run/WSL/<n>_interop`. Without it, WSL finds a socket
/// itself.
fn interop_socket(value: &str) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::FileTypeExt;
    let name = value.strip_prefix("/run/WSL/")?;
    let digits = name.strip_suffix("_interop")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        tracing::debug!(value, "Ignoring the client's WSL_INTEROP");
        return None;
    }
    let path = std::path::PathBuf::from(value);
    std::fs::symlink_metadata(&path)
        .is_ok_and(|m| m.file_type().is_socket())
        .then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::process::linux::wsl::Interop;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("mairu-test-wsl-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        /// A shell script that appends its argv, one per line, to `<name>.log` and exits with `status`.
        fn script(&self, name: &str, status: u8) -> std::path::PathBuf {
            use std::os::unix::fs::PermissionsExt;
            let path = self.0.join(name);
            let log = self.0.join(format!("{name}.log"));
            std::fs::write(
                &path,
                format!(
                    "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done >> '{}'\nexit {status}\n",
                    log.display()
                ),
            )
            .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path
        }

        fn log(&self, name: &str) -> Option<String> {
            std::fs::read_to_string(self.0.join(format!("{name}.log"))).ok()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const URL: &str = "https://example.com/authorize?client_id=a&state=b c";

    fn url() -> url::Url {
        url::Url::parse(URL).unwrap()
    }

    #[test]
    fn test_attempts() {
        let launchers = Launchers {
            rundll32: Some("/mnt/c/Windows/System32/rundll32.exe".into()),
            explorer: Some("/mnt/c/Windows/explorer.exe".into()),
        };
        let attempts = launchers.attempts(&url());
        assert_eq!(
            attempts,
            vec![
                Attempt {
                    program: "/mnt/c/Windows/System32/rundll32.exe".into(),
                    args: vec![
                        "url.dll,FileProtocolHandler".to_owned(),
                        "https://example.com/authorize?client_id=a&state=b%20c".to_owned()
                    ],
                    check_status: true,
                },
                Attempt {
                    program: "/mnt/c/Windows/explorer.exe".into(),
                    args: vec!["https://example.com/authorize?client_id=a&state=b%20c".to_owned()],
                    check_status: false,
                },
            ]
        );
        let explorer_only = Launchers {
            rundll32: None,
            ..launchers
        };
        assert_eq!(explorer_only.attempts(&url()).len(), 1);
        assert!(Launchers::default().attempts(&url()).is_empty());
    }

    #[test]
    fn test_locate_with() {
        let dir = TempDir::new("locate");
        std::fs::create_dir_all(dir.0.join("c/Windows/System32")).unwrap();
        std::fs::write(dir.0.join("c/Windows/System32/rundll32.exe"), "").unwrap();
        // A wslpath that maps C:\ under the temp dir, as WSL maps it to /mnt/c.
        let wslpath = dir.0.join("wslpath");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(
                &wslpath,
                format!(
                    "#!/bin/sh\n[ \"$1\" = -u ] || exit 2\nprintf '%s\\n' \"$2\" | sed -e 's|^C:|{}/c|' -e 's|\\\\|/|g'\n",
                    dir.0.display()
                ),
            )
            .unwrap();
            std::fs::set_permissions(&wslpath, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let launchers = Launchers::locate_with(&wslpath);
        assert_eq!(
            launchers,
            Launchers {
                rundll32: Some(dir.0.join("c/Windows/System32/rundll32.exe")),
                explorer: None,
            }
        );
        assert_eq!(
            Launchers::locate_with(&dir.0.join("missing")),
            Launchers::default()
        );
    }

    #[tokio::test]
    async fn test_open_with_rundll32() {
        let dir = TempDir::new("rundll32");
        let launchers = Launchers {
            rundll32: Some(dir.script("rundll32.exe", 0)),
            explorer: Some(dir.script("explorer.exe", 1)),
        };
        let resp = open_with(&launchers.attempts(&url()), None).await;
        assert!(resp.opened, "{}", resp.detail);
        assert_eq!(resp.detail, "rundll32.exe");
        assert_eq!(
            dir.log("rundll32.exe").unwrap(),
            "url.dll,FileProtocolHandler\nhttps://example.com/authorize?client_id=a&state=b%20c\n"
        );
        assert_eq!(dir.log("explorer.exe"), None);
    }

    #[tokio::test]
    async fn test_open_with_explorer_fallback_ignores_status() {
        let dir = TempDir::new("explorer");
        let launchers = Launchers {
            rundll32: Some(dir.script("rundll32.exe", 3)),
            explorer: Some(dir.script("explorer.exe", 1)),
        };
        let resp = open_with(&launchers.attempts(&url()), None).await;
        assert!(resp.opened, "{}", resp.detail);
        assert_eq!(resp.detail, "explorer.exe");
        assert!(dir.log("rundll32.exe").is_some());
        assert_eq!(
            dir.log("explorer.exe").unwrap(),
            "https://example.com/authorize?client_id=a&state=b%20c\n"
        );
    }

    #[tokio::test]
    async fn test_open_with_failure() {
        let dir = TempDir::new("failure");
        let launchers = Launchers {
            rundll32: Some(dir.script("rundll32.exe", 3)),
            explorer: Some(dir.0.join("missing.exe")),
        };
        let resp = open_with(&launchers.attempts(&url()), None).await;
        assert!(!resp.opened);
        assert!(resp.detail.contains("exited with"), "{}", resp.detail);
        assert!(resp.detail.contains("failed to run"), "{}", resp.detail);
    }

    #[tokio::test]
    async fn test_open_url_refusals() {
        let resp = open_url(
            crate::proto::platform::OpenUrlRequest {
                url: "file:///etc/passwd".to_owned(),
                session: None,
            },
            Interop::Enabled,
        )
        .await;
        assert!(!resp.opened);
        assert!(resp.detail.contains("file:"), "{}", resp.detail);

        let resp = open_url(
            crate::proto::platform::OpenUrlRequest {
                url: URL.to_owned(),
                session: None,
            },
            Interop::DisabledByConfig,
        )
        .await;
        assert!(!resp.opened);
        assert!(resp.detail.contains("isolated"), "{}", resp.detail);

        let resp = open_url(
            crate::proto::platform::OpenUrlRequest {
                url: URL.to_owned(),
                session: Some(crate::proto::platform::SessionHint {
                    ssh: true,
                    display: ":0".to_owned(),
                    ..Default::default()
                }),
            },
            Interop::Enabled,
        )
        .await;
        assert!(!resp.opened);
        assert!(resp.detail.contains("SSH"), "{}", resp.detail);
    }

    #[test]
    fn test_refusal_ignores_display() {
        let hint = crate::proto::platform::SessionHint::default();
        assert_eq!(refusal(&hint, Interop::Enabled), None);
        assert_eq!(refusal(&hint, Interop::EnabledPendingRestart), None);
        assert!(refusal(&hint, Interop::DisabledBinfmt).is_some());
    }

    #[test]
    fn test_interop_socket() {
        for value in [
            "",
            "/tmp/1_interop",
            "/run/WSL/_interop",
            "/run/WSL/12_interop/../x",
            "/run/WSL/1a_interop",
            "/run/WSL/../12_interop",
        ] {
            assert_eq!(interop_socket(value), None, "{value}");
        }
        // Well-formed, but not a socket on this host.
        assert_eq!(interop_socket("/run/WSL/1_interop"), None);
    }
}
