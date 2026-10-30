#![cfg(all(feature = "cli", target_os = "linux"))]

use mairu::platform::PlatformServices;

const MAIRU: &str = env!("CARGO_BIN_EXE_mairu");

fn launcher() -> mairu::platform::helper::Launcher {
    mairu::platform::helper::Launcher::new(MAIRU, ["platform-helper"])
        .respawn_interval(std::time::Duration::from_secs(3))
}

async fn authorize(
    helper: &mairu::platform::helper::HelperClient,
) -> mairu::proto::platform::AuthorizeResponse {
    helper
        .authorize(mairu::proto::platform::AuthorizeRequest::default())
        .await
}

#[tokio::test]
async fn test_helper_starts_verified_and_serves() {
    let helper = mairu::platform::helper::HelperClient::start(launcher()).await;
    let description = helper.describe();
    assert!(
        description.starts_with("running pid=") && description.ends_with(" verified"),
        "{description}"
    );
    let caps = helper.capabilities().await;
    assert_eq!(
        caps.authorization(),
        mairu::proto::platform::AuthorizationFacility::None
    );
    // The fallback backend answers, not the client's own fail-closed path.
    let resp = authorize(&helper).await;
    assert_eq!(
        resp.result(),
        mairu::proto::platform::authorize_response::Result::Unavailable
    );
    assert_eq!(resp.reason, "no-authorization-facility");
}

#[tokio::test]
async fn test_killed_helper_fails_closed_and_respawns() {
    let helper = mairu::platform::helper::HelperClient::start(launcher()).await;
    let pid = helper.pid().expect("helper running");
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid as i32),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let resp = authorize(&helper).await;
    assert_eq!(resp.reason, mairu::platform::helper::REASON_UNAVAILABLE);

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Some(new_pid) = helper.pid()
            && new_pid != pid
        {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "not respawned");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(authorize(&helper).await.reason, "no-authorization-facility");
}

/// Runs `mairu platform-helper --fd 3` through `sh`, with `fd` as fd 3. Returns the exit code.
fn run_via_shell(script: &str, fd: std::os::fd::RawFd) -> Option<i32> {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.args(["-c", script, "sh", MAIRU])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: dup2 is async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(fd, 3) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.status().unwrap().code()
}

#[test]
fn test_helper_refuses_a_caller_other_than_its_parent() {
    use std::os::fd::AsRawFd;
    // This test process created the pair, but the helper's parent is the shell.
    let (_ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let code = run_via_shell(
        r#""$1" platform-helper --fd 3; exit $?"#,
        theirs.as_raw_fd(),
    );
    assert_eq!(code, Some(3));
}

#[test]
fn test_helper_started_by_hand_refuses() {
    let status = std::process::Command::new(MAIRU)
        .args(["platform-helper", "--fd", "0"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(3));
}

#[test]
fn test_helper_exits_when_the_parent_closes_its_end() {
    use std::os::fd::AsRawFd;
    // exec keeps the shell's pid, so the helper's parent is this process, which created the pair.
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut child = {
        use std::os::unix::process::CommandExt;
        let fd = theirs.as_raw_fd();
        let mut cmd = std::process::Command::new(MAIRU);
        cmd.args(["platform-helper", "--fd", "3"])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // SAFETY: dup2 is async-signal-safe.
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(fd, 3) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd.spawn().unwrap()
    };
    drop(theirs);
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert!(child.try_wait().unwrap().is_none(), "helper exited early");
    drop(ours);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(0));
            break;
        }
        assert!(std::time::Instant::now() < deadline, "helper outlived EOF");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
