#[derive(clap::Args)]
pub struct AgentArgs {
    /// Run as a daemon.
    #[arg(long, default_value_t = false)]
    daemonize: bool,

    /// Enable logging to file ($XDG_STATE_HOME/mairu/log/*).
    #[arg(long, default_value_t = false)]
    pub log_to_file: bool,

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[arg(long, hide = true)]
    uds_fd: Option<std::os::fd::RawFd>, // See daemonize_reexec() for details
}

pub fn run(args: &AgentArgs) -> Result<(), anyhow::Error> {
    let path = crate::config::socket_path();

    protect_process();
    crate::config::cache_dir_mkpath()?;

    if args.daemonize {
        return serve_on_path_daemon(path);
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        // See daemonize_reexec(2) for details
        if let Some(uds_fd) = args.uds_fd {
            return serve_on_fd(uds_fd);
        }
    }

    serve_on_path(path)
}

fn daemonize() -> Result<(), anyhow::Error> {
    let d = daemonize::Daemonize::new()
        .working_directory(crate::config::runtime_dir())
        .stderr(daemonize::Stdio::keep());

    match d.execute() {
        daemonize::Outcome::Parent(Ok(o)) => {
            return Err(
                crate::Error::SilentlyExitWithCode(std::process::ExitCode::from(
                    o.first_child_exit_code as u8,
                ))
                .into(),
            );
        }
        daemonize::Outcome::Parent(Err(e)) => return Err(e.into()),
        daemonize::Outcome::Child(Ok(_)) => {} // do nothing
        daemonize::Outcome::Child(Err(e)) => return Err(e.into()),
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn daemonize_reexec(
    uds: std::os::unix::net::UnixListener,
    arg0: std::path::PathBuf,
) -> Result<(), anyhow::Error> {
    // We can encounter the following error if we continue without re-exec(2)-ing:
    //
    //     objc[11602]: +[__NSCFConstantString initialize] may have been in progress in another thread when fork() was called.
    //     We cannot safely call it or ignore it in the fork() child process. Crashing instead. Set a breakpoint on objc_initializeAfterForkError to debug.
    //
    // In Mairu's case, most these crashes are triggered in a copy_certificates_from_keychain dispatch queue thread.
    // This is likely relevant to security-framework crate which utilise Security.framework for TLS functionality, and
    // appears to be difficult to avoid; unforeseen risks remain ahead that could cause similar issues.
    //
    // We're avoiding by re-exec(2)-ing itself to prevent the issue at all.
    //
    // See also: https://www.sealiesoftware.com/blog/archive/2017/6/5/Objective-C_and_fork_in_macOS_1013.html
    use std::os::fd::IntoRawFd;
    use std::os::unix::process::CommandExt;

    let raw_fd = uds.into_raw_fd();
    crate::os::set_cloexec(&raw_fd, false)?;

    let args = std::env::args()
        .skip(1)
        .map(|x| x.to_owned())
        .filter(|x| x.as_str() != "--daemonize")
        .chain(["--uds-fd".to_string(), raw_fd.to_string()])
        .collect::<Vec<_>>();

    tracing::debug!(arg0 = ?arg0, args = ?args, "Re-exec(2)-ing");

    let err = std::process::Command::new(arg0).args(args).exec();
    panic!("exec(2) failed to re-exec itself after daemonize: {err}");
}

fn protect_process() {
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits(0o077).unwrap());

    #[cfg(target_os = "linux")]
    nix::sys::prctl::set_dumpable(false).unwrap();
    #[cfg(target_os = "macos")]
    macos_pt_deny_attach().unwrap();

    nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0).unwrap();

    if let Err(e) = nix::sys::mman::mlockall(nix::sys::mman::MlockAllFlags::all()) {
        tracing::warn!(err = ?e, "Failed to mlockall(2), but continuing");
    }
}

#[cfg(target_os = "macos")]
fn macos_pt_deny_attach() -> Result<(), anyhow::Error> {
    let res = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    Ok(nix::errno::Errno::result(res).map(drop)?)
}

#[tokio::main]
pub async fn serve_on_path(path: std::path::PathBuf) -> Result<(), anyhow::Error> {
    tracing::info!(path = ?path, "Server starting");
    let uds = try_bind_or_check_liveness(&path, false).await?;
    serve(uds).await
}

#[tokio::main]
pub async fn serve_on_fd(raw_fd: std::os::fd::RawFd) -> Result<(), anyhow::Error> {
    use std::os::fd::FromRawFd;
    tracing::info!(raw_fd = ?raw_fd, "Server starting using given fd");
    crate::os::set_cloexec(&raw_fd, true)?;
    // SAFETY: we validate liveness roughly by resetting O_CLOXEC
    let uds = unsafe { std::os::unix::net::UnixListener::from_raw_fd(raw_fd) };
    uds.set_nonblocking(true)?;
    serve(tokio::net::UnixListener::from_std(uds)?).await
}

#[cfg_attr(any(target_os = "macos", target_os = "ios"), allow(unreachable_code))]
pub fn serve_on_path_daemon(path: std::path::PathBuf) -> Result<(), anyhow::Error> {
    tracing::debug!(path = ?path, "Server starting as a daemon");
    let uds = try_bind_or_check_liveness_std(&path)?;
    tracing::info!(path = ?path, "Agent starting as a daemon");

    // See daemonize_reexec() for details
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let arg0 = process_path::get_executable_path().expect("Can't get executable path");

    daemonize()?;

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    return daemonize_reexec(uds, arg0);

    serve_on_path_daemon2(uds)
}

#[tokio::main]
pub async fn serve_on_path_daemon2(
    uds: std::os::unix::net::UnixListener,
) -> Result<(), anyhow::Error> {
    serve(tokio::net::UnixListener::from_std(uds)?).await
}

pub async fn serve(uds: tokio::net::UnixListener) -> Result<(), anyhow::Error> {
    let uds_stream = tokio_stream::wrappers::UnixListenerStream::new(uds);
    let agent = crate::agent::Agent::new();

    tonic::transport::Server::builder()
        .add_service(crate::proto::agent_server::AgentServer::new(agent))
        .serve_with_incoming(uds_stream)
        .await?;

    Ok(())
}

#[async_recursion::async_recursion(?Send)]
async fn try_bind_or_check_liveness(
    path: &std::path::PathBuf,
    retry: bool,
) -> Result<tokio::net::UnixListener, anyhow::Error> {
    match tokio::net::UnixListener::bind(path) {
        Ok(s) => Ok(s),
        Err(e) => {
            if retry || e.kind() != std::io::ErrorKind::AddrInUse {
                tracing::error!(err = ?e, path = ?path, "Failed to bind socket");
                return Err(e.into());
            }
            // Attempt to connect and say hello.
            check_liveness(path).await?;
            try_bind_or_check_liveness(path, true).await
        }
    }
}

fn try_bind_or_check_liveness_std(
    path: &std::path::PathBuf,
) -> Result<std::os::unix::net::UnixListener, anyhow::Error> {
    match std::os::unix::net::UnixListener::bind(path) {
        Ok(s) => Ok(s),
        Err(e) => {
            if e.kind() != std::io::ErrorKind::AddrInUse {
                return Err(e.into());
            }

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(check_liveness(path))?;

            Ok(std::os::unix::net::UnixListener::bind(path)?)
        }
    }
}

#[cfg(unix)]
async fn check_liveness(path: &std::path::PathBuf) -> Result<(), anyhow::Error> {
    use std::os::unix::fs::FileTypeExt;
    if let Err(e) = crate::agent::connect_to_agent_with_path(&path).await {
        tracing::info!(err = ?e, path = ?path, "Attempting to replace the stale socket file as failing to connect to the existing agent");
        let stat = tokio::fs::symlink_metadata(&path).await?;
        if stat.file_type().is_socket() {
            tokio::fs::remove_file(&path).await?;
        } else {
            anyhow::bail!(
                "A file at the socket path ({path}) is not a socket, aborting",
                path = path.display()
            );
        }
        tracing::debug!(err = ?e, path = ?path, "removed stale socket file");
        return Ok(());
    }
    anyhow::bail!("There is already running agent on the same socket path");
}

pub async fn connect_or_start() -> Result<crate::agent::AgentConn, anyhow::Error> {
    let liveness = crate::agent::connect_to_agent().await;
    match liveness {
        Ok(c) => return Ok(c),
        Err(e) => {
            if std::env::var_os("MAIRU_NO_AUTO_AGENT").is_some() {
                return Err(e.into());
            }
            tracing::info!("Starting the agent");
            tracing::debug!(err = ?e, "Starting the agent");
        }
    }

    spawn_agent().await?;

    let fut = attempt_connect_to_agent_loop();
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(20), fut);
    match timeout.await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(_)) => unreachable!(),
        Err(_) => {
            anyhow::bail!("Failed to launch and connect to the agent");
        }
    }
}

async fn attempt_connect_to_agent_loop() -> Result<crate::agent::AgentConn, anyhow::Error> {
    loop {
        match crate::agent::connect_to_agent().await {
            Ok(c) => return Ok(c),
            Err(e) => tracing::debug!(err = ?e, "Waiting for agent to start"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

pub async fn spawn_agent() -> Result<(), anyhow::Error> {
    let arg0 = process_path::get_executable_path().expect("Can't get executable path");
    tokio::process::Command::new(arg0)
        .args(["agent", "--log-to-file", "--daemonize"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(false)
        .status()
        .await?;
    Ok(())
}
