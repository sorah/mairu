#[derive(clap::Args)]
pub struct AgentArgs {
    /// Run as a daemon.
    #[arg(long, default_value_t = false)]
    daemonize: bool,

    /// Enable logging to file ($XDG_STATE_HOME/mairu/log/*).
    #[arg(long, default_value_t = false)]
    pub log_to_file: bool,
}

pub fn run(args: &AgentArgs) -> Result<(), anyhow::Error> {
    let path = crate::config::socket_path();

    protect_process();
    crate::config::cache_dir_mkpath()?;

    if args.daemonize {
        serve_on_path_daemon(path)
    } else {
        serve_on_path(path)
    }
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
        daemonize::Outcome::Child(Ok(_)) => {}
        daemonize::Outcome::Child(Err(e)) => return Err(e.into()),
    }
    Ok(())
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

pub fn serve_on_path_daemon(path: std::path::PathBuf) -> Result<(), anyhow::Error> {
    tracing::debug!(path = ?path, "Server starting as a daemon");
    let uds = try_bind_or_check_liveness_std(&path)?;
    tracing::info!(path = ?path, "Agent starting as a daemon");
    daemonize()?;
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

async fn check_liveness(path: &std::path::PathBuf) -> Result<(), anyhow::Error> {
    if let Err(e) = crate::agent::connect_to_agent_with_path(&path).await {
        tracing::info!(err = ?e, path = ?path, "Attempting to replace the stale socket file as failing to connect to the existing agent");
        tokio::fs::remove_file(&path).await?;
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
