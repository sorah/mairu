#[derive(clap::Args)]
pub struct AgentArgs {}

pub fn run(args: &AgentArgs) -> Result<(), anyhow::Error> {
    protect_process();

    let path = crate::config::socket_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    serve(path, args)
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
    let res = unsafe {
        libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
    };
    nix::errno::Errno::result(res).map(drop)
}

#[tokio::main]
pub async fn serve(path: std::path::PathBuf, _args: &AgentArgs) -> Result<(), anyhow::Error> {
    let uds = try_bind_or_check_liveness(&path, false).await?;
    let uds_stream = tokio_stream::wrappers::UnixListenerStream::new(uds);

    let agent = crate::agent::Agent::new();

    tracing::info!(path = ?path, "Server starting");

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
            if let Err(e2) = crate::agent::connect_to_agent_with_path(&path).await {
                tracing::info!(err = ?e2, path = ?path, "Attempting to replace the stale socket file as failing to connect to the existing agent");
                tokio::fs::remove_file(&path).await?;
                tracing::debug!(err = ?e2, path = ?path, "removed stale socket file");
                return try_bind_or_check_liveness(path, true).await;
            }
            tracing::error!(err = ?e, path = ?path, "There is already running agent on the same socket path");
            anyhow::bail!("There is already running agent on the same socket path");
        }
    }
}

pub async fn connect_or_start() -> Result<crate::agent::AgentConn, anyhow::Error> {
    Ok(crate::agent::connect_to_agent().await?)
}
