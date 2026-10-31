//! The platform helper: serves `mairu.platform.PlatformHelper` to its parent agent over an inherited socketpair.

/// Runs the helper on the inherited `fd` until the agent closes its end. `Hardening::detect` must have run.
pub fn run(fd: std::os::fd::RawFd) -> std::process::ExitCode {
    init_log();
    protect_process();

    let stream = match take_socket(fd) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(fd, err = %e, "Refusing to serve: the fd is not an inherited socket");
            return std::process::ExitCode::from(crate::platform::HELPER_EXIT_PARENT_UNVERIFIED);
        }
    };
    let parent = {
        use std::os::fd::AsFd;
        match crate::platform::process().verify_parent(stream.as_fd()) {
            Ok(pid) => pid,
            Err(e) => {
                tracing::error!(err = %e, "Refusing to serve a process that is not the parent agent");
                return std::process::ExitCode::from(
                    crate::platform::HELPER_EXIT_PARENT_UNVERIFIED,
                );
            }
        }
    };
    tracing::debug!(parent, "Serving the parent agent");

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(err = %e, "Failed to start the runtime");
            return std::process::ExitCode::FAILURE;
        }
    };
    let service = HelperService {
        services: crate::platform::services(),
        uid: nix::unistd::geteuid().as_raw(),
    };
    match rt.block_on(serve(stream, service, parent)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(err = %e, "Platform helper failed");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Logs to stderr, which the agent forwards into its own log.
fn init_log() {
    let filter = std::env::var("MAIRU_LOG").unwrap_or_else(|_| "mairu=info".to_owned());
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .without_time()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .try_init();
}

fn protect_process() {
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
    #[cfg(target_os = "linux")]
    if let Err(e) = nix::sys::prctl::set_dumpable(false) {
        tracing::warn!(err = %e, "Failed to make the helper non-dumpable");
    }
    if let Err(e) = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0) {
        tracing::warn!(err = %e, "Failed to disable core dumps");
    }
}

fn take_socket(fd: std::os::fd::RawFd) -> std::io::Result<std::os::unix::net::UnixStream> {
    use std::os::fd::FromRawFd;
    // SAFETY: fstat only reads the descriptor's metadata, and fails cleanly on a closed fd.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    let stat = nix::sys::stat::fstat(borrowed)?;
    if nix::sys::stat::SFlag::from_bits_truncate(stat.st_mode) & nix::sys::stat::SFlag::S_IFMT
        != nix::sys::stat::SFlag::S_IFSOCK
    {
        return Err(std::io::Error::other(format!("fd {fd} is not a socket")));
    }
    {
        use nix::fcntl::{F_SETFD, FdFlag, fcntl};
        fcntl(borrowed, F_SETFD(FdFlag::FD_CLOEXEC))?;
    }
    // SAFETY: the fd is an open socket inherited from the parent, and nothing else in this process owns it.
    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    stream.set_nonblocking(true)?;
    Ok(stream)
}

async fn serve(
    stream: std::os::unix::net::UnixStream,
    service: HelperService,
    parent: u32,
) -> Result<(), anyhow::Error> {
    use futures::StreamExt;
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel::<()>();
    let conn = HelperConn {
        inner: tokio::net::UnixStream::from_std(stream)?,
        _closed: closed_tx,
    };
    // One connection, then nothing more: the server must not end before the connection does.
    let incoming = futures::stream::once(async move { Ok::<_, std::io::Error>(conn) })
        .chain(futures::stream::pending());
    let parent_pid = nix::unistd::Pid::from_raw(i32::try_from(parent).unwrap_or(0));
    tonic::transport::Server::builder()
        .add_service(
            crate::proto::platform::platform_helper_server::PlatformHelperServer::new(service),
        )
        .serve_with_incoming_shutdown(incoming, async move {
            tokio::select! {
                _ = closed_rx => tracing::debug!("The agent closed the connection"),
                _ = crate::ppid::wait_for_parent_process_die(parent_pid) => {
                    tracing::debug!("The parent agent exited");
                }
            }
        })
        .await?;
    Ok(())
}

/// The connection to the agent. Dropping it, at EOF, ends the helper.
struct HelperConn {
    inner: tokio::net::UnixStream,
    _closed: tokio::sync::oneshot::Sender<()>,
}

impl tonic::transport::server::Connected for HelperConn {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl tokio::io::AsyncRead for HelperConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for HelperConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Serves [`crate::platform::PlatformServices`] after the checks every request gets.
#[derive(Debug)]
pub struct HelperService {
    services: &'static dyn crate::platform::PlatformServices,
    uid: u32,
}

impl HelperService {
    fn require_own_uid(&self, uid: u32) -> Result<(), tonic::Status> {
        if uid != self.uid {
            return Err(tonic::Status::permission_denied(format!(
                "request for uid {uid}; this helper serves uid {}",
                self.uid
            )));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl crate::proto::platform::platform_helper_server::PlatformHelper for HelperService {
    async fn get_capabilities(
        &self,
        request: tonic::Request<crate::proto::platform::GetCapabilitiesRequest>,
    ) -> Result<tonic::Response<crate::proto::platform::Capabilities>, tonic::Status> {
        Ok(tonic::Response::new(
            self.services.capabilities(request.into_inner()).await,
        ))
    }

    async fn authorize(
        &self,
        request: tonic::Request<crate::proto::platform::AuthorizeRequest>,
    ) -> Result<tonic::Response<crate::proto::platform::AuthorizeResponse>, tonic::Status> {
        let req = request.into_inner();
        if let Some(subject) = &req.subject {
            self.require_own_uid(subject.uid)?;
        }
        Ok(tonic::Response::new(self.services.authorize(req).await))
    }

    async fn notify(
        &self,
        request: tonic::Request<crate::proto::platform::NotifyRequest>,
    ) -> Result<tonic::Response<crate::proto::platform::NotifyResponse>, tonic::Status> {
        Ok(tonic::Response::new(
            self.services.notify(request.into_inner()).await,
        ))
    }

    async fn open_url(
        &self,
        request: tonic::Request<crate::proto::platform::OpenUrlRequest>,
    ) -> Result<tonic::Response<crate::proto::platform::OpenUrlResponse>, tonic::Status> {
        Ok(tonic::Response::new(
            self.services.open_url(request.into_inner()).await,
        ))
    }

    async fn record_integrity(
        &self,
        request: tonic::Request<crate::proto::platform::RecordIntegrityRequest>,
    ) -> Result<tonic::Response<crate::proto::platform::RecordIntegrityResponse>, tonic::Status>
    {
        let req = request.into_inner();
        self.require_own_uid(req.uid)?;
        Ok(tonic::Response::new(
            self.services.record_integrity(req).await,
        ))
    }

    async fn verify_integrity(
        &self,
        request: tonic::Request<crate::proto::platform::VerifyIntegrityRequest>,
    ) -> Result<tonic::Response<crate::proto::platform::VerifyIntegrityResponse>, tonic::Status>
    {
        let req = request.into_inner();
        self.require_own_uid(req.uid)?;
        Ok(tonic::Response::new(
            self.services.verify_integrity(req).await,
        ))
    }

    async fn reset_integrity(
        &self,
        request: tonic::Request<crate::proto::platform::ResetIntegrityRequest>,
    ) -> Result<tonic::Response<crate::proto::platform::ResetIntegrityResponse>, tonic::Status>
    {
        self.require_own_uid(request.get_ref().uid)?;
        Err(tonic::Status::unimplemented(
            "ResetIntegrity is not supported on this OS",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::platform::platform_helper_server::PlatformHelper;

    fn service() -> HelperService {
        HelperService {
            services: &crate::platform::services::fallback::FallbackServices,
            uid: 1000,
        }
    }

    #[tokio::test]
    async fn test_foreign_uid_is_rejected() {
        let svc = service();
        let status = svc
            .verify_integrity(tonic::Request::new(
                crate::proto::platform::VerifyIntegrityRequest {
                    name: "policy".to_owned(),
                    uid: 1001,
                    digest: vec![0; 32],
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        let status = svc
            .record_integrity(tonic::Request::new(
                crate::proto::platform::RecordIntegrityRequest {
                    name: "policy".to_owned(),
                    uid: 0,
                    record: None,
                    stores: vec![],
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        let status = svc
            .authorize(tonic::Request::new(
                crate::proto::platform::AuthorizeRequest {
                    subject: Some(crate::proto::platform::Process {
                        uid: 1001,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn test_own_uid_is_served() {
        let resp = service()
            .verify_integrity(tonic::Request::new(
                crate::proto::platform::VerifyIntegrityRequest {
                    name: "policy".to_owned(),
                    uid: 1000,
                    digest: vec![0; 32],
                },
            ))
            .await
            .unwrap();
        assert!(resp.into_inner().results.is_empty());
    }

    #[tokio::test]
    async fn test_reset_integrity_unimplemented() {
        let status = service()
            .reset_integrity(tonic::Request::new(
                crate::proto::platform::ResetIntegrityRequest {
                    name: "policy".to_owned(),
                    uid: 1000,
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unimplemented);
    }

    #[test]
    fn test_take_socket_refuses_non_socket() {
        use std::os::fd::IntoRawFd;
        let fd = std::fs::File::open("/dev/null").unwrap().into_raw_fd();
        assert!(take_socket(fd).is_err());
        // SAFETY: take_socket did not take ownership of the fd.
        drop(unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) });
    }
}
