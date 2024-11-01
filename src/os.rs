pub(crate) fn set_cloexec<T>(fd: &T, value: bool) -> crate::Result<()>
where
    T: std::os::fd::AsRawFd,
{
    use nix::fcntl::{fcntl, FdFlag, F_GETFD, F_SETFD};
    let mut fdopts = FdFlag::from_bits(fcntl(fd.as_raw_fd(), F_GETFD)?).unwrap();
    fdopts.set(FdFlag::FD_CLOEXEC, value);
    fcntl(fd.as_raw_fd(), F_SETFD(fdopts))?;
    Ok(())
}
