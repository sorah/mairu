pub(crate) fn set_cloexec<T>(fd: &T, value: bool) -> crate::Result<()>
where
    T: std::os::fd::AsFd,
{
    use nix::fcntl::{F_GETFD, F_SETFD, FdFlag, fcntl};
    let mut fdopts = FdFlag::from_bits(fcntl(fd, F_GETFD)?).unwrap();
    fdopts.set(FdFlag::FD_CLOEXEC, value);
    fcntl(fd, F_SETFD(fdopts))?;
    Ok(())
}
