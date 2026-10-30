//! The platform helper as a standalone executable, built without the client and agent.

fn main() -> std::process::ExitCode {
    mairu::hardening::Hardening::detect();
    match parse_fd(std::env::args_os().skip(1)) {
        Some(fd) => mairu::cmd::platform_helper::run(fd),
        None => {
            eprintln!("usage: mairu-platform-helper --fd <n>");
            std::process::ExitCode::from(2)
        }
    }
}

fn parse_fd(mut args: impl Iterator<Item = std::ffi::OsString>) -> Option<std::os::fd::RawFd> {
    if args.next()? != "--fd" {
        return None;
    }
    let fd = args.next()?.to_str()?.parse().ok()?;
    args.next().is_none().then_some(fd)
}
