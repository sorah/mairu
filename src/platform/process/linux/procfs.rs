//! `/proc/<pid>` parsing. Callers confirm afterwards that the process is still alive, so the values cannot belong
//! to a recycled pid.

/// Fields of `/proc/<pid>/stat`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub ppid: i32,
    pub pgrp: i32,
    pub session: i32,
    pub tty_nr: i32,
    /// Clock ticks since boot.
    pub start_time: u64,
}

impl Stat {
    pub fn read(pid: u32) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        Self::parse(&content).ok_or_else(|| malformed(pid, "stat"))
    }

    /// Splits at the last `)`, because comm may contain spaces and parentheses.
    pub fn parse(content: &str) -> Option<Self> {
        let (_, rest) = content.rsplit_once(')')?;
        // rest starts at field 3 (state).
        let fields: Vec<&str> = rest.split_whitespace().collect();
        let field = |n: usize| fields.get(n - 3).copied();
        Some(Self {
            ppid: field(4)?.parse().ok()?,
            pgrp: field(5)?.parse().ok()?,
            session: field(6)?.parse().ok()?,
            tty_nr: field(7)?.parse().ok()?,
            start_time: field(22)?.parse().ok()?,
        })
    }
}

/// The device path of a `tty_nr` from `/proc/<pid>/stat`, for display.
pub fn tty_path(tty_nr: i32) -> Option<String> {
    if tty_nr == 0 {
        return None;
    }
    let nr = tty_nr as u32;
    let major = (nr >> 8) & 0xfff;
    let minor = (nr & 0xff) | ((nr >> 12) & 0xfff00);
    Some(match major {
        136..=143 => format!("/dev/pts/{}", (major - 136) * 256 + minor),
        4 if minor < 64 => format!("/dev/tty{minor}"),
        4 => format!("/dev/ttyS{}", minor - 64),
        _ => format!("tty {major}:{minor}"),
    })
}

/// The real gid from the `Gid:` line of `/proc/<pid>/status`. Readable even for a non-dumpable process.
pub fn read_real_gid(pid: u32) -> std::io::Result<u32> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    parse_real_gid(&content).ok_or_else(|| malformed(pid, "status"))
}

pub fn parse_real_gid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Gid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

pub fn read_comm(pid: u32) -> std::io::Result<String> {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))?;
    Ok(comm.trim_end_matches('\n').to_owned())
}

/// Fails for a process that is not dumpable.
pub fn read_exe(pid: u32) -> std::io::Result<std::path::PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
}

/// For display and matching only, never for trust: the process can rewrite it.
pub fn read_cmdline(pid: u32) -> std::io::Result<Vec<std::ffi::OsString>> {
    let content = std::fs::read(format!("/proc/{pid}/cmdline"))?;
    Ok(parse_cmdline(&content))
}

pub fn parse_cmdline(content: &[u8]) -> Vec<std::ffi::OsString> {
    use std::os::unix::ffi::OsStrExt;
    content
        .strip_suffix(b"\0")
        .unwrap_or(content)
        .split(|b| *b == 0)
        .filter(|_| !content.is_empty())
        .map(|a| std::ffi::OsStr::from_bytes(a).to_owned())
        .collect()
}

fn malformed(pid: u32, file: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("malformed /proc/{pid}/{file}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stat_parse_tricky_comm() {
        let content = "4242 (a) (b) c) S 1 4240 4239 34816 4242 4194560 100 0 0 0 1 2 0 0 20 0 1 0 8812345 1000 100 18446744073709551615\n";
        assert_eq!(
            Stat::parse(content),
            Some(Stat {
                ppid: 1,
                pgrp: 4240,
                session: 4239,
                tty_nr: 34816,
                start_time: 8812345,
            })
        );
    }

    #[test]
    fn test_stat_parse_truncated() {
        assert_eq!(Stat::parse("4242 (sh) S 1 4240"), None);
        assert_eq!(Stat::parse("4242 sh S 1 4240"), None);
    }

    #[test]
    fn test_stat_read_self() {
        let stat = Stat::read(std::process::id()).unwrap();
        assert_eq!(
            stat.ppid,
            nix::unistd::getppid().as_raw(),
            "ppid of this process"
        );
        assert!(stat.start_time > 0);
    }

    #[test]
    fn test_tty_path() {
        assert_eq!(tty_path(0), None);
        assert_eq!(tty_path(34816 + 3), Some("/dev/pts/3".to_owned()));
        // major 136, minor 300
        assert_eq!(
            tty_path((136 << 8) | (300 & 0xff) | ((300 & 0xfff00) << 12)),
            Some("/dev/pts/300".to_owned())
        );
        assert_eq!(tty_path((4 << 8) | 2), Some("/dev/tty2".to_owned()));
        assert_eq!(tty_path((4 << 8) | 65), Some("/dev/ttyS1".to_owned()));
    }

    #[test]
    fn test_parse_real_gid() {
        let status = "Name:\tmairu\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t973\t973\t1000\nGroups:\t1000\n";
        assert_eq!(parse_real_gid(status), Some(1000));
        assert_eq!(parse_real_gid("Name:\tmairu\n"), None);
    }

    #[test]
    fn test_read_real_gid_self() {
        assert_eq!(
            read_real_gid(std::process::id()).unwrap(),
            nix::unistd::getgid().as_raw()
        );
    }

    #[test]
    fn test_parse_cmdline() {
        assert_eq!(
            parse_cmdline(b"mairu\0agent\0--daemonize\0"),
            vec!["mairu", "agent", "--daemonize"]
        );
        assert_eq!(parse_cmdline(b"rewritten title"), vec!["rewritten title"]);
        assert!(parse_cmdline(b"").is_empty());
    }
}
