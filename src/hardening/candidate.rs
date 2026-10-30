//! Ownership checks for a hardened copy and the directories it lives in. The rules are pure functions over stat
//! results, so they can be tested without root.

const FUSE_SUPER_MAGIC: i64 = 0x65735546;

/// The parts of `stat` the rules look at. `mode` includes the file type bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inode {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

/// The parts of `statfs`/`statvfs` the rules look at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Filesystem {
    pub magic: i64,
    pub nosuid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Rejection {
    #[error("not a regular file")]
    NotRegularFile,
    #[error("not a directory")]
    NotDirectory,
    #[error("owned by uid {0}, not root")]
    NotRootOwned(u32),
    #[error("writable by group or others (mode {0:o})")]
    Writable(u32),
    #[error("not setgid")]
    NotSetgid,
    #[error("its group is gid {0}, not the `mairu` group")]
    WrongGroup(u32),
    #[error("not executable by others")]
    NotExecutable,
    #[error("on a FUSE filesystem")]
    Fuse,
    #[error("on a nosuid mount")]
    NoSuid,
    #[error("parent directory {path}: {reason}")]
    Ancestor {
        path: std::path::PathBuf,
        reason: Box<Rejection>,
    },
    #[error("{0}")]
    Io(String),
}

impl Inode {
    pub fn check_root_owned_file(&self) -> Result<(), Rejection> {
        if self.mode & libc::S_IFMT != libc::S_IFREG {
            return Err(Rejection::NotRegularFile);
        }
        self.check_owner()
    }

    pub fn check_root_owned_dir(&self) -> Result<(), Rejection> {
        if self.mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(Rejection::NotDirectory);
        }
        self.check_owner()
    }

    /// A hardened copy: root-owned, setgid to the marker group, and executable by the users it serves.
    pub fn check_candidate(&self, marker: u32) -> Result<(), Rejection> {
        self.check_root_owned_file()?;
        if self.gid != marker {
            return Err(Rejection::WrongGroup(self.gid));
        }
        if self.mode & libc::S_ISGID == 0 {
            return Err(Rejection::NotSetgid);
        }
        if self.mode & 0o001 == 0 {
            return Err(Rejection::NotExecutable);
        }
        Ok(())
    }

    fn check_owner(&self) -> Result<(), Rejection> {
        if self.uid != 0 {
            return Err(Rejection::NotRootOwned(self.uid));
        }
        if self.mode & 0o022 != 0 {
            return Err(Rejection::Writable(self.mode & 0o7777));
        }
        Ok(())
    }

    fn stat(path: &std::path::Path) -> Result<Self, Rejection> {
        let st = nix::sys::stat::lstat(path).map_err(|e| io_rejection(path, e))?;
        Ok(Self {
            uid: st.st_uid,
            gid: st.st_gid,
            mode: st.st_mode,
        })
    }
}

impl Filesystem {
    /// A setgid binary only carries the marker from a mount that honors setgid bits.
    pub fn check(&self, needs_suid: bool) -> Result<(), Rejection> {
        if self.magic == FUSE_SUPER_MAGIC {
            return Err(Rejection::Fuse);
        }
        if needs_suid && self.nosuid {
            return Err(Rejection::NoSuid);
        }
        Ok(())
    }

    fn stat(path: &std::path::Path) -> Result<Self, Rejection> {
        let fs = nix::sys::statfs::statfs(path).map_err(|e| io_rejection(path, e))?;
        let vfs = nix::sys::statvfs::statvfs(path).map_err(|e| io_rejection(path, e))?;
        Ok(Self {
            #[allow(clippy::unnecessary_cast)] // the width of f_type differs by architecture and libc
            magic: fs.filesystem_type().0 as i64,
            nosuid: vfs
                .flags()
                .contains(nix::sys::statvfs::FsFlags::ST_NOSUID),
        })
    }
}

/// Validates a hardened copy at `path` for the marker gid `marker`, returning its canonical path.
pub fn hardened_candidate(
    path: &std::path::Path,
    marker: u32,
) -> Result<std::path::PathBuf, Rejection> {
    let path = canonicalize(path)?;
    Filesystem::stat(&path)?.check(true)?;
    Inode::stat(&path)?.check_candidate(marker)?;
    check_ancestors(&path)?;
    Ok(path)
}

/// Validates that the file at `path` and its ancestors cannot be modified by anyone but root.
pub fn root_owned_file(path: &std::path::Path) -> Result<std::path::PathBuf, Rejection> {
    let path = canonicalize(path)?;
    Filesystem::stat(&path)?.check(false)?;
    Inode::stat(&path)?.check_root_owned_file()?;
    check_ancestors(&path)?;
    Ok(path)
}

/// Validates that the directory at `path` and its ancestors cannot be modified by anyone but root.
pub fn root_owned_dir(path: &std::path::Path) -> Result<std::path::PathBuf, Rejection> {
    let path = canonicalize(path)?;
    Filesystem::stat(&path)?.check(false)?;
    Inode::stat(&path)?.check_root_owned_dir()?;
    check_ancestors(&path)?;
    Ok(path)
}

fn check_ancestors(path: &std::path::Path) -> Result<(), Rejection> {
    for ancestor in path.ancestors().skip(1) {
        Inode::stat(ancestor)?
            .check_root_owned_dir()
            .map_err(|reason| Rejection::Ancestor {
                path: ancestor.to_owned(),
                reason: Box::new(reason),
            })?;
    }
    Ok(())
}

fn canonicalize(path: &std::path::Path) -> Result<std::path::PathBuf, Rejection> {
    std::fs::canonicalize(path).map_err(|e| Rejection::Io(format!("{}: {e}", path.display())))
}

fn io_rejection(path: &std::path::Path, e: nix::Error) -> Rejection {
    Rejection::Io(format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: u32 = 973;

    fn file(uid: u32, gid: u32, perm: u32) -> Inode {
        Inode {
            uid,
            gid,
            mode: libc::S_IFREG | perm,
        }
    }

    fn dir(uid: u32, perm: u32) -> Inode {
        Inode {
            uid,
            gid: 0,
            mode: libc::S_IFDIR | perm,
        }
    }

    #[test]
    fn test_candidate_valid() {
        assert_eq!(file(0, MARKER, 0o2755).check_candidate(MARKER), Ok(()));
        assert_eq!(file(0, MARKER, 0o2711).check_candidate(MARKER), Ok(()));
    }

    #[test]
    fn test_candidate_not_root_owned() {
        assert_eq!(
            file(1000, MARKER, 0o2755).check_candidate(MARKER),
            Err(Rejection::NotRootOwned(1000))
        );
    }

    #[test]
    fn test_candidate_wrong_group() {
        assert_eq!(
            file(0, 0, 0o2755).check_candidate(MARKER),
            Err(Rejection::WrongGroup(0))
        );
    }

    #[test]
    fn test_candidate_not_setgid() {
        assert_eq!(
            file(0, MARKER, 0o0755).check_candidate(MARKER),
            Err(Rejection::NotSetgid)
        );
    }

    #[test]
    fn test_candidate_writable() {
        assert_eq!(
            file(0, MARKER, 0o2775).check_candidate(MARKER),
            Err(Rejection::Writable(0o2775))
        );
        assert_eq!(
            file(0, MARKER, 0o2757).check_candidate(MARKER),
            Err(Rejection::Writable(0o2757))
        );
    }

    #[test]
    fn test_candidate_not_executable() {
        assert_eq!(
            file(0, MARKER, 0o2750).check_candidate(MARKER),
            Err(Rejection::NotExecutable)
        );
    }

    #[test]
    fn test_candidate_not_regular_file() {
        let symlink = Inode {
            uid: 0,
            gid: MARKER,
            mode: libc::S_IFLNK | 0o2755,
        };
        assert_eq!(
            symlink.check_candidate(MARKER),
            Err(Rejection::NotRegularFile)
        );
        assert_eq!(
            dir(0, 0o2755).check_candidate(MARKER),
            Err(Rejection::NotRegularFile)
        );
    }

    #[test]
    fn test_root_owned_file() {
        assert_eq!(file(0, 0, 0o755).check_root_owned_file(), Ok(()));
        assert_eq!(file(0, 50, 0o644).check_root_owned_file(), Ok(()));
        assert_eq!(
            file(1000, 1000, 0o755).check_root_owned_file(),
            Err(Rejection::NotRootOwned(1000))
        );
        assert_eq!(
            file(0, 0, 0o666).check_root_owned_file(),
            Err(Rejection::Writable(0o666))
        );
    }

    #[test]
    fn test_ancestor() {
        assert_eq!(dir(0, 0o755).check_root_owned_dir(), Ok(()));
        assert_eq!(
            dir(1000, 0o755).check_root_owned_dir(),
            Err(Rejection::NotRootOwned(1000))
        );
        assert_eq!(
            dir(0, 0o1777).check_root_owned_dir(),
            Err(Rejection::Writable(0o1777))
        );
        assert_eq!(
            dir(0, 0o775).check_root_owned_dir(),
            Err(Rejection::Writable(0o775))
        );
        assert_eq!(
            file(0, 0, 0o755).check_root_owned_dir(),
            Err(Rejection::NotDirectory)
        );
    }

    #[test]
    fn test_filesystem() {
        let ext4 = Filesystem {
            magic: 0xef53,
            nosuid: false,
        };
        assert_eq!(ext4.check(true), Ok(()));
        let fuse = Filesystem {
            magic: FUSE_SUPER_MAGIC,
            nosuid: false,
        };
        assert_eq!(fuse.check(true), Err(Rejection::Fuse));
        assert_eq!(fuse.check(false), Err(Rejection::Fuse));
        let nosuid = Filesystem {
            magic: 0xef53,
            nosuid: true,
        };
        assert_eq!(nosuid.check(true), Err(Rejection::NoSuid));
        assert_eq!(nosuid.check(false), Ok(()));
    }

    #[test]
    fn test_user_owned_file_rejected() {
        let exe = std::env::current_exe().unwrap();
        if nix::unistd::geteuid().is_root() {
            return;
        }
        assert!(hardened_candidate(&exe, MARKER).is_err());
        assert!(root_owned_file(&exe).is_err());
    }
}
