#[derive(clap::Args)]
pub struct HardenArgs {
    /// Install under <PATH>/libexec/mairu. Defaults to MAIRU_HARDEN_HOME, then harden_home in config.json, then
    /// /usr/local
    #[arg(long, value_name = "PATH", value_parser = absolute_path)]
    pub home: Option<std::path::PathBuf>,

    /// Install FILE instead of this binary, after verifying its release attestation
    #[arg(long, value_name = "FILE", conflicts_with = "uninstall")]
    pub from: Option<std::path::PathBuf>,

    /// With --from, install FILE without an attestation, such as a build from source
    #[arg(long, requires = "from")]
    pub unattested: bool,

    /// With --from, allow installing a release older than this mairu
    #[arg(long, requires = "from")]
    pub allow_downgrade: bool,

    /// Remove the files a previous `mairu harden` installed in the harden home
    #[arg(long)]
    pub uninstall: bool,

    /// With --uninstall, also remove /var/lib/mairu
    #[arg(long, requires = "uninstall")]
    pub purge: bool,

    /// Remove a user's policy approval record from /var/lib/mairu, for when every approval key is lost
    #[arg(long, requires = "user", conflicts_with_all = ["uninstall", "from", "home"])]
    pub reset_policy_record: bool,

    /// With --reset-policy-record, the user whose record to remove
    #[arg(long, value_name = "NAME", requires = "reset_policy_record")]
    pub user: Option<String>,
}

fn absolute_path(s: &str) -> Result<std::path::PathBuf, String> {
    let path = std::path::PathBuf::from(s);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err("must be an absolute path".to_owned())
    }
}

#[cfg(target_os = "linux")]
pub fn run(args: &HardenArgs) -> Result<(), anyhow::Error> {
    linux::run(args)
}

#[cfg(not(target_os = "linux"))]
pub fn run(_args: &HardenArgs) -> Result<(), anyhow::Error> {
    anyhow::bail!("mairu harden is only supported on Linux")
}

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::Context as _;

    const STATE_DIR: &str = "/var/lib/mairu";
    const USERS_DIR: &str = "/var/lib/mairu/users";
    const INSTALLS: &str = "installs";
    const MANIFEST_NAME: &str = ".harden-manifest";
    const POLKIT_ACTIONS_DIR: &str = "/usr/share/polkit-1/actions";
    const POLKIT_ACTION_NAME: &str = "co.0w0.mairu.policy";
    /// The one manifest entry outside the libexec directory.
    const POLKIT_ACTION_PATH: &str = "/usr/share/polkit-1/actions/co.0w0.mairu.policy";
    const POLKIT_ACTION: &str = include_str!("../../pkg/polkit/co.0w0.mairu.policy");
    const SETCAP: &[&str] = &["/usr/sbin/setcap", "/usr/bin/setcap"];

    /// The image to install, held in memory so that the bytes checked are the bytes written.
    struct Source {
        bytes: Vec<u8>,
        /// Where helpers to copy along are looked up.
        exe: std::path::PathBuf,
        version: Option<String>,
    }

    impl Source {
        /// `/proc/self/exe` is the exact image already running as root, so nothing can swap it before the copy.
        fn running() -> Result<Self, anyhow::Error> {
            let bytes = read_regular_file(std::path::Path::new("/proc/self/exe"))?;
            Ok(Self {
                bytes,
                exe: std::env::current_exe()?.canonicalize()?,
                version: Some(crate::version::VERSION.to_owned()),
            })
        }

        /// The new file never runs: its attestation is verified over the bytes read once here.
        fn from_file(
            path: &std::path::Path,
            unattested: bool,
            allow_downgrade: bool,
        ) -> Result<Self, anyhow::Error> {
            let bytes = read_regular_file(path)?;
            let version = if unattested {
                use sha2::Digest as _;
                eprintln!(
                    "warning: installing {} (sha256:{:x}) without verifying its attestation",
                    path.display(),
                    sha2::Sha256::digest(&bytes)
                );
                None
            } else {
                let attested = crate::attestation::verify_file(path, &bytes).with_context(|| {
                    format!(
                        "cannot verify the attestation of {}; pass --unattested to install a build from source",
                        path.display()
                    )
                })?;
                println!(
                    "Verified {}: mairu {} signed by {}",
                    path.display(),
                    attested.version,
                    attested.identity
                );
                check_version(&attested.version, crate::version::VERSION, allow_downgrade)?;
                Some(attested.version)
            };
            Ok(Self {
                bytes,
                exe: path.canonicalize()?,
                version,
            })
        }
    }

    fn check_version(
        new: &str,
        installed: &str,
        allow_downgrade: bool,
    ) -> Result<(), anyhow::Error> {
        if allow_downgrade || crate::version::at_least(new, installed) {
            return Ok(());
        }
        anyhow::bail!(
            "mairu {new} is older than this mairu ({installed}); pass --allow-downgrade to install it anyway"
        )
    }

    pub fn run(args: &super::HardenArgs) -> Result<(), anyhow::Error> {
        if !nix::unistd::geteuid().is_root() {
            let extra: Vec<String> = std::env::args_os()
                .skip(2)
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            let extra = if extra.is_empty() {
                String::new()
            } else {
                format!(" {}", extra.join(" "))
            };
            eprintln!(
                "mairu harden must run as root; {}",
                crate::hardening::reexec::harden_instruction(&extra)
            );
            return Err(crate::Error::FailureButSilentlyExit.into());
        }
        if args.reset_policy_record {
            return reset_policy_record(args.user.as_deref().unwrap_or_default());
        }
        let invoker = invoking_user();
        let home = resolve_home(args.home.as_deref(), invoker.as_ref());
        println!("Harden home: {} ({})", home.path.display(), home.source);

        if args.uninstall {
            return uninstall(&home, args.purge);
        }

        let source = match &args.from {
            Some(path) => Source::from_file(path, args.unattested, args.allow_downgrade)?,
            None => Source::running()?,
        };
        let group = ensure_group(invoker.as_ref())?;
        let dir = prepare_libexec_dir(&home.libexec_dir())?;

        let binary = dir.join("mairu");
        install_file(&dir, "mairu", &source.bytes, group.gid, 0o2755)
            .with_context(|| format!("failed to install {}", binary.display()))?;
        println!(
            "Installed {} (root:{} 2755)",
            binary.display(),
            crate::hardening::MARKER_GROUP_NAME
        );
        set_ipc_lock_capability(&binary);
        let mut written = vec!["mairu".to_owned()];
        written.extend(install_helpers(&dir, &source.exe));
        written.extend(install_polkit_action()?);

        prepare_state_dir(group.gid)?;
        write_manifest(&dir, &written)?;
        record_install(&home.path, group.gid)?;

        println!();
        println!(
            "mairu {} is hardened at {}.",
            source.version.as_deref().unwrap_or("(unattested)"),
            binary.display()
        );
        println!(
            "Other mairu installations on this host now run it. The next mairu command replaces a running unhardened agent; or run `mairu kill-agent` now."
        );
        Ok(())
    }

    /// Deletes the strong record of both profiles. The user's Secret Service item stays; once it no longer
    /// matches the files, it means lockdown until the next approval.
    fn reset_policy_record(name: &str) -> Result<(), anyhow::Error> {
        let user = nix::unistd::User::from_name(name)?
            .ok_or_else(|| anyhow::anyhow!("no user named {name:?}"))?;
        let uid = user.uid.as_raw();
        let root = std::path::Path::new(crate::platform::integrity::PROTECTED_DIRECTORY);
        let mut removed = 0;
        for record in ["policy", "policy-dev"] {
            let path = crate::platform::integrity::record_path(root, uid, record);
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    println!("Removed {}", path.display());
                    removed += 1;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(e).with_context(|| format!("failed to remove {}", path.display()));
                }
            }
        }
        if removed == 0 {
            println!(
                "{name} (uid {uid}) has no policy record in {}",
                root.display()
            );
            return Ok(());
        }
        println!(
            "{name}'s policy is now unapproved, and the next approval asks through \"platform\". Until then, a Secret Service record of the old approval that no longer matches the files means lockdown."
        );
        Ok(())
    }

    fn invoking_user() -> Option<nix::unistd::User> {
        let uid: u32 = std::env::var("SUDO_UID").ok()?.parse().ok()?;
        nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .ok()
            .flatten()
    }

    /// `sudo` usually drops `MAIRU_HARDEN_HOME`, so the invoking user's config.json counts too.
    fn resolve_home(
        flag: Option<&std::path::Path>,
        invoker: Option<&nix::unistd::User>,
    ) -> crate::hardening::home::HardenHome {
        let config_path = match invoker {
            Some(user) => user.dir.join(".config").join("mairu").join("config.json"),
            None => crate::config::UserConfig::path(),
        };
        // Only a regular file, so that a FIFO in the user's home cannot stall root.
        let config = std::fs::metadata(&config_path)
            .ok()
            .filter(|m| m.is_file())
            .and_then(|_| crate::config::UserConfig::load_from(&config_path).ok())
            .and_then(|c| c.harden_home);
        crate::hardening::home::HardenHome::resolve(
            flag,
            std::env::var_os(crate::hardening::home::HARDEN_HOME_ENV).as_deref(),
            config.as_deref(),
        )
    }

    fn ensure_group(
        invoker: Option<&nix::unistd::User>,
    ) -> Result<nix::unistd::Group, anyhow::Error> {
        let name = crate::hardening::MARKER_GROUP_NAME;
        let group = match nix::unistd::Group::from_name(name)? {
            Some(g) => g,
            None => {
                create_group(name)?;
                println!("Created the system group `{name}`");
                nix::unistd::Group::from_name(name)?
                    .with_context(|| format!("group `{name}` is missing after creating it"))?
            }
        };
        if !group.mem.is_empty() {
            anyhow::bail!(
                "the `{name}` group has members ({}), who could forge the marker; remove them with `gpasswd -d <user> {name}` and run harden again",
                group.mem.join(", ")
            );
        }
        if let Some(user) = invoker
            && user.gid == group.gid
        {
            anyhow::bail!(
                "the primary group of {} is `{name}`, so they could forge the marker; change it with `usermod -g <group> {}` and run harden again",
                user.name,
                user.name
            );
        }
        let gshadow = std::fs::read_to_string("/etc/gshadow").ok();
        if group_has_password(name, &group.passwd.to_string_lossy(), gshadow.as_deref()) {
            let status = crate::hardening::command("gpasswd")
                .args(["-r", name])
                .status()
                .context("failed to run gpasswd")?;
            if !status.success() {
                anyhow::bail!("`gpasswd -r {name}` failed ({status})");
            }
            println!(
                "Removed the password of the `{name}` group; with it, anyone knowing it could hold the marker"
            );
        }
        Ok(group)
    }

    fn create_group(name: &str) -> Result<(), anyhow::Error> {
        let mut errors = vec![];
        // `addgroup -S` is the busybox form.
        for (program, args) in [("groupadd", ["--system", name]), ("addgroup", ["-S", name])] {
            match crate::hardening::command(program).args(args).status() {
                Ok(s) if s.success() => return Ok(()),
                Ok(s) => errors.push(format!("{program}: {s}")),
                Err(e) => errors.push(format!("{program}: {e}")),
            }
        }
        anyhow::bail!(
            "failed to create the group `{name}` ({})",
            errors.join(", ")
        )
    }

    /// Whether the group database gives the group a password usable with `newgrp`.
    fn group_has_password(name: &str, group_field: &str, gshadow: Option<&str>) -> bool {
        let is_set = |pw: &str| !pw.is_empty() && !pw.starts_with('!') && !pw.starts_with('*');
        let shadow = gshadow.and_then(|content| {
            content.lines().find_map(|line| {
                let mut fields = line.split(':');
                (fields.next() == Some(name)).then(|| fields.next().unwrap_or(""))
            })
        });
        match shadow {
            Some(pw) => is_set(pw),
            None => group_field != "x" && is_set(group_field),
        }
    }

    /// Creates the directory as `root:root 0755` and checks that only root can modify it or its ancestors.
    fn prepare_libexec_dir(dir: &std::path::Path) -> Result<std::path::PathBuf, anyhow::Error> {
        let mut missing = vec![];
        let mut cursor = dir;
        while !cursor.try_exists()? {
            missing.push(cursor);
            cursor = cursor
                .parent()
                .with_context(|| format!("{} has no existing ancestor", dir.display()))?;
        }
        crate::hardening::candidate::root_owned_dir(cursor).map_err(|e| {
            anyhow::anyhow!(
                "{} is not safe for a hardened copy: {e}; choose another harden home with --home",
                cursor.display()
            )
        })?;
        for path in missing.into_iter().rev() {
            std::fs::create_dir(path)
                .with_context(|| format!("failed to create {}", path.display()))?;
            set_mode(path, 0o755)?;
        }
        let dir = crate::hardening::candidate::root_owned_dir(dir).map_err(|e| {
            anyhow::anyhow!("{} is not safe for a hardened copy: {e}", dir.display())
        })?;
        std::os::unix::fs::chown(&dir, Some(0), Some(0))?;
        set_mode(&dir, 0o755)?;
        Ok(dir)
    }

    /// Writes `name` in `dir` through a temporary file and an atomic rename.
    fn install_file(
        dir: &std::path::Path,
        name: &str,
        contents: &[u8],
        gid: nix::unistd::Gid,
        mode: u32,
    ) -> std::io::Result<()> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = dir.join(format!(".{name}.tmp.{}", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        let result = (|| {
            file.write_all(contents)?;
            // chown clears the setgid bit, so the mode comes after it.
            std::os::unix::fs::fchown(&file, Some(0), Some(gid.as_raw()))?;
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
            file.sync_all()?;
            std::fs::rename(&tmp, dir.join(name))?;
            std::fs::File::open(dir)?.sync_all()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// So that the agent's `mlockall` succeeds without RLIMIT_MEMLOCK headroom. Must follow the chown, which clears
    /// file capabilities.
    fn set_ipc_lock_capability(path: &std::path::Path) {
        let Some(setcap) = SETCAP.iter().find(|p| std::path::Path::new(p).exists()) else {
            println!("setcap not found; skipping cap_ipc_lock");
            return;
        };
        match crate::hardening::command(setcap)
            .arg("cap_ipc_lock=+ep")
            .arg(path)
            .status()
        {
            Ok(s) if s.success() => println!("Granted cap_ipc_lock to {}", path.display()),
            Ok(s) => {
                eprintln!("warning: setcap failed ({s}); the agent may fail to lock its memory")
            }
            Err(e) => eprintln!("warning: failed to run {setcap} ({e})"),
        }
    }

    /// Copies the helpers found next to `exe`, root-owned. A helper that fails is skipped with a warning.
    fn install_helpers(dir: &std::path::Path, exe: &std::path::Path) -> Vec<String> {
        let mut written = vec![];
        for name in crate::helpers::SHIPPED {
            let Some(path) = crate::helpers::locate_for_executable(exe, name) else {
                continue;
            };
            let result = (|| -> Result<(), anyhow::Error> {
                use std::os::unix::fs::PermissionsExt as _;
                let file = std::fs::File::open(&path)?;
                let metadata = file.metadata()?;
                if !metadata.is_file() {
                    anyhow::bail!("not a regular file");
                }
                let bytes = read_all(file)?;
                let mode = metadata.permissions().mode() & 0o755;
                install_file(dir, name, &bytes, nix::unistd::Gid::from_raw(0), mode)?;
                Ok(())
            })();
            match result {
                Ok(()) => {
                    println!("Installed {}", dir.join(name).display());
                    written.push((*name).to_owned());
                }
                Err(e) => eprintln!("warning: skipping the helper {}: {e}", path.display()),
            }
        }
        written
    }

    /// Writes the polkit actions unless an identical file is there. Returns the manifest entry when written.
    fn install_polkit_action() -> Result<Option<String>, anyhow::Error> {
        let dir = std::path::Path::new(POLKIT_ACTIONS_DIR);
        if !dir.is_dir() {
            eprintln!(
                "warning: {POLKIT_ACTIONS_DIR} does not exist; install polkit, or authorization prompts will be unavailable"
            );
            return Ok(None);
        }
        let path = dir.join(POLKIT_ACTION_NAME);
        if std::fs::read(&path).is_ok_and(|c| c == POLKIT_ACTION.as_bytes()) {
            println!("{} is up to date", path.display());
            return Ok(None);
        }
        install_file(
            dir,
            POLKIT_ACTION_NAME,
            POLKIT_ACTION.as_bytes(),
            nix::unistd::Gid::from_raw(0),
            0o644,
        )
        .with_context(|| format!("failed to install {}", path.display()))?;
        println!("Installed {}", path.display());
        Ok(Some(POLKIT_ACTION_PATH.to_owned()))
    }

    fn prepare_state_dir(gid: nix::unistd::Gid) -> Result<(), anyhow::Error> {
        for path in [STATE_DIR, USERS_DIR] {
            let path = std::path::Path::new(path);
            match std::fs::symlink_metadata(path) {
                Ok(m) if m.is_dir() => {}
                Ok(_) => anyhow::bail!("{} exists and is not a directory", path.display()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    use std::os::unix::fs::DirBuilderExt as _;
                    std::fs::DirBuilder::new()
                        .mode(0o700)
                        .create(path)
                        .with_context(|| format!("failed to create {}", path.display()))?;
                }
                Err(e) => return Err(e.into()),
            }
            std::os::unix::fs::lchown(path, Some(0), Some(gid.as_raw()))?;
            set_mode(path, 0o2770)?;
        }
        println!(
            "Prepared {STATE_DIR} and {USERS_DIR} (root:{} 2770)",
            crate::hardening::MARKER_GROUP_NAME
        );
        Ok(())
    }

    fn write_manifest(dir: &std::path::Path, written: &[String]) -> Result<(), anyhow::Error> {
        let mut entries = read_manifest(dir).unwrap_or_default();
        for name in written {
            if !entries.contains(name) {
                entries.push(name.clone());
            }
        }
        install_file(
            dir,
            MANIFEST_NAME,
            join_lines(&entries).as_bytes(),
            nix::unistd::Gid::from_raw(0),
            0o644,
        )
        .context("failed to write the manifest")
    }

    /// The manifest counts only when it and its directory are root-owned and not group/other-writable.
    fn read_manifest(dir: &std::path::Path) -> Result<Vec<String>, anyhow::Error> {
        let dir = crate::hardening::candidate::root_owned_dir(dir)?;
        let manifest = crate::hardening::candidate::root_owned_file(&dir.join(MANIFEST_NAME))?;
        if manifest.parent() != Some(dir.as_path()) {
            anyhow::bail!("{} is not inside {}", manifest.display(), dir.display());
        }
        Ok(parse_manifest(&std::fs::read_to_string(&manifest)?))
    }

    /// Plain file names, and the polkit action file, so that a manifest can never name any other file outside its
    /// directory.
    fn parse_manifest(content: &str) -> Vec<String> {
        content
            .lines()
            .filter(|l| {
                *l == POLKIT_ACTION_PATH
                    || (!l.is_empty()
                        && *l != "."
                        && *l != ".."
                        && !l.contains('/')
                        && !l.contains('\0'))
            })
            .map(ToOwned::to_owned)
            .collect()
    }

    fn join_lines(lines: &[String]) -> String {
        lines.iter().map(|l| format!("{l}\n")).collect()
    }

    fn installs_path() -> std::path::PathBuf {
        std::path::Path::new(STATE_DIR).join(INSTALLS)
    }

    /// /var/lib/mairu is writable by the marker gid, so only the file itself is checked.
    fn read_installs() -> Vec<String> {
        use std::os::unix::fs::MetadataExt as _;
        let path = installs_path();
        let trusted = std::fs::symlink_metadata(&path)
            .is_ok_and(|m| m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0);
        if !trusted {
            return vec![];
        }
        std::fs::read_to_string(&path)
            .map(|c| {
                c.lines()
                    .filter(|l| !l.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn write_installs(entries: &[String], gid: nix::unistd::Gid) -> Result<(), anyhow::Error> {
        install_file(
            std::path::Path::new(STATE_DIR),
            INSTALLS,
            join_lines(entries).as_bytes(),
            gid,
            0o640,
        )
        .with_context(|| format!("failed to write {}", installs_path().display()))
    }

    fn record_install(home: &std::path::Path, gid: nix::unistd::Gid) -> Result<(), anyhow::Error> {
        let home = home.to_string_lossy().into_owned();
        let mut entries = read_installs();
        if !entries.contains(&home) {
            entries.push(home);
        }
        write_installs(&entries, gid)
    }

    fn uninstall(
        home: &crate::hardening::home::HardenHome,
        purge: bool,
    ) -> Result<(), anyhow::Error> {
        let dir = home.libexec_dir();
        let home_entry = home.path.to_string_lossy().into_owned();
        let other_installs = read_installs().iter().any(|e| *e != home_entry);
        if dir.try_exists()? {
            let entries = read_manifest(&dir).map_err(|e| {
                anyhow::anyhow!("refusing to use the manifest in {}: {e}", dir.display())
            })?;
            for name in entries {
                if name == POLKIT_ACTION_PATH && other_installs {
                    println!("Left {name} in place for the other hardened copies");
                    continue;
                }
                let path = dir.join(&name);
                match std::fs::remove_file(&path) {
                    Ok(()) => println!("Removed {}", path.display()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => eprintln!("warning: failed to remove {}: {e}", path.display()),
                }
            }
            std::fs::remove_file(dir.join(MANIFEST_NAME))?;
            match std::fs::remove_dir(&dir) {
                Ok(()) => println!("Removed {}", dir.display()),
                Err(e) => println!("Left {} in place ({e})", dir.display()),
            }
        } else {
            println!("Nothing is installed at {}", dir.display());
        }

        if purge {
            match std::fs::remove_dir_all(STATE_DIR) {
                Ok(()) => println!("Removed {STATE_DIR}"),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(anyhow::anyhow!("failed to remove {STATE_DIR}: {e}")),
            }
        } else if let Ok(Some(group)) =
            nix::unistd::Group::from_name(crate::hardening::MARKER_GROUP_NAME)
        {
            let home = home.path.to_string_lossy();
            let entries = read_installs();
            if entries.iter().any(|e| *e == home) {
                let remaining: Vec<String> = entries.into_iter().filter(|e| *e != home).collect();
                write_installs(&remaining, group.gid)?;
            }
        }
        println!(
            "The `{0}` group is left in place; remove it with `groupdel {0}` once nothing uses it.",
            crate::hardening::MARKER_GROUP_NAME
        );
        Ok(())
    }

    fn read_regular_file(path: &std::path::Path) -> Result<Vec<u8>, anyhow::Error> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        if !file.metadata()?.is_file() {
            anyhow::bail!("{} is not a regular file", path.display());
        }
        Ok(read_all(file)?)
    }

    fn read_all(mut file: std::fs::File) -> std::io::Result<Vec<u8>> {
        use std::io::Read as _;
        let mut bytes = vec![];
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn set_mode(path: &std::path::Path, mode: u32) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_group_has_password() {
            let gshadow = "root:*::\nmairu:!::\nlocked:!$6$abc::\nopen:$6$abc$def::\nempty:::\n";
            assert!(!group_has_password("mairu", "x", Some(gshadow)));
            assert!(!group_has_password("locked", "x", Some(gshadow)));
            assert!(group_has_password("open", "x", Some(gshadow)));
            assert!(!group_has_password("empty", "x", Some(gshadow)));
            // Without a gshadow entry, /etc/group's own field counts.
            assert!(!group_has_password("missing", "x", Some(gshadow)));
            assert!(group_has_password("missing", "$6$abc$def", Some(gshadow)));
            assert!(group_has_password("mairu", "$6$abc$def", None));
            assert!(!group_has_password("mairu", "", None));
            assert!(!group_has_password("mairu", "!", None));
        }

        #[test]
        fn test_parse_manifest_polkit_action() {
            assert_eq!(
                parse_manifest(&format!(
                    "mairu\n{POLKIT_ACTION_PATH}\n/usr/share/polkit-1/actions/other.policy\n"
                )),
                vec!["mairu", POLKIT_ACTION_PATH]
            );
        }

        #[test]
        fn test_parse_manifest() {
            assert_eq!(
                parse_manifest(
                    "mairu\nmairu-windows-hello.exe\n\n../../etc/passwd\n/etc/shadow\n.\n..\nsub/file\n"
                ),
                vec!["mairu", "mairu-windows-hello.exe"]
            );
        }

        #[test]
        fn test_check_version() {
            assert!(check_version("0.13.0", "0.13.0", false).is_ok());
            assert!(check_version("0.14.0", "0.13.0", false).is_ok());
            assert!(check_version("0.12.0", "0.13.0", false).is_err());
            assert!(check_version("0.12.0", "0.13.0", true).is_ok());
        }

        #[test]
        fn test_join_lines() {
            assert_eq!(join_lines(&["a".to_owned(), "b".to_owned()]), "a\nb\n");
            assert_eq!(join_lines(&[]), "");
        }
    }
}
