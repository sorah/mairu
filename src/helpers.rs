/// Helpers that release archives ship next to `mairu` on this OS. `mairu harden` copies them next to the hardened
/// copy.
#[cfg(target_os = "linux")]
pub const SHIPPED: &[&str] = &["mairu-windows-hello.exe"];

/// Finds a helper shipped beside the running executable, or in `../lib/mairu/` relative to it.
///
/// Never searches `PATH`. Callers verify the returned helper before use.
pub fn locate(file_name: &str) -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    crate::helpers::locate_for_executable(&exe, file_name)
}

/// As [`locate`], for the executable at `exe`.
pub fn locate_for_executable(exe: &std::path::Path, file_name: &str) -> Option<std::path::PathBuf> {
    // On macOS current_exe() returns the path mairu was started through, which may be a symlink.
    let exe = std::fs::canonicalize(exe).ok()?;
    let dir = exe.parent()?;
    let candidates = [
        Some(dir.join(file_name)),
        dir.parent()
            .map(|prefix| prefix.join("lib").join("mairu").join(file_name)),
    ];
    candidates
        .into_iter()
        .flatten()
        .find(|path| path.try_exists().unwrap_or(false))
}

#[cfg(test)]
mod tests {
    /// A temporary directory that is removed even when the test panics.
    struct ScratchDir(std::path::PathBuf);

    impl std::ops::Deref for ScratchDir {
        type Target = std::path::Path;

        fn deref(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch_dir(name: &str) -> ScratchDir {
        let dir = std::env::temp_dir().join(format!(
            "mairu-helpers-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        ScratchDir(dir.canonicalize().unwrap())
    }

    fn touch(path: &std::path::Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"").unwrap();
    }

    #[test]
    fn test_beside_executable() {
        let root = scratch_dir("beside");
        touch(&root.join("dist/mairu"));
        touch(&root.join("dist/helper"));

        assert_eq!(
            crate::helpers::locate_for_executable(&root.join("dist/mairu"), "helper"),
            Some(root.join("dist/helper"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_symlinked_executable() {
        let root = scratch_dir("symlink");
        touch(&root.join("cellar/mairu"));
        touch(&root.join("cellar/helper"));
        touch(&root.join("bin/helper"));
        std::os::unix::fs::symlink(root.join("cellar/mairu"), root.join("bin/mairu")).unwrap();

        assert_eq!(
            crate::helpers::locate_for_executable(&root.join("bin/mairu"), "helper"),
            Some(root.join("cellar/helper"))
        );
    }

    #[test]
    fn test_package_layout() {
        let root = scratch_dir("package");
        touch(&root.join("usr/bin/mairu"));
        touch(&root.join("usr/lib/mairu/helper"));

        assert_eq!(
            crate::helpers::locate_for_executable(&root.join("usr/bin/mairu"), "helper"),
            Some(root.join("usr/lib/mairu/helper"))
        );
    }

    #[test]
    fn test_beside_executable_preferred_over_package_layout() {
        let root = scratch_dir("preferred");
        touch(&root.join("usr/bin/mairu"));
        touch(&root.join("usr/bin/helper"));
        touch(&root.join("usr/lib/mairu/helper"));

        assert_eq!(
            crate::helpers::locate_for_executable(&root.join("usr/bin/mairu"), "helper"),
            Some(root.join("usr/bin/helper"))
        );
    }

    #[test]
    fn test_bundle_directory() {
        let root = scratch_dir("bundle");
        touch(&root.join("dist/mairu"));
        touch(&root.join("dist/Mairu Helper.app/Contents/Info.plist"));

        assert_eq!(
            crate::helpers::locate_for_executable(&root.join("dist/mairu"), "Mairu Helper.app"),
            Some(root.join("dist/Mairu Helper.app"))
        );
    }

    #[test]
    fn test_missing() {
        let root = scratch_dir("missing");
        touch(&root.join("usr/bin/mairu"));

        assert_eq!(
            crate::helpers::locate_for_executable(&root.join("usr/bin/mairu"), "helper"),
            None
        );
    }
}
