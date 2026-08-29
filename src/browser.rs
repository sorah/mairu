/// Decide whether the authentication URL should be opened in a browser.
///
/// Auto-open is enabled by default. It is suppressed when the user opted out
/// (`--no-browser` / `MAIRU_NO_BROWSER`) or when stdout/tty is not a real
/// terminal (e.g. CI, piped output), in which case only the printed URL is
/// used.
pub fn should_open(no_browser: bool, is_terminal: bool) -> bool {
    !no_browser && is_terminal
}

/// Best-effort: open `url` in the user's default browser.
///
/// Never returns an error to the caller — the URL is always printed first as a
/// fallback, so a failure to launch a browser (no DISPLAY, no browser, launcher
/// error) must not fail the login. `webbrowser::open_browser_with_options` is
/// synchronous and may spawn a subprocess, so it runs on a blocking thread.
pub async fn open_url(url: &str) {
    let url = url.to_owned();
    let result = tokio::task::spawn_blocking(move || {
        webbrowser::open_browser_with_options(
            webbrowser::Browser::Default,
            &url,
            webbrowser::BrowserOptions::new().with_suppress_output(true),
        )
    })
    .await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!("Failed to open browser: {e}"),
        Err(e) => tracing::warn!("Failed to spawn browser-open task: {e}"),
    }
}

#[cfg(test)]
mod tests {
    mod should_open {
        #[test]
        fn opens_when_enabled_and_terminal() {
            assert!(crate::browser::should_open(false, true));
        }

        #[test]
        fn does_not_open_when_no_browser() {
            assert!(!crate::browser::should_open(true, true));
        }

        #[test]
        fn does_not_open_when_not_terminal() {
            assert!(!crate::browser::should_open(false, false));
        }

        #[test]
        fn does_not_open_when_no_browser_and_not_terminal() {
            assert!(!crate::browser::should_open(true, false));
        }
    }
}
