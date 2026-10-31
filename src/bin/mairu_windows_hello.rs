//! `mairu-windows-hello.exe`: signs mairu's challenges with a Windows Hello key credential. mairu runs it through
//! WSL interop and verifies every signature itself, so nothing this program prints is trusted on its own.
//!
//! ```text
//! mairu-windows-hello.exe public-key   prints the key's SubjectPublicKeyInfo, base64
//! mairu-windows-hello.exe create       creates the key, then prints as public-key
//! mairu-windows-hello.exe sign         reads base64 data on stdin, prints the signature, base64
//! ```

// Exit statuses, as src/windows_hello.rs reads them.
const EXIT_FAILED: u8 = 1;
const EXIT_CANCELLED: u8 = 2;
const EXIT_NOT_FOUND: u8 = 3;
const EXIT_EXISTS: u8 = 4;
const EXIT_UNSUPPORTED: u8 = 5;
const EXIT_USAGE: u8 = 64;

/// Statements are a few hundred bytes.
const MAX_INPUT: u64 = 64 * 1024;

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match args.as_slice() {
        [c] if matches!(c.as_str(), "public-key" | "create" | "sign") => c.clone(),
        [v] if v == "--version" => {
            println!("mairu-windows-hello {}", env!("CARGO_PKG_VERSION"));
            return std::process::ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("usage: mairu-windows-hello.exe public-key|create|sign");
            return std::process::ExitCode::from(EXIT_USAGE);
        }
    };
    let result = match command.as_str() {
        "sign" => read_input().and_then(|data| hello::sign(&data)),
        "create" => hello::create(),
        _ => hello::public_key(),
    };
    match result {
        Ok(bytes) => {
            use base64::Engine;
            println!(
                "{}",
                base64::engine::general_purpose::STANDARD.encode(bytes)
            );
            std::process::ExitCode::SUCCESS
        }
        Err(Failure(status, message)) => {
            eprintln!("mairu-windows-hello: {message}");
            std::process::ExitCode::from(status)
        }
    }
}

#[derive(Debug)]
struct Failure(u8, String);

fn read_input() -> Result<Vec<u8>, Failure> {
    use base64::Engine;
    use std::io::Read;
    let mut input = String::new();
    std::io::stdin()
        .take(MAX_INPUT)
        .read_to_string(&mut input)
        .map_err(|e| Failure(EXIT_FAILED, format!("failed to read stdin: {e}")))?;
    base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .map_err(|e| Failure(EXIT_FAILED, format!("stdin is not base64: {e}")))
}

#[cfg(windows)]
mod hello {
    use super::Failure;
    use windows::Security::Credentials::{
        KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    };

    const KEY_NAME: &str = "co.0w0.mairu";
    /// The window class of the Windows Hello dialog.
    const DIALOG_CLASS: windows::core::PCWSTR = windows::core::w!("Credential Dialog Xaml Host");
    const FOCUS_ATTEMPTS: u32 = 100;
    const FOCUS_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

    fn failed(what: &str, e: windows::core::Error) -> Failure {
        Failure(super::EXIT_FAILED, format!("{what}: {e}"))
    }

    fn status_failure(what: &str, status: KeyCredentialStatus) -> Failure {
        let code = match status {
            KeyCredentialStatus::UserCanceled | KeyCredentialStatus::UserPrefersPassword => {
                super::EXIT_CANCELLED
            }
            KeyCredentialStatus::NotFound => super::EXIT_NOT_FOUND,
            KeyCredentialStatus::CredentialAlreadyExists => super::EXIT_EXISTS,
            _ => super::EXIT_FAILED,
        };
        let name = match status {
            KeyCredentialStatus::UserCanceled => "cancelled",
            KeyCredentialStatus::UserPrefersPassword => "the user chose a password",
            KeyCredentialStatus::NotFound => "no key credential",
            KeyCredentialStatus::CredentialAlreadyExists => "the key credential exists",
            KeyCredentialStatus::SecurityDeviceLocked => "the security device is locked",
            _ => "unknown error",
        };
        Failure(code, format!("{what}: {name} (status {})", status.0))
    }

    fn ensure_supported() -> Result<(), Failure> {
        let supported = KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| op.join())
            .map_err(|e| failed("IsSupportedAsync", e))?;
        if supported {
            Ok(())
        } else {
            Err(Failure(
                super::EXIT_UNSUPPORTED,
                "Windows Hello is not set up for this account".to_owned(),
            ))
        }
    }

    fn open() -> Result<KeyCredential, Failure> {
        let result = KeyCredentialManager::OpenAsync(&KEY_NAME.into())
            .and_then(|op| op.join())
            .map_err(|e| failed("OpenAsync", e))?;
        let status = result.Status().map_err(|e| failed("OpenAsync", e))?;
        if status != KeyCredentialStatus::Success {
            return Err(status_failure("OpenAsync", status));
        }
        result.Credential().map_err(|e| failed("OpenAsync", e))
    }

    fn spki(credential: &KeyCredential) -> Result<Vec<u8>, Failure> {
        let buffer = credential
            .RetrievePublicKeyWithBlobType(
                windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType::X509SubjectPublicKeyInfo,
            )
            .map_err(|e| failed("RetrievePublicKey", e))?;
        to_vec(&buffer)
    }

    fn to_vec(buffer: &windows::Storage::Streams::IBuffer) -> Result<Vec<u8>, Failure> {
        let mut bytes = windows::core::Array::<u8>::new();
        windows::Security::Cryptography::CryptographicBuffer::CopyToByteArray(buffer, &mut bytes)
            .map_err(|e| failed("CopyToByteArray", e))?;
        Ok(bytes.to_vec())
    }

    pub fn public_key() -> Result<Vec<u8>, Failure> {
        ensure_supported()?;
        spki(&open()?)
    }

    pub fn create() -> Result<Vec<u8>, Failure> {
        ensure_supported()?;
        let focus = focus_dialog();
        let result = KeyCredentialManager::RequestCreateAsync(
            &KEY_NAME.into(),
            KeyCredentialCreationOption::FailIfExists,
        )
        .and_then(|op| op.join())
        .map_err(|e| failed("RequestCreateAsync", e));
        drop(focus);
        let result = result?;
        let status = result
            .Status()
            .map_err(|e| failed("RequestCreateAsync", e))?;
        if status != KeyCredentialStatus::Success {
            return Err(status_failure("RequestCreateAsync", status));
        }
        spki(
            &result
                .Credential()
                .map_err(|e| failed("RequestCreateAsync", e))?,
        )
    }

    /// Windows hashes `data` itself (SHA-256, PKCS #1 v1.5), so it is passed as it is.
    pub fn sign(data: &[u8]) -> Result<Vec<u8>, Failure> {
        ensure_supported()?;
        let credential = open()?;
        let buffer =
            windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(data)
                .map_err(|e| failed("CreateFromByteArray", e))?;
        let focus = focus_dialog();
        let result = credential
            .RequestSignAsync(&buffer)
            .and_then(|op| op.join())
            .map_err(|e| failed("RequestSignAsync", e));
        drop(focus);
        let result = result?;
        let status = result.Status().map_err(|e| failed("RequestSignAsync", e))?;
        if status != KeyCredentialStatus::Success {
            return Err(status_failure("RequestSignAsync", status));
        }
        to_vec(&result.Result().map_err(|e| failed("RequestSignAsync", e))?)
    }

    /// Stops looking for the dialog when dropped.
    struct Focus(std::sync::Arc<std::sync::atomic::AtomicBool>);

    impl Drop for Focus {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// A console process owns no foreground window, so the dialog opens behind the terminal unless brought forward.
    fn focus_dialog() -> Focus {
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = done.clone();
        std::thread::spawn(move || {
            for _ in 0..FOCUS_ATTEMPTS {
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                // SAFETY: FindWindowW reads a static string; SetForegroundWindow takes a window handle by value.
                unsafe {
                    if let Ok(hwnd) =
                        windows::Win32::UI::WindowsAndMessaging::FindWindowW(DIALOG_CLASS, None)
                        && !hwnd.is_invalid()
                    {
                        let _ = windows::Win32::UI::WindowsAndMessaging::SetForegroundWindow(hwnd);
                        return;
                    }
                }
                std::thread::sleep(FOCUS_INTERVAL);
            }
        });
        Focus(done)
    }
}

#[cfg(not(windows))]
mod hello {
    use super::Failure;

    fn unsupported() -> Result<Vec<u8>, Failure> {
        Err(Failure(
            super::EXIT_UNSUPPORTED,
            "runs on Windows only".to_owned(),
        ))
    }

    pub fn public_key() -> Result<Vec<u8>, Failure> {
        unsupported()
    }

    pub fn create() -> Result<Vec<u8>, Failure> {
        unsupported()
    }

    pub fn sign(_data: &[u8]) -> Result<Vec<u8>, Failure> {
        unsupported()
    }
}
