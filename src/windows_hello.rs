//! The `windows-hello` presence method on WSL2. The agent issues the same challenges as for `ssh-agent`, and
//! verifies their signatures against registered Windows Hello public keys; the client has `mairu-windows-hello.exe`
//! sign them through WSL interop, after checking the helper against its pinned SHA-256.

pub const METHOD: &str = "windows-hello";
/// The helper as release archives ship it next to `mairu`.
pub const HELPER_FILE_NAME: &str = "mairu-windows-hello.exe";
pub const DECLINED_NO_HELPER: &str = "no-helper";

/// The SHA-256 of the helper this build ships, recorded by release builds.
pub const BUILD_HELPER_SHA256: Option<&str> = option_env!("MAIRU_WINDOWS_HELLO_HELPER_SHA256");

const FINGERPRINT_PREFIX: &str = "wh:SHA256:";
const KEY_BITS: usize = 2048;

// The helper's exit statuses, as src/bin/mairu_windows_hello.rs sets them.
const EXIT_CANCELLED: i32 = 2;
const EXIT_NOT_FOUND: i32 = 3;
const EXIT_EXISTS: i32 = 4;
const EXIT_UNSUPPORTED: i32 = 5;

/// For the helper's commands that show no dialog.
const QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// For `create`, which waits for the human.
pub const CREATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
const MAX_OUTPUT: usize = 64 * 1024;

/// A Windows Hello public key registered in `windows_hello_keys`: an RSA-2048 SubjectPublicKeyInfo.
#[derive(Clone, PartialEq, Eq)]
pub struct RegisteredKey {
    pub name: String,
    spki: Vec<u8>,
    public: rsa::RsaPublicKey,
}

impl std::fmt::Debug for RegisteredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredKey")
            .field("name", &self.name)
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

impl RegisteredKey {
    /// A base64 SubjectPublicKeyInfo, as `windows_hello_keys[].public_key` holds it.
    pub fn parse(name: &str, public_key: &str) -> Result<Self, String> {
        use base64::Engine;
        let der = base64::engine::general_purpose::STANDARD
            .decode(public_key.trim())
            .map_err(|e| format!("public_key is not base64: {e}"))?;
        Self::from_der(name, &der)
    }

    /// A DER SubjectPublicKeyInfo, as approval anchors record it.
    pub fn from_der(name: &str, der: &[u8]) -> Result<Self, String> {
        use rsa::pkcs8::DecodePublicKey;
        use rsa::traits::PublicKeyParts;
        let public = rsa::RsaPublicKey::from_public_key_der(der)
            .map_err(|e| format!("public_key is not an RSA SubjectPublicKeyInfo: {e}"))?;
        let bits = public.n().bits();
        if bits != KEY_BITS {
            return Err(format!(
                "public_key is RSA-{bits}; Windows Hello keys are RSA-{KEY_BITS}"
            ));
        }
        Ok(Self {
            name: name.to_owned(),
            spki: der.to_vec(),
            public,
        })
    }

    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.spki)
    }

    /// `wh:SHA256:...`, the SHA-256 of the SubjectPublicKeyInfo.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.spki)
    }

    /// RSA PKCS #1 v1.5 with SHA-256 over `message` itself, as KeyCredential.RequestSignAsync signs.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), String> {
        use rsa::signature::Verifier;
        let signature = rsa::pkcs1v15::Signature::try_from(signature)
            .map_err(|e| format!("the signature is malformed: {e}"))?;
        rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(self.public.clone())
            .verify(message, &signature)
            .map_err(|_| "the signature does not verify".to_owned())
    }
}

/// `wh:SHA256:<unpadded base64>` of a DER SubjectPublicKeyInfo, in the style of OpenSSH fingerprints.
pub fn fingerprint(spki: &[u8]) -> String {
    use base64::Engine;
    use sha2::Digest;
    format!(
        "{FINGERPRINT_PREFIX}{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha2::Sha256::digest(spki))
    )
}

/// The fingerprints a challenge lists for `keys`.
pub fn fingerprints(keys: &[RegisteredKey]) -> Vec<String> {
    keys.iter().map(RegisteredKey::fingerprint).collect()
}

/// Checks the challenge against the retried request and the signature against `keys`. Returns the key that signed.
pub fn verify<'k, G>(
    challenge: &crate::ssh_agent_presence::PendingChallenge<G>,
    binding: &crate::ssh_agent_presence::Binding,
    now: std::time::Duration,
    signature: &[u8],
    keys: &'k [RegisteredKey],
) -> Result<&'k RegisteredKey, String> {
    challenge.check(binding, now)?;
    if challenge.method() != METHOD {
        return Err(format!(
            "a Windows Hello signature does not answer a {} challenge",
            challenge.method()
        ));
    }
    keys.iter()
        .find(|k| k.verify(challenge.statement(), signature).is_ok())
        .ok_or_else(|| "the signature does not verify with a registered key".to_owned())
}

/// Where the expected SHA-256 of the helper comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pin {
    /// Recorded by the release build that ships the helper.
    Build(String),
    /// `windows_hello_helper_sha256` of the approved settings.
    Settings(String),
    None,
}

impl Pin {
    /// The build's pin, else the approved settings' one (empty for none).
    pub fn resolve(settings: Option<&str>) -> Self {
        if let Some(pin) = BUILD_HELPER_SHA256 {
            return Pin::Build(pin.to_owned());
        }
        match settings.map(str::trim).filter(|s| !s.is_empty()) {
            Some(pin) => Pin::Settings(pin.to_ascii_lowercase()),
            None => Pin::None,
        }
    }

    pub fn expected(&self) -> Option<&str> {
        match self {
            Pin::Build(pin) | Pin::Settings(pin) => Some(pin),
            Pin::None => None,
        }
    }
}

impl std::fmt::Display for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pin::Build(pin) => write!(f, "{pin} (recorded by this build)"),
            Pin::Settings(pin) => write!(f, "{pin} (windows_hello_helper_sha256)"),
            Pin::None => write!(f, "none"),
        }
    }
}

/// The hex SHA-256 of a file.
pub fn digest(path: &std::path::Path) -> std::io::Result<String> {
    use sha2::Digest;
    let content = std::fs::read(path)?;
    Ok(crate::platform::integrity::hex(&sha2::Sha256::digest(
        content,
    )))
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("{0}")]
    Refused(String),
    #[error("failed to run: {0}")]
    Spawn(std::io::Error),
    #[error("timed out")]
    Timeout,
    #[error("exited with {}: {stderr}", code.map_or_else(|| "a signal".to_owned(), |c| format!("status {c}")))]
    Exit { code: Option<i32>, stderr: String },
    #[error("malformed output: {0}")]
    Malformed(String),
}

impl RunError {
    fn code(&self) -> Option<i32> {
        match self {
            RunError::Exit { code, .. } => *code,
            _ => None,
        }
    }

    /// The key credential does not exist, or Windows Hello is not set up.
    pub fn is_not_enrolled(&self) -> bool {
        matches!(self.code(), Some(EXIT_NOT_FOUND | EXIT_UNSUPPORTED))
    }

    pub fn is_cancelled(&self) -> bool {
        self.code() == Some(EXIT_CANCELLED)
    }
}

/// `mairu-windows-hello.exe` at `path`, run only while it matches `pin`, or with a warning when not hardened.
#[derive(Debug, Clone)]
pub struct Helper {
    pub path: std::path::PathBuf,
    pub pin: Pin,
    pub hardened: bool,
}

impl Helper {
    /// `windows_hello_helper` of `config`, else the helper shipped next to this mairu.
    pub fn locate(config: &crate::config::UserConfig) -> Option<std::path::PathBuf> {
        match &config.windows_hello_helper {
            Some(path) if path.is_absolute() => Some(path.clone()),
            Some(path) => {
                tracing::warn!(path = %path.display(), "Ignoring windows_hello_helper: not an absolute path");
                None
            }
            None => crate::helpers::locate(HELPER_FILE_NAME),
        }
    }

    /// Compares the file's SHA-256 with the pin. A hardened client refuses a mismatch or a missing pin.
    pub fn check(&self) -> Result<(), String> {
        let actual =
            digest(&self.path).map_err(|e| format!("cannot read {}: {e}", self.path.display()))?;
        let problem = match self.pin.expected() {
            Some(expected) if expected == actual => return Ok(()),
            Some(expected) => format!("its SHA-256 {actual} does not match the pinned {expected}"),
            None => format!(
                "no SHA-256 is pinned for it (this build records none; set windows_hello_helper_sha256 to {actual} in {} and approve it)",
                crate::policy::files::SETTINGS_FILE_NAME
            ),
        };
        if self.hardened {
            return Err(format!(
                "refusing to run {}: {problem}",
                self.path.display()
            ));
        }
        match self.pin {
            Pin::None => {
                tracing::debug!(path = %self.path.display(), problem, "Running an unpinned Windows Hello helper")
            }
            _ => {
                tracing::warn!(path = %self.path.display(), problem, "Running a Windows Hello helper that does not match its pin")
            }
        }
        Ok(())
    }

    /// Runs `command` with `input` on stdin and returns its stdout decoded from base64. Checks the pin first.
    pub async fn run(
        &self,
        command: &str,
        input: Option<&[u8]>,
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>, RunError> {
        use base64::Engine;
        use tokio::io::AsyncWriteExt;
        self.check().map_err(RunError::Refused)?;
        let mut cmd = crate::hardening::command(&self.path);
        cmd.arg(command)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = tokio::process::Command::from(cmd)
            .kill_on_drop(true)
            .spawn()
            .map_err(RunError::Spawn)?;
        let mut stdin = child.stdin.take();
        let run = async move {
            if let (Some(stdin), Some(input)) = (stdin.as_mut(), input) {
                let line = format!(
                    "{}\n",
                    base64::engine::general_purpose::STANDARD.encode(input)
                );
                stdin.write_all(line.as_bytes()).await?;
            }
            drop(stdin);
            child.wait_with_output().await
        };
        let output = tokio::time::timeout(timeout, run)
            .await
            .map_err(|_| RunError::Timeout)?
            .map_err(RunError::Spawn)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(RunError::Exit {
                code: output.status.code(),
                stderr: stderr.trim().chars().take(512).collect(),
            });
        }
        if output.stdout.len() > MAX_OUTPUT {
            return Err(RunError::Malformed(format!(
                "{} bytes",
                output.stdout.len()
            )));
        }
        let stdout = String::from_utf8(output.stdout)
            .map_err(|_| RunError::Malformed("not UTF-8".to_owned()))?;
        base64::engine::general_purpose::STANDARD
            .decode(stdout.trim())
            .map_err(|e| RunError::Malformed(e.to_string()))
    }

    /// The SubjectPublicKeyInfo of the key credential, without asking the human.
    pub async fn public_key(&self) -> Result<Vec<u8>, RunError> {
        self.run("public-key", None, QUERY_TIMEOUT).await
    }

    /// Creates the key credential, or returns the existing one's public key.
    pub async fn create(&self) -> Result<Vec<u8>, RunError> {
        match self.run("create", None, CREATE_TIMEOUT).await {
            Err(e) if e.code() == Some(EXIT_EXISTS) => self.public_key().await,
            other => other,
        }
    }

    /// Has Windows Hello sign `data`; the human passes the dialog.
    pub async fn sign(
        &self,
        data: &[u8],
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>, RunError> {
        self.run("sign", Some(data), timeout).await
    }
}

/// Whether this is WSL2 with interop enabled, the only place the helper can run.
pub fn interop_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::platform::process::linux::wsl::Wsl::detect()
            .and_then(crate::platform::process::linux::wsl::Wsl::interop_enabled)
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Why a challenge was not signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsigned {
    /// Retry with `declined`, so the agent moves on to the next method.
    Declined(&'static str),
    /// The human cancelled or let the dialog time out: the agent is told, and denies the request.
    Denied(String),
}

#[derive(Debug)]
enum Source {
    /// WSL2 interop, `windows_hello_helper` and the shipped helper, looked up when a challenge arrives.
    Detect,
    Fixed {
        helper: Option<std::path::PathBuf>,
        hardened: bool,
    },
}

/// The client's side: answers `windows-hello` challenges through the helper. A decline sticks for the rest of the
/// command.
#[derive(Debug)]
pub struct Relay {
    source: Source,
    declined: parking_lot::Mutex<Option<&'static str>>,
}

impl Relay {
    pub fn detect() -> Self {
        Self {
            source: Source::Detect,
            declined: Default::default(),
        }
    }

    /// A helper at `helper`, regardless of WSL.
    pub fn fixed(helper: Option<std::path::PathBuf>, hardened: bool) -> Self {
        Self {
            source: Source::Fixed { helper, hardened },
            declined: Default::default(),
        }
    }

    async fn helper(&self) -> Option<(std::path::PathBuf, bool)> {
        match &self.source {
            Source::Fixed { helper, hardened } => helper.clone().map(|h| (h, *hardened)),
            Source::Detect => {
                if !interop_available() {
                    tracing::debug!(
                        "Not on WSL2 with interop; declining the Windows Hello challenge"
                    );
                    return None;
                }
                let config = crate::config::UserConfig::load().await.unwrap_or_else(|e| {
                    tracing::warn!(err = %e, "Failed to read config.json");
                    Default::default()
                });
                let helper = Helper::locate(&config);
                if helper.is_none() {
                    tracing::info!(
                        "No {HELPER_FILE_NAME} next to mairu and no windows_hello_helper; declining the Windows Hello challenge"
                    );
                }
                Some((helper?, crate::hardening::Hardening::marker().is_some()))
            }
        }
    }

    /// Signs the challenge's statement with the Windows Hello key when it is a registered one. `notice` gives the
    /// lines printed before the dialog opens.
    pub async fn sign(
        &self,
        challenge: &crate::proto::AuthorizationChallenge,
        notice: impl FnOnce() -> String,
    ) -> Result<Vec<u8>, Unsigned> {
        if let Some(declined) = *self.declined.lock() {
            return Err(Unsigned::Declined(declined));
        }
        let result = self.try_sign(challenge, notice).await;
        if let Err(Unsigned::Declined(declined)) = &result {
            *self.declined.lock() = Some(declined);
        }
        result
    }

    async fn try_sign(
        &self,
        challenge: &crate::proto::AuthorizationChallenge,
        notice: impl FnOnce() -> String,
    ) -> Result<Vec<u8>, Unsigned> {
        use crate::ssh_agent_presence::{DECLINED_NO_REGISTERED_KEY, DECLINED_SIGN_FAILED};
        let Some((path, hardened)) = self.helper().await else {
            return Err(Unsigned::Declined(DECLINED_NO_HELPER));
        };
        let helper = Helper {
            path,
            pin: Pin::resolve(Some(&challenge.windows_hello_helper_sha256)),
            hardened,
        };
        let spki = match helper.public_key().await {
            Ok(spki) => spki,
            Err(e) if e.is_not_enrolled() => {
                tracing::info!(err = %e, "No Windows Hello key credential; declining the challenge");
                return Err(Unsigned::Declined(DECLINED_NO_REGISTERED_KEY));
            }
            Err(e) => {
                tracing::warn!(helper = %helper.path.display(), err = %e, "The Windows Hello helper failed; declining the challenge");
                return Err(Unsigned::Declined(DECLINED_NO_HELPER));
            }
        };
        if !challenge.key_fingerprints.contains(&fingerprint(&spki)) {
            tracing::info!(
                "The Windows Hello key credential is not registered; declining the challenge"
            );
            return Err(Unsigned::Declined(DECLINED_NO_REGISTERED_KEY));
        }
        let notice = notice();
        if !notice.is_empty() {
            crate::terminal::send(&notice).await;
        }
        match helper
            .sign(&challenge.statement, remaining(challenge))
            .await
        {
            Ok(signature) => Ok(signature),
            Err(e) if e.is_cancelled() => Err(Unsigned::Denied(
                "the Windows Hello dialog was cancelled".to_owned(),
            )),
            Err(RunError::Timeout) => Err(Unsigned::Denied(
                "the Windows Hello dialog timed out".to_owned(),
            )),
            Err(e) if e.is_not_enrolled() => Err(Unsigned::Declined(DECLINED_NO_REGISTERED_KEY)),
            Err(e @ RunError::Refused(_)) => {
                tracing::warn!(err = %e, "Declining the Windows Hello challenge");
                Err(Unsigned::Declined(DECLINED_NO_HELPER))
            }
            Err(e) => {
                tracing::warn!(err = %e, "Windows Hello did not sign; declining the challenge");
                Err(Unsigned::Declined(DECLINED_SIGN_FAILED))
            }
        }
    }
}

/// The challenge's remaining lifetime, for the dialog.
fn remaining(challenge: &crate::proto::AuthorizationChallenge) -> std::time::Duration {
    let lifetime = crate::ssh_agent_presence::CHALLENGE_LIFETIME;
    challenge
        .expires_at
        .and_then(|t| std::time::SystemTime::try_from(t).ok())
        .and_then(|t| t.duration_since(std::time::SystemTime::now()).ok())
        .map_or(lifetime, |d| d.min(lifetime))
        .max(std::time::Duration::from_secs(1))
}

/// A registered key and its signatures, for tests elsewhere.
#[cfg(test)]
pub mod test_support {
    /// PKCS #8 DER of an RSA-2048 key, base64.
    pub const PRIVATE_KEY: &str = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC869jDZL09C2QqJKYT4SOtE50LSVsObls1eOzdtFl/0DEUvF2GWHavbBb26Pdjy8L94G0L+pKsfxvajLYUeqrlljz6JRUePb7EL2awJnMNq8TanP+f7cY1/EvbTSAMjefRXZoayMmpreXxHf0PU0fC7FHayuO94huhLqaEQQUi/n0rLygpr229gqdVWsF2lfnoEfke3x7CqeSkwYOMbnjP1JvDEaZMn1UHIuGzL3D171bDowobURlURcyNvRr/BGKUkqZWa5GExV4qh0Qx2G4aJIXOsW+uumKnu2RJY8Gz9oC6OC0xpe1UzKNa/NPrHEyrjBm9mDNRzGZ96Bi46M+tAgMBAAECggEADxlDUPRtamJNbk/RBSA2d3fsknEZqajYuciRF7P4/i3PqmJWkCzkSWdYW4HpeayYiC1GUdGEJOygt4IM8EyQeXpdI7nQewMAytGmAZiFE/fhKv6msGuyrnBcSKnckJxLxXAXZ6IZ+elnyfI1XiLwBoxYC2YxNuUKA8MEdGf05uOv6V502fa+2SnGlc4mhz1nQakn63B8AvmYuHi/yeNkqJvScplIwJcL4T9D3yv+KNCKWLMZX6/9B6X5tXvHlL/KRM9irY3Sm/aLV5PBbVzM/zZXou1J8pp1DX7R74Yr4QSRx2YLkQBsEMCKRitnFL9DMJODIZkj6GA6QRXd3PhtEQKBgQD+vGt8BXKX3kwyJyDLJf+yC3+FB9Fp82V8i7qkb4tPXT1/vwL7TCNFNffV1hPWvmab52nxUKOdUpGGmyjPiwtOCbv1EMb22u4cVeTGyukjDxkAWZy2lAP6zQh7Bba4qlYWvi6q7QpQtasUcrCuvALcPnmTdiw/SykSUy/+lWuD3QKBgQC929ND6uCBd7Y7VPk4zby76hcvNPuG3kRPwRN4A7g1ukSOIgHFohpPtUC9z9g5ErujeT1bkRJnEaAR689+GWyiYz3Ygpp9twSDei9cwmg7OAsNWyGoKXDonsufEOm7U+urICDfjsP0o4AVQdRczChck/3/q1K1YN5dU/oM7PdmEQKBgDAWuePL03pACPpe0J4JKmAeM5CVjT8HJ91/M1jfhdkRrQ50rMdr9CyYp5TCuTQM9anw4dsgcgK9F6PlnqqvgQ7WX5k/9Y+cfN70iB/PJnvr2bhrMl51StsJ4dP3nCr4XRAmDwFNhmj+IrHVhO03qQKS+LiR0oCQW8yNz72rz4QxAoGBAK2t2qXWx2moSVwdb583FeARVQQqQ64sxfDvfw/a1zjPHMeo9FYG5GrmNENvTy1mpZ/12Nta6qq+xN+gCEAioe4rOvhFAW7fbZGYxJrmfNMvgWzGYROkVVV3bm4k2qwzKPNygKAByeCRcSoA/nOlj4ahG0o3P4INC1305FnOrMMBAoGBAMviyNG65WdrOyE0+lo1MfWBtacrWY3MX2OBerooboGfM+RHtsUUpDb13OjTzeDpDo+G0ubmvJASzxotv7zhr9gy8/YS0vK3JPKgPulPPklejSvRplMi7REmt+9xUc6zuvgkkYPJEEkFqN62rYaw6qvJvokLwFpwYKAWH3Dmk5YJ";

    fn private() -> rsa::RsaPrivateKey {
        use base64::Engine;
        use rsa::pkcs8::DecodePrivateKey;
        let der = base64::engine::general_purpose::STANDARD
            .decode(PRIVATE_KEY)
            .unwrap();
        rsa::RsaPrivateKey::from_pkcs8_der(&der).unwrap()
    }

    pub fn key() -> super::RegisteredKey {
        use rsa::pkcs8::EncodePublicKey;
        let der = private().to_public_key().to_public_key_der().unwrap();
        super::RegisteredKey::from_der("test", der.as_bytes()).unwrap()
    }

    /// RSA PKCS #1 v1.5 with SHA-256, as Windows Hello signs.
    pub fn sign_bytes(data: &[u8]) -> Vec<u8> {
        use rsa::signature::{SignatureEncoding, Signer};
        rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private())
            .sign(data)
            .to_vec()
    }

    pub fn signed(
        challenge: &crate::proto::AuthorizationChallenge,
    ) -> crate::proto::AuthorizationResponse {
        crate::proto::AuthorizationResponse {
            challenge_id: challenge.challenge_id.clone(),
            result: Some(
                crate::proto::authorization_response::Result::WindowsHelloSignature(sign_bytes(
                    &challenge.statement,
                )),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Q-W2: from a Windows Hello key on Windows 11 25H2.
    const QW2_SPKI: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzXqNwEiMhTbmSIZQbFz7qICqSP/pTwGiwHPzu5pUh6uIK72wZGT2NgfmkahtC0wZBW2VXw9Z37fCLdYdAhtIl7dU//58lktKckkwfXCKkYQ4QD/K1R5CvnceXUuqIgwR3qxJCV1KW1Kv7CvH7NiZK1VaiAtqbPNOe4Uilk14rntMfH0OhPfS6HiTg7UmRoaYsR4q70owKnC6ahHBYILwDY6X4h3Lip8k9sOUUGVsE2CSCON78jejJqism166CNYsP99nlundVddlhh2m3BhcYoqObg7WVNGqZH/ovQQluuh0oktVGsrvvBpTFs7LKoHZMHt/YWSF+A1CSUue+PpFaQIDAQAB";
    const QW2_DATA: &[u8] = b"mairu Q-W2 test vector: hello";
    const QW2_SIGNATURE: &str = "yQ3hK8Zppf577e0I86Kr1jmsENGG5By1w6viC81BSRsbkmP+TFTDCcuF1Wmp3qPkCD6E9fpJoVL8nM6YFEAETsLDdCbGRSodBGV8konQrp3AZCcLN768hU6UtJ0VNOooZ7aJh3RvyMd3hQ2RdWaRyR15gPESvlWNRVN+Q9G65A+iGgEFyIyH7O6pLeJIT8t1JazKyzfSCKT37BZiOd3WVwolruy7vKHV96+i5XWGF6mkrx+F2ArjwBnnRTuUWfu6ntswzh2zc0lSS8obKzHCX1hSEfQlwbCZjiTcTqhmSjRtOiGUroq4UoRtIOTHvdTVs35iYRJ5i6uvcrVHVf8oBA==";
    /// The test key's RSA-PSS (SHA-256, 32-byte salt) signature over [`PSS_DATA`], from OpenSSL.
    const PSS_DATA: &[u8] = b"mairu PSS fixture";
    const PSS_SIGNATURE: &str = "JaJuI/daeqxBA8s3txr/a+WEqe9az7E6VvGQ4qjlgK2n6sQJsf8puwxaabyUFc9KZYG7lcSua5RKTHC5jCqDhJUXD7KUHO3tbgxe/FDR4F16rdXaPna4w4GNHb2O/FNBCgggjsjREpiNXIrTChChE0I0xJ/WtI4HXg3/gJvJ3rHdkuJeYs6q5QTBd5rkT6aZVCFBX7k6G26N0KW7NG91fEayxSjp36Eg8hffWbZn9pPg6IXwRV8a37rscCTZoiPcqQj7lSshQLUnzWSRnLgkhTocnGKCNWcgvW5O3O6/ouWDpmjWeOIbMLR31//TlIvNRfEvCoBUru2172iAOxv2NQ==";
    const RSA_1024_SPKI: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDV1vcfc5FbYFCP4NLad7Cb2aMROlVletkow+G6LAKMq5i1irWQ5OM3aDzdWb+b4+JdHlXb/YaOJQsx7zFEcvw4Ybsh5lQPzh+Omlm9EHCiNm5J5pFIi5YWXRgac97pwKX2YgKdD7mRkqv4jS5CwNhBXQkF4ruhS0rnlUxG8CQjSQIDAQAB";
    const P256_SPKI: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcgCBEbv8eo0ixfkV7AEwi7RInSj2V24dyw44tvg1Rz1XQ69sAm++wfLk15e6yl+MGlUyabN+5n5ZLyw6WQ0KjA==";

    const NOW: std::time::Duration = std::time::Duration::from_secs(1000);

    fn b64(s: &str) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(s).unwrap()
    }

    fn binding(pid: u32) -> crate::ssh_agent_presence::Binding {
        crate::ssh_agent_presence::Binding {
            pid,
            start_time: 7,
            action: crate::ssh_agent_presence::ACTION_ASSUME_ROLE,
            server_id: "contoso".to_owned(),
            rolespec: None,
            request_digest: [1; 32],
        }
    }

    #[test]
    fn test_q_w2_vector() {
        let key = RegisteredKey::parse("desktop", QW2_SPKI).unwrap();
        key.verify(QW2_DATA, &b64(QW2_SIGNATURE)).unwrap();
        assert!(
            key.verify(b"mairu Q-W2 test vector: hellO", &b64(QW2_SIGNATURE))
                .is_err()
        );
        assert!(
            test_support::key()
                .verify(QW2_DATA, &b64(QW2_SIGNATURE))
                .is_err()
        );
        assert_eq!(key.to_base64(), QW2_SPKI);
        assert!(key.fingerprint().starts_with("wh:SHA256:"));
        assert_eq!(key.fingerprint(), fingerprint(&b64(QW2_SPKI)));
        assert!(!key.fingerprint().ends_with('='));
    }

    #[test]
    fn test_pss_refused() {
        let key = test_support::key();
        key.verify(PSS_DATA, &test_support::sign_bytes(PSS_DATA))
            .unwrap();
        assert!(key.verify(PSS_DATA, &b64(PSS_SIGNATURE)).is_err());
    }

    #[test]
    fn test_parse_refusals() {
        assert!(
            RegisteredKey::parse("x", "not base64!")
                .unwrap_err()
                .contains("base64")
        );
        assert!(
            RegisteredKey::parse("x", "AAAA")
                .unwrap_err()
                .contains("RSA")
        );
        assert!(
            RegisteredKey::parse("x", RSA_1024_SPKI)
                .unwrap_err()
                .contains("RSA-1024")
        );
        assert!(RegisteredKey::parse("x", P256_SPKI).is_err());
    }

    #[test]
    fn test_verify_challenge() {
        let key = test_support::key();
        let keys = [key.clone()];
        let mut store = crate::ssh_agent_presence::Challenges::<()>::new([0; 16]);
        let issue = |store: &mut crate::ssh_agent_presence::Challenges<()>, method| {
            store
                .issue(binding(1), method, fingerprints(&keys), NOW, None)
                .0
        };
        let c = issue(&mut store, METHOD);
        assert_eq!(c.method, "windows-hello");
        assert_eq!(c.key_fingerprints, vec![key.fingerprint()]);
        let signature = test_support::sign_bytes(&c.statement);
        let pending = store.take(&c.challenge_id).unwrap();
        assert_eq!(
            verify(&pending, &binding(1), NOW, &signature, &keys).unwrap(),
            &key
        );
        assert!(store.take(&c.challenge_id).is_none());

        // Refusals: another process, expiry, another key, an altered statement, an ssh-agent challenge.
        assert!(
            verify(&pending, &binding(2), NOW, &signature, &keys)
                .unwrap_err()
                .contains("another process")
        );
        assert!(
            verify(
                &pending,
                &binding(1),
                NOW + crate::ssh_agent_presence::CHALLENGE_LIFETIME,
                &signature,
                &keys
            )
            .unwrap_err()
            .contains("expired")
        );
        let other = RegisteredKey::parse("desktop", QW2_SPKI).unwrap();
        assert!(verify(&pending, &binding(1), NOW, &signature, &[other]).is_err());
        let mut altered = c.statement.clone();
        altered[0] ^= 1;
        assert!(
            verify(
                &pending,
                &binding(1),
                NOW,
                &test_support::sign_bytes(&altered),
                &keys
            )
            .is_err()
        );
        let ssh = issue(&mut store, crate::ssh_agent_presence::METHOD);
        let pending = store.take(&ssh.challenge_id).unwrap();
        assert!(
            verify(
                &pending,
                &binding(1),
                NOW,
                &test_support::sign_bytes(&ssh.statement),
                &keys
            )
            .unwrap_err()
            .contains("ssh-agent challenge")
        );
    }

    #[test]
    fn test_pin() {
        if BUILD_HELPER_SHA256.is_some() {
            return;
        }
        assert_eq!(Pin::resolve(None), Pin::None);
        assert_eq!(Pin::resolve(Some("")), Pin::None);
        assert_eq!(Pin::resolve(Some("ABCD")), Pin::Settings("abcd".to_owned()));
    }

    /// A fake helper: `public-key` prints `spki`, `sign` saves stdin and prints `sign.out`, or exits with the
    /// status in `sign.status`.
    struct FakeHelper {
        dir: std::path::PathBuf,
    }

    impl FakeHelper {
        fn new(name: &str, spki: &[u8]) -> Self {
            use base64::Engine;
            use std::os::unix::fs::PermissionsExt;
            let dir = std::env::temp_dir().join(format!(
                "mairu-windows-hello-test-{}-{name}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("spki"),
                base64::engine::general_purpose::STANDARD.encode(spki),
            )
            .unwrap();
            let script = format!(
                "#!/bin/sh\nd='{}'\ncase \"$1\" in\n  public-key) cat \"$d/spki\" ;;\n  sign) cat >\"$d/stdin\"; [ -e \"$d/sign.status\" ] && exit \"$(cat \"$d/sign.status\")\"; cat \"$d/sign.out\" ;;\n  *) exit 64 ;;\nesac\n",
                dir.display()
            );
            let path = dir.join(HELPER_FILE_NAME);
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            Self { dir }
        }

        fn path(&self) -> std::path::PathBuf {
            self.dir.join(HELPER_FILE_NAME)
        }

        fn respond(&self, signature: &[u8]) {
            use base64::Engine;
            std::fs::write(
                self.dir.join("sign.out"),
                base64::engine::general_purpose::STANDARD.encode(signature),
            )
            .unwrap();
        }

        fn exit(&self, status: i32) {
            std::fs::write(self.dir.join("sign.status"), status.to_string()).unwrap();
        }

        fn stdin(&self) -> Option<String> {
            std::fs::read_to_string(self.dir.join("stdin")).ok()
        }
    }

    impl Drop for FakeHelper {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn challenge(
        store: &mut crate::ssh_agent_presence::Challenges<()>,
        keys: &[RegisteredKey],
    ) -> crate::proto::AuthorizationChallenge {
        store
            .issue(binding(1), METHOD, fingerprints(keys), NOW, None)
            .0
    }

    #[tokio::test]
    async fn test_relay_signs() {
        use base64::Engine;
        let key = test_support::key();
        let keys = [key.clone()];
        let fake = FakeHelper::new("signs", key.spki());
        let mut store = crate::ssh_agent_presence::Challenges::<()>::new([0; 16]);
        let c = challenge(&mut store, &keys);
        fake.respond(&test_support::sign_bytes(&c.statement));
        let relay = Relay::fixed(Some(fake.path()), false);
        let noticed = std::sync::atomic::AtomicBool::new(false);
        let signature = relay
            .sign(&c, || {
                noticed.store(true, std::sync::atomic::Ordering::SeqCst);
                String::new()
            })
            .await
            .unwrap();
        assert!(noticed.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            fake.stdin().unwrap().trim(),
            base64::engine::general_purpose::STANDARD.encode(&c.statement)
        );
        let pending = store.take(&c.challenge_id).unwrap();
        verify(&pending, &binding(1), NOW, &signature, &keys).unwrap();
    }

    #[tokio::test]
    async fn test_relay_declines() {
        let key = test_support::key();
        let keys = [key.clone()];
        let mut store = crate::ssh_agent_presence::Challenges::<()>::new([0; 16]);
        let c = challenge(&mut store, &keys);

        let missing = Relay::fixed(None, false);
        assert_eq!(
            missing.sign(&c, String::new).await,
            Err(Unsigned::Declined(DECLINED_NO_HELPER))
        );

        // Another key credential than the registered one: nothing is shown.
        let other = RegisteredKey::parse("desktop", QW2_SPKI).unwrap();
        let fake = FakeHelper::new("unregistered", other.spki());
        let relay = Relay::fixed(Some(fake.path()), false);
        assert_eq!(
            relay.sign(&c, || panic!("noticed")).await,
            Err(Unsigned::Declined(
                crate::ssh_agent_presence::DECLINED_NO_REGISTERED_KEY
            ))
        );
        assert!(fake.stdin().is_none());
        // The decline sticks.
        drop(fake);
        assert_eq!(
            relay.sign(&c, String::new).await,
            Err(Unsigned::Declined(
                crate::ssh_agent_presence::DECLINED_NO_REGISTERED_KEY
            ))
        );

        let fake = FakeHelper::new("fails", key.spki());
        fake.exit(1);
        assert_eq!(
            Relay::fixed(Some(fake.path()), false)
                .sign(&c, String::new)
                .await,
            Err(Unsigned::Declined(
                crate::ssh_agent_presence::DECLINED_SIGN_FAILED
            ))
        );
    }

    #[tokio::test]
    async fn test_relay_cancelled() {
        let key = test_support::key();
        let mut store = crate::ssh_agent_presence::Challenges::<()>::new([0; 16]);
        let c = challenge(&mut store, std::slice::from_ref(&key));
        let fake = FakeHelper::new("cancelled", key.spki());
        fake.exit(EXIT_CANCELLED);
        let relay = Relay::fixed(Some(fake.path()), false);
        assert!(matches!(
            relay.sign(&c, String::new).await,
            Err(Unsigned::Denied(d)) if d.contains("cancelled")
        ));
        // A cancellation is no decline; the next challenge asks again.
        assert!(matches!(
            relay.sign(&c, String::new).await,
            Err(Unsigned::Denied(_))
        ));
    }

    #[tokio::test]
    async fn test_relay_pin() {
        let key = test_support::key();
        let mut store = crate::ssh_agent_presence::Challenges::<()>::new([0; 16]);
        let mut c = challenge(&mut store, std::slice::from_ref(&key));
        let fake = FakeHelper::new("pin", key.spki());
        fake.respond(&test_support::sign_bytes(&c.statement));
        let actual = digest(&fake.path()).unwrap();

        let helper = |pin: Pin, hardened| Helper {
            path: fake.path(),
            pin,
            hardened,
        };
        helper(Pin::Settings(actual.clone()), true).check().unwrap();
        assert!(
            helper(Pin::Settings("00".repeat(32)), true)
                .check()
                .unwrap_err()
                .contains("does not match")
        );
        assert!(
            helper(Pin::None, true)
                .check()
                .unwrap_err()
                .contains("no SHA-256 is pinned")
        );
        helper(Pin::Settings("00".repeat(32)), false)
            .check()
            .unwrap();
        helper(Pin::None, false).check().unwrap();

        if BUILD_HELPER_SHA256.is_some() {
            return;
        }
        // A hardened client runs the helper only while it matches the approved pin.
        assert_eq!(
            Relay::fixed(Some(fake.path()), true)
                .sign(&c, String::new)
                .await,
            Err(Unsigned::Declined(DECLINED_NO_HELPER))
        );
        c.windows_hello_helper_sha256 = actual;
        Relay::fixed(Some(fake.path()), true)
            .sign(&c, String::new)
            .await
            .unwrap();
        c.windows_hello_helper_sha256 = "00".repeat(32);
        assert_eq!(
            Relay::fixed(Some(fake.path()), true)
                .sign(&c, String::new)
                .await,
            Err(Unsigned::Declined(DECLINED_NO_HELPER))
        );
    }
}
