#[derive(Debug, Clone)]
pub struct Auto {
    pub path: std::path::PathBuf,
    pub data: Vec<u8>,

    pub inner: AutoData,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct AutoData {
    pub server: String,
    pub role: String,
    pub mode: Option<crate::config::ProviderMode>,
}

impl Auto {
    pub async fn find_for(dir: impl AsRef<std::path::Path>) -> crate::Result<Option<Auto>> {
        let Some(path) = find_auto_file_path(dir).await? else {
            return Ok(None);
        };

        let json = match tokio::fs::read(&path).await {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(path = ?path, err = ?e, "Failed to read .mairu.json");
                return Ok(None);
            }
        };
        let inner: AutoData = serde_json::from_slice(&json)?;

        Ok(Some(Auto {
            data: json,
            path,
            inner,
        }))
    }

    pub fn digest(&self) -> TrustDigest {
        TrustDigest::Sha384 {
            hash: self.digest_sha384().to_vec(),
        }
    }

    pub fn digest_sha384(&self) -> [u8; 48] {
        use sha2::Digest;

        #[cfg(unix)]
        let path = {
            use std::os::unix::ffi::OsStrExt;
            self.path.as_os_str().as_bytes()
        };

        let hash = sha2::Sha384::new()
            .chain_update(b"v0.auto\0\0")
            .chain_update(path)
            .chain_update(b"\0\0")
            .chain_update(&self.data)
            .finalize();

        hash.as_slice().try_into().unwrap()
    }

    pub fn trust_path(&self) -> std::path::PathBuf {
        use base64::Engine;
        use sha2::Digest;

        #[cfg(unix)]
        let path = {
            use std::os::unix::ffi::OsStrExt;
            self.path.as_os_str().as_bytes()
        };

        let hash = sha2::Sha256::new()
            .chain_update(b"v0.trust_path\0\0")
            .chain_update(path)
            .finalize();
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);

        crate::config::trust_dir().join(format!("trust.{key}.json"))
    }

    pub async fn find_trust(&self) -> Option<Trustability> {
        let path = self.trust_path();
        let data = match tokio::fs::read(&path).await {
            Ok(d) => d,
            Err(e) => {
                if !matches!(e.kind(), std::io::ErrorKind::NotFound) {
                    tracing::warn!(auto_path = ?self.path, trust_path = ?path, err = ?e, "Failed to read trust");
                }
                return None;
            }
        };
        let trust: Trust = match serde_json::from_slice(&data) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(auto_path = ?self.path, trust_path = ?path, err = ?e, "Failed to parse trust");
                return None;
            }
        };

        Some(Trustability::verify(self, trust))
    }

    pub async fn mark_trust(&self) -> crate::Result<()> {
        use tokio::io::AsyncWriteExt;

        let trust = Trust {
            path: self.path.clone(),
            trust: true,
            digest: self.digest(),
            content: self.inner.clone(),
            updated_at: chrono::Utc::now(),
        };
        let trust_path = self.trust_path();

        tracing::info!(path = %self.path.display(), trust_path = %trust_path.display(), auto = ?self.inner, trust = ?trust, "saving Trust");
        let data = serde_json::to_string_pretty(&trust)?;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .mode(0o600)
            .open(&trust_path)
            .await?;
        file.write_all(data.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        Ok(())
    }
}

async fn find_auto_file_path(
    dir: impl AsRef<std::path::Path>,
) -> crate::Result<Option<std::path::PathBuf>> {
    if !dir.as_ref().is_absolute() {
        return Err(crate::Error::UserError(format!(
            "Auto::find_for(dir): dir must be an absolute path, {} given",
            dir.as_ref().display()
        )));
    }
    let mut dir = dir.as_ref().to_path_buf();
    loop {
        let candidate = dir.join(".mairu.json");

        if tokio::fs::metadata(&candidate).await.is_ok() {
            return Ok(Some(candidate));
        }

        if !dir.pop() {
            break;
        }
    }

    Ok(None)

    // TODO: ceiling directory
    // TODO: one filesystem
}

#[derive(Debug, Clone)]
pub enum Trustability {
    Matched(Trust),
    Diverged(Trust),
}

impl Trustability {
    pub fn verify(auto: &Auto, trust: Trust) -> Self {
        let matched = match trust.digest {
            TrustDigest::Sha384 { ref hash } => {
                let hash_u8r: Result<&[u8; 48], _> = hash.as_slice().try_into();
                if let Ok(hash_u8) = hash_u8r {
                    &auto.digest_sha384() == hash_u8
                } else {
                    false
                }
            }
        };
        if matched {
            Trustability::Matched(trust)
        } else {
            Trustability::Diverged(trust)
        }
    }
}

#[serde_with::serde_as]
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Trust {
    pub path: std::path::PathBuf,
    pub trust: bool,
    pub digest: TrustDigest,
    pub content: AutoData,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[serde_with::serde_as]
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum TrustDigest {
    Sha384 {
        #[serde_as(
            as = "serde_with::base64::Base64<serde_with::base64::Standard, serde_with::formats::Padded>"
        )]
        hash: Vec<u8>, // [u8; 48]
    },
}

impl std::fmt::Display for TrustDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use base64::Engine;
        let hash = match self {
            TrustDigest::Sha384 { ref hash } => hash,
        };
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
        write!(f, "{b64}")
    }
}
