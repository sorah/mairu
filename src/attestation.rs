//! Verifies the sigstore attestation (GitHub artifact attestation, build provenance) of a mairu release binary,
//! for `mairu harden --from`.

const ISSUER: &str = "https://token.actions.githubusercontent.com";
const GITHUB_API: &str = "https://api.github.com";
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Who must have signed the attestation: a release workflow run for a version tag.
#[derive(Debug, Clone, Copy)]
pub struct Signer<'a> {
    pub repository: &'a str,
    pub workflow: &'a str,
}

impl Signer<'static> {
    pub const MAIRU: Self = Signer {
        repository: "sorah/mairu",
        workflow: ".github/workflows/release.yml",
    };
}

impl Signer<'_> {
    /// The release version from a certificate identity such as
    /// `https://github.com/sorah/mairu/.github/workflows/release.yml@refs/tags/v0.13.0`.
    pub fn version_from_identity(&self, identity: &str) -> Option<String> {
        let prefix = format!(
            "https://github.com/{}/{}@refs/tags/v",
            self.repository, self.workflow
        );
        let version = identity.strip_prefix(&prefix)?;
        crate::version::at_least(version, "0.0.0").then(|| version.to_owned())
    }
}

/// A verified attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    pub version: String,
    pub identity: String,
}

/// Verifies `artifact` against each bundle in turn and returns the first one signed by `signer`.
pub fn verify_bundles(
    root: &sigstore_verify::trust_root::TrustedRoot,
    signer: Signer<'_>,
    artifact: sigstore_verify::types::Artifact<'_>,
    bundles: &[sigstore_verify::types::Bundle],
) -> Result<Attested, anyhow::Error> {
    let verifier = sigstore_verify::Verifier::new(root)?;
    let policy = sigstore_verify::VerificationPolicy::any_identity().require_issuer(ISSUER);
    let mut failures = vec![];
    for bundle in bundles {
        match verifier.verify(artifact.clone(), bundle, &policy) {
            Ok(result) => match attested(&result, signer) {
                Ok(a) => return Ok(a),
                Err(e) => failures.push(e),
            },
            Err(e) => failures.push(e.to_string()),
        }
    }
    if failures.is_empty() {
        anyhow::bail!("no attestation found");
    }
    anyhow::bail!("no valid attestation: {}", failures.join("; "))
}

fn attested(
    result: &sigstore_verify::VerificationResult,
    signer: Signer<'_>,
) -> Result<Attested, String> {
    if !(result.certificate_verified() && result.tlog_verified()) {
        return Err("the certificate or the transparency log entry was not verified".to_owned());
    }
    let identity = match result.identity() {
        Some(sigstore_verify::SubjectAltName::Uri(uri)) => uri.clone(),
        other => return Err(format!("unexpected certificate identity {other:?}")),
    };
    match signer.version_from_identity(&identity) {
        Some(version) => Ok(Attested { version, identity }),
        None => Err(format!(
            "signed by {identity}, not by {}/{} for a version tag",
            signer.repository, signer.workflow
        )),
    }
}

/// Verifies `artifact`, read from `path`, against the sigstore public-good trust root fetched through TUF. The
/// bundle comes from `<path>.sigstore.json`, or else from GitHub's attestation API by digest. Fails closed.
pub fn verify_file(path: &std::path::Path, artifact: &[u8]) -> Result<Attested, anyhow::Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let client = sigstore_trust_root::reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .user_agent(concat!("mairu/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let bundles = match local_bundle(path)? {
            Some(bundle) => vec![bundle],
            None => fetch_bundles(&client, Signer::MAIRU, artifact).await?,
        };
        let config = sigstore_trust_root::TufConfig::production()
            .without_cache()
            .with_http_client(client);
        let root = sigstore_trust_root::TrustedRoot::from_tuf(config)
            .await
            .map_err(|e| anyhow::anyhow!("failed to update the sigstore trust root: {e}"))?;
        verify_bundles(&root, Signer::MAIRU, artifact.into(), &bundles)
    })
}

fn local_bundle(
    path: &std::path::Path,
) -> Result<Option<sigstore_verify::types::Bundle>, anyhow::Error> {
    let mut bundle_path = path.as_os_str().to_owned();
    bundle_path.push(".sigstore.json");
    let bundle_path = std::path::PathBuf::from(bundle_path);
    match std::fs::read_to_string(&bundle_path) {
        Ok(json) => {
            let bundle = sigstore_verify::types::Bundle::from_json(&json)
                .map_err(|e| anyhow::anyhow!("{}: {e}", bundle_path.display()))?;
            eprintln!("Using the attestation in {}", bundle_path.display());
            Ok(Some(bundle))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::anyhow!("{}: {e}", bundle_path.display())),
    }
}

#[derive(serde::Deserialize)]
struct AttestationsResponse {
    #[serde(default)]
    attestations: Vec<AttestationEntry>,
}

#[derive(serde::Deserialize)]
struct AttestationEntry {
    bundle: Option<serde_json::Value>,
    bundle_url: Option<String>,
}

async fn fetch_bundles(
    client: &sigstore_trust_root::reqwest::Client,
    signer: Signer<'_>,
    artifact: &[u8],
) -> Result<Vec<sigstore_verify::types::Bundle>, anyhow::Error> {
    use sha2::Digest;
    let digest = hex_encode(&sha2::Sha256::digest(artifact));
    let url = format!(
        "{GITHUB_API}/repos/{}/attestations/sha256:{digest}",
        signer.repository
    );
    eprintln!("Fetching the attestation from {url}");
    let response = client
        .get(&url)
        .header("accept", "application/vnd.github+json")
        .send()
        .await?;
    if response.status() == 404 {
        anyhow::bail!(
            "GitHub has no attestation for this file (sha256:{digest}) in {}",
            signer.repository
        );
    }
    let response: AttestationsResponse = response.error_for_status()?.json().await?;
    let mut bundles = vec![];
    for entry in response.attestations {
        let json = match (entry.bundle, entry.bundle_url) {
            (Some(bundle), _) => bundle.to_string(),
            (None, Some(url)) => fetch_bundle_url(client, &url).await?,
            (None, None) => continue,
        };
        bundles.push(parse_bundle(&json)?);
    }
    Ok(bundles)
}

/// A bundle URL serves the bundle compressed with raw snappy.
async fn fetch_bundle_url(
    client: &sigstore_trust_root::reqwest::Client,
    url: &str,
) -> Result<String, anyhow::Error> {
    let body = client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let raw = snap::raw::Decoder::new().decompress_vec(&body)?;
    Ok(String::from_utf8(raw)?)
}

fn parse_bundle(json: &str) -> Result<sigstore_verify::types::Bundle, anyhow::Error> {
    sigstore_verify::types::Bundle::from_json(json)
        .map_err(|e| anyhow::anyhow!("malformed attestation bundle: {e}"))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // GitHub's attestation API response for mise-v2026.10.24-linux-x64-musl.tar.gz: an immutable-release
    // attestation and a build provenance attestation signed by jdx/mise's release workflow.
    const MISE_RESPONSE: &str = include_str!("../testdata/attestation/mise-v2026.10.24.json");
    const MISE_DIGEST: &str = "257bc6521a2401470fc38cf6be45bbf5783c0443c80298b61fb13f3354f7e06e";
    const MISE: Signer<'static> = Signer {
        repository: "jdx/mise",
        workflow: ".github/workflows/release.yml",
    };

    fn mise_bundles() -> Vec<sigstore_verify::types::Bundle> {
        let response: AttestationsResponse = serde_json::from_str(MISE_RESPONSE).unwrap();
        response
            .attestations
            .into_iter()
            .map(|a| parse_bundle(&a.bundle.unwrap().to_string()).unwrap())
            .collect()
    }

    fn embedded_root() -> sigstore_verify::trust_root::TrustedRoot {
        sigstore_verify::trust_root::TrustedRoot::from_embedded(
            sigstore_verify::trust_root::SigstoreInstance::PublicGood,
        )
        .unwrap()
    }

    fn verify_digest(
        signer: Signer<'_>,
        digest: &str,
        bundles: &[sigstore_verify::types::Bundle],
    ) -> Result<Attested, anyhow::Error> {
        let digest = sigstore_verify::types::Sha256Hash::from_hex(digest)?;
        verify_bundles(&embedded_root(), signer, digest.into(), bundles)
    }

    #[test]
    fn test_version_from_identity() {
        let mairu = Signer::MAIRU;
        assert_eq!(
            mairu.version_from_identity(
                "https://github.com/sorah/mairu/.github/workflows/release.yml@refs/tags/v0.13.0"
            ),
            Some("0.13.0".to_owned())
        );
        for identity in [
            "https://github.com/sorah/mairu/.github/workflows/release.yml@refs/heads/main",
            "https://github.com/sorah/mairu/.github/workflows/ci.yml@refs/tags/v0.13.0",
            "https://github.com/evil/mairu/.github/workflows/release.yml@refs/tags/v0.13.0",
            "https://github.com/sorah/mairu-fork/.github/workflows/release.yml@refs/tags/v0.13.0",
            "https://github.com/sorah/mairu/.github/workflows/release.yml@refs/tags/v0.13",
            "https://github.com/sorah/mairu/.github/workflows/release.yml@refs/tags/vgarbage",
            "https://github.com/sorah/mairu/.github/workflows/release.yml@refs/tags/0.13.0",
        ] {
            assert_eq!(mairu.version_from_identity(identity), None, "{identity}");
        }
    }

    #[test]
    fn test_verify_release_attestation() {
        let attested = verify_digest(MISE, MISE_DIGEST, &mise_bundles()).unwrap();
        assert_eq!(attested.version, "2026.10.24");
        assert_eq!(
            attested.identity,
            "https://github.com/jdx/mise/.github/workflows/release.yml@refs/tags/v2026.10.24"
        );
    }

    #[test]
    fn test_verify_wrong_digest() {
        let other = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(verify_digest(MISE, other, &mise_bundles()).is_err());
    }

    #[test]
    fn test_verify_wrong_signer() {
        let err = verify_digest(Signer::MAIRU, MISE_DIGEST, &mise_bundles()).unwrap_err();
        assert!(err.to_string().contains("not by sorah/mairu"), "{err}");
    }

    #[test]
    fn test_verify_bundles_bytes() {
        let err = verify_bundles(&embedded_root(), MISE, b"not mise".into(), &mise_bundles());
        assert!(err.is_err());
        let err = verify_bundles(&embedded_root(), MISE, b"not mise".into(), &[]).unwrap_err();
        assert_eq!(err.to_string(), "no attestation found");
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xab, 0xff]), "00abff");
    }

    /// Fetches the trust root through TUF and the bundles from GitHub. `cargo test -- --ignored` with network.
    #[test]
    #[ignore]
    fn test_online_trust_root_and_api() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let client = sigstore_trust_root::reqwest::Client::builder()
                .timeout(HTTP_TIMEOUT)
                .user_agent("mairu-test")
                .build()
                .unwrap();
            let config = sigstore_trust_root::TufConfig::production()
                .without_cache()
                .with_http_client(client.clone());
            sigstore_trust_root::TrustedRoot::from_tuf(config)
                .await
                .unwrap();
            let url = format!("{GITHUB_API}/repos/jdx/mise/attestations/sha256:{MISE_DIGEST}");
            let response: AttestationsResponse = client
                .get(&url)
                .header("accept", "application/vnd.github+json")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let url = response.attestations[0].bundle_url.as_ref().unwrap();
            parse_bundle(&fetch_bundle_url(&client, url).await.unwrap()).unwrap();
        });
    }
}
