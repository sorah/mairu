//! Integrity records as the stores keep them: the JSON form, record names, and where the protected directory keeps
//! them.

/// The root of the protected directory, `root:mairu 2770` after `mairu harden`.
pub const PROTECTED_DIRECTORY: &str = "/var/lib/mairu";
/// Records larger than this are refused when read back.
pub const MAX_RECORD_SIZE: usize = 64 * 1024;

const RECORD_VERSION: u32 = 1;

/// Record names are used in file names and store attributes.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `/var/lib/mairu/users/<uid>`.
pub fn user_directory(root: &std::path::Path, uid: u32) -> std::path::PathBuf {
    root.join("users").join(uid.to_string())
}

/// `/var/lib/mairu/users/<uid>/<name>.record`.
pub fn record_path(root: &std::path::Path, uid: u32, name: &str) -> std::path::PathBuf {
    user_directory(root, uid).join(format!("{name}.record"))
}

/// Strong stores cannot be written by same-user code.
pub fn is_strong(kind: crate::proto::platform::IntegrityStoreKind) -> bool {
    use crate::proto::platform::IntegrityStoreKind as K;
    matches!(kind, K::ProtectedDirectory | K::DataProtectionKeychain)
}

pub fn store_name(kind: crate::proto::platform::IntegrityStoreKind) -> &'static str {
    use crate::proto::platform::IntegrityStoreKind as K;
    match kind {
        K::Unspecified => "unknown",
        K::ProtectedDirectory => "protected-directory",
        K::SecretService => "secret-service",
        K::DataProtectionKeychain => "data-protection-keychain",
        K::LegacyKeychain => "legacy-keychain",
    }
}

pub fn status_name(status: crate::proto::platform::IntegrityStatus) -> &'static str {
    use crate::proto::platform::IntegrityStatus as S;
    match status {
        S::Unspecified => "unknown",
        S::Matched => "matched",
        S::Mismatched => "mismatched",
        S::NotRecorded => "not-recorded",
        S::Unavailable => "unavailable",
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd length".to_owned());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            s.get(i..i + 2)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
                .ok_or_else(|| format!("invalid hex at {i}"))
        })
        .collect()
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordJson {
    version: u32,
    generation: u64,
    digest: String,
    servers: std::collections::BTreeMap<String, String>,
    approval: AnchorJson,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorJson {
    methods: Vec<String>,
    ssh_agent_keys: Vec<String>,
    windows_hello_keys: Vec<String>,
}

impl crate::proto::platform::IntegrityRecord {
    /// `{"version": 1, "generation": 7, "digest": "<hex>", "servers": {...}, "approval": {...}}`.
    pub fn to_json(&self) -> String {
        use base64::Engine;
        let approval = self.approval.clone().unwrap_or_default();
        let json = RecordJson {
            version: RECORD_VERSION,
            generation: self.generation,
            digest: hex(&self.digest),
            servers: self
                .server_digests
                .iter()
                .map(|(id, d)| (id.clone(), hex(d)))
                .collect(),
            approval: AnchorJson {
                methods: approval.methods,
                ssh_agent_keys: approval.ssh_agent_keys,
                windows_hello_keys: approval
                    .windows_hello_keys
                    .iter()
                    .map(|k| base64::engine::general_purpose::STANDARD.encode(k))
                    .collect(),
            },
        };
        serde_json::to_string(&json).unwrap_or_default()
    }

    pub fn from_json(source: &[u8]) -> Result<Self, String> {
        use base64::Engine;
        if source.len() > MAX_RECORD_SIZE {
            return Err(format!("larger than {MAX_RECORD_SIZE} bytes"));
        }
        let json: RecordJson = serde_json::from_slice(source).map_err(|e| e.to_string())?;
        if json.version != RECORD_VERSION {
            return Err(format!("unsupported record version {}", json.version));
        }
        let digest = |s: &str| {
            let d = unhex(s)?;
            if d.len() != 32 {
                return Err(format!("a digest has {} bytes, not 32", d.len()));
            }
            Ok(d)
        };
        Ok(Self {
            digest: digest(&json.digest)?,
            approval: Some(crate::proto::platform::ApprovalAnchor {
                methods: json.approval.methods,
                ssh_agent_keys: json.approval.ssh_agent_keys,
                windows_hello_keys: json
                    .approval
                    .windows_hello_keys
                    .iter()
                    .map(|k| {
                        base64::engine::general_purpose::STANDARD
                            .decode(k)
                            .map_err(|e| e.to_string())
                    })
                    .collect::<Result<_, _>>()?,
            }),
            generation: json.generation,
            server_digests: json
                .servers
                .iter()
                .map(|(id, d)| Ok((id.clone(), digest(d)?)))
                .collect::<Result<_, String>>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> crate::proto::platform::IntegrityRecord {
        crate::proto::platform::IntegrityRecord {
            digest: vec![0xab; 32],
            approval: Some(crate::proto::platform::ApprovalAnchor {
                methods: vec!["platform".to_owned()],
                ssh_agent_keys: vec!["ssh-ed25519 AAAA alice".to_owned()],
                windows_hello_keys: vec![vec![0x30, 0x01]],
            }),
            generation: 7,
            server_digests: [("contoso".to_owned(), vec![0x01; 32])].into(),
        }
    }

    #[test]
    fn test_record_json_round_trip() {
        let json = record().to_json();
        assert!(json.starts_with(r#"{"version":1,"generation":7,"digest":"abab"#));
        assert!(json.contains(r#""servers":{"contoso":"0101"#));
        assert_eq!(
            crate::proto::platform::IntegrityRecord::from_json(json.as_bytes()).unwrap(),
            record()
        );
    }

    #[test]
    fn test_record_json_rejects() {
        let reject = |s: &str| crate::proto::platform::IntegrityRecord::from_json(s.as_bytes());
        assert!(reject("{}").is_err());
        let mut v: serde_json::Value = serde_json::from_str(&record().to_json()).unwrap();
        v["digest"] = "abcd".into();
        assert!(reject(&v.to_string()).unwrap_err().contains("2 bytes"));
        v["digest"] = "zz".repeat(32).into();
        assert!(reject(&v.to_string()).is_err());
        let mut v: serde_json::Value = serde_json::from_str(&record().to_json()).unwrap();
        v["version"] = 2.into();
        assert!(reject(&v.to_string()).is_err());
        v["version"] = 1.into();
        v["extra"] = 1.into();
        assert!(reject(&v.to_string()).is_err());
    }

    #[test]
    fn test_names_and_paths() {
        assert!(valid_name("policy"));
        assert!(valid_name("policy-dev"));
        assert!(!valid_name("../policy"));
        assert!(!valid_name(""));
        assert_eq!(
            record_path(std::path::Path::new(PROTECTED_DIRECTORY), 1000, "policy"),
            std::path::Path::new("/var/lib/mairu/users/1000/policy.record")
        );
    }

    #[test]
    fn test_hex() {
        assert_eq!(hex(&[0x00, 0xff, 0x1a]), "00ff1a");
        assert_eq!(unhex("00ff1a").unwrap(), vec![0x00, 0xff, 0x1a]);
        assert!(unhex("0").is_err());
    }
}
