//! `authorization.json`: settings that are not policies, and the subset in force for a policy state.

/// How long a grant is kept at all, by default; freshness itself is up to the policy.
pub const DEFAULT_GRANT_RETENTION_SECS: u64 = 43200;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationSettings {
    pub version: u32,
    pub methods: Option<Vec<String>>,
    pub approval_methods: Option<Vec<String>>,
    pub tool_detection: Option<std::collections::BTreeMap<String, ToolDetectionEntry>>,
    pub grant_retention_secs: Option<u64>,
    pub sts: Option<StsSettings>,
    pub network: Option<NetworkSettings>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDetectionEntry {
    #[serde(default)]
    pub process_names: Vec<String>,
    #[serde(default)]
    pub env_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct StsSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<url::Url>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub servers: std::collections::BTreeMap<String, StsServerSettings>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct StsServerSettings {
    pub region: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<url::Url>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_roots: Vec<String>,
}

impl AuthorizationSettings {
    /// Parses and validates `authorization.json`. Comments are not accepted.
    pub fn parse(source: &str) -> Result<Self, String> {
        let settings: Self = serde_json::from_str(source).map_err(|e| e.to_string())?;
        settings.validate()?;
        Ok(settings)
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!("unsupported version {}; expected 1", self.version));
        }
        for (field, methods) in [
            ("methods", &self.methods),
            ("approval_methods", &self.approval_methods),
        ] {
            for method in methods.iter().flatten() {
                if !KNOWN_METHODS.contains(&method.as_str()) {
                    return Err(format!(
                        "{field}: unknown method {method:?}; known: {}",
                        KNOWN_METHODS.join(", ")
                    ));
                }
            }
        }
        for label in self.tool_detection.iter().flat_map(|t| t.keys()) {
            if !crate::tool_detection::ToolLabel::is_valid_name(label) {
                return Err(format!(
                    "tool_detection: invalid label {label:?}; use lowercase letters, digits and '-'"
                ));
            }
        }
        if let Some(endpoint) = self.sts.as_ref().and_then(|s| s.endpoint.as_ref())
            && endpoint.scheme() != "https"
        {
            return Err(format!("sts.endpoint: {endpoint} is not https"));
        }
        if let Some(network) = &self.network {
            if let Some(proxy) = &network.proxy
                && !matches!(proxy.scheme(), "http" | "https")
            {
                return Err(format!("network.proxy: {proxy} is not http or https"));
            }
            for (i, pem) in network.extra_roots.iter().enumerate() {
                validate_certificate(pem).map_err(|e| format!("network.extra_roots[{i}]: {e}"))?;
            }
        }
        Ok(())
    }
}

/// The presence methods this binary knows.
const KNOWN_METHODS: &[&str] = &[crate::authorization::METHOD_PLATFORM];

const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

/// Exactly one PEM certificate.
fn validate_certificate(pem: &str) -> Result<(), String> {
    use base64::Engine;
    let pem = pem.trim();
    let body = pem
        .strip_prefix(PEM_BEGIN)
        .and_then(|rest| rest.strip_suffix(PEM_END))
        .ok_or("not a single PEM certificate")?;
    if body.contains("-----") {
        return Err("not a single PEM certificate".to_owned());
    }
    let der: String = body.split_whitespace().collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(der)
        .map_err(|e| format!("invalid base64: {e}"))?;
    if der.first() != Some(&0x30) {
        return Err("not a DER certificate".to_owned());
    }
    reqwest::Certificate::from_pem(pem.as_bytes()).map_err(|e| e.to_string())?;
    Ok(())
}

/// Whether the policy files carry an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyState {
    /// Neither file exists, and no store holds a record.
    Absent,
    /// A strong store, or on an unhardened agent a weak one, records the files as they are.
    Approved,
    /// A file exists, and nothing records that a human approved it.
    Unapproved,
    /// The files differ from a record: lockdown.
    Tampered,
}

impl PolicyState {
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyState::Absent => "absent",
            PolicyState::Approved => "approved",
            PolicyState::Unapproved => "unapproved",
            PolicyState::Tampered => "tampered",
        }
    }

    /// `APPROVED` < `UNAPPROVED` < `TAMPERED`; `ABSENT` sits with `APPROVED`, as the built-ins apply anyway.
    fn strictness(self) -> u8 {
        match self {
            PolicyState::Absent | PolicyState::Approved => 0,
            PolicyState::Unapproved => 1,
            PolicyState::Tampered => 2,
        }
    }

    /// The stricter of two states.
    pub fn max(self, other: Self) -> Self {
        if other.strictness() > self.strictness() {
            other
        } else {
            self
        }
    }

    pub fn to_proto(self) -> crate::proto::PolicyIntegrity {
        match self {
            PolicyState::Absent => crate::proto::PolicyIntegrity::Absent,
            PolicyState::Approved => crate::proto::PolicyIntegrity::Approved,
            PolicyState::Unapproved => crate::proto::PolicyIntegrity::Unapproved,
            PolicyState::Tampered => crate::proto::PolicyIntegrity::Tampered,
        }
    }
}

/// `approval_methods` when the file has none: the key-based methods with registered keys, else `["platform"]`.
/// No key-based method exists yet.
pub fn default_approval_methods() -> Vec<String> {
    vec![crate::authorization::METHOD_PLATFORM.to_owned()]
}

/// The settings in force.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EffectiveSettings {
    pub version: u32,
    pub methods: Vec<String>,
    /// Methods allowed to approve the next change, recorded in the anchor; only set from an approved file.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub approval_methods: Vec<String>,
    /// Additions to the built-in labels.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub tool_detection: std::collections::BTreeMap<String, ToolDetectionEntry>,
    pub grant_retention_secs: u64,
    /// How gate 2 reaches STS; only set from an approved file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sts: Option<StsSettings>,
    /// The agent's proxy and extra TLS roots; only set from an approved file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkSettings>,
}

impl Default for EffectiveSettings {
    fn default() -> Self {
        Self {
            version: 1,
            methods: vec![crate::authorization::METHOD_PLATFORM.to_owned()],
            approval_methods: vec![],
            tool_detection: Default::default(),
            grant_retention_secs: DEFAULT_GRANT_RETENTION_SECS,
            sts: None,
            network: None,
        }
    }
}

impl EffectiveSettings {
    /// An approved file as it is. Otherwise the defaults, plus what can only tighten: label additions and a
    /// shorter grant retention. `methods`, `approval_methods`, `sts` and `network` are never taken from a file that
    /// is not approved.
    pub fn effective(state: PolicyState, file: Option<&AuthorizationSettings>) -> Self {
        let mut settings = Self::default();
        let Some(file) = file else {
            return settings;
        };
        match state {
            PolicyState::Absent => {}
            PolicyState::Approved => {
                if let Some(methods) = &file.methods {
                    settings.methods = methods.clone();
                }
                settings.approval_methods = file
                    .approval_methods
                    .clone()
                    .unwrap_or_else(default_approval_methods);
                if let Some(tool_detection) = &file.tool_detection {
                    settings.tool_detection = tool_detection.clone();
                }
                if let Some(secs) = file.grant_retention_secs {
                    settings.grant_retention_secs = secs;
                }
                settings.sts = file.sts.clone();
                settings.network = file.network.clone();
            }
            PolicyState::Unapproved | PolicyState::Tampered => {
                if let Some(tool_detection) = &file.tool_detection {
                    settings.tool_detection = tool_detection.clone();
                }
                if let Some(secs) = file.grant_retention_secs {
                    settings.grant_retention_secs = settings.grant_retention_secs.min(secs);
                }
            }
        }
        settings
    }

    /// The approval anchor an approval of a file with these settings records.
    pub fn anchor(file: Option<&AuthorizationSettings>) -> crate::proto::platform::ApprovalAnchor {
        crate::proto::platform::ApprovalAnchor {
            methods: file
                .and_then(|f| f.approval_methods.clone())
                .unwrap_or_else(default_approval_methods),
            ssh_agent_keys: vec![],
            windows_hello_keys: vec![],
        }
    }

    pub fn labels(&self) -> Vec<crate::tool_detection::ToolLabel> {
        crate::tool_detection::ToolLabel::effective(&self.tool_detection)
    }

    pub fn grant_retention(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.grant_retention_secs)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A self-signed certificate for "example.com".
    const CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBgzCCASmgAwIBAgIUEDgCz6ZhH3oNclSxpavYJ+7Ot+cwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wIBcNMjYxMDMxMDA0NjM1WhgPMjEyNjEw
MDcwMDQ2MzVaMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEKtIB7uCunWTPV0ygrW7QGORJVm7va52RqqC22jtu05GC2bIP
shjt1p+vMEmXbodiXaP0GOc3wLueekf6RQlAG6NTMFEwHQYDVR0OBBYEFB0t+Xi9
ZYQxxEHwv8r2aR4DZrXlMB8GA1UdIwQYMBaAFB0t+Xi9ZYQxxEHwv8r2aR4DZrXl
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgDkKdwrVsjQ7oXxRX
7SdlxC6KrKdcXWRfueK/7wFLo8sCIQDC7L0+2uBLGfjI8ojTSlcg24kSsNzjKSxG
XLz4KNOFkg==
-----END CERTIFICATE-----";

    fn full() -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "methods": ["platform"],
            "tool_detection": {
                "ai-agent": {"process_names": ["my-agent"], "env_names": ["MY_AGENT_ACTIVE"]},
                "ci": {"env_names": ["CI", "GITHUB_ACTIONS"]},
                "terraform": {"process_names": ["terraform", "tofu"]}
            },
            "grant_retention_secs": 86400,
            "sts": {
                "region": "us-east-1",
                "endpoint": "https://vpce-0123-abcd.sts.us-east-1.vpce.amazonaws.com",
                "servers": {"cn": {"region": "cn-north-1"}}
            },
            "network": {
                "proxy": "http://proxy.corp.example:3128",
                "extra_roots": [CERT]
            }
        })
    }

    fn parse(value: serde_json::Value) -> Result<AuthorizationSettings, String> {
        AuthorizationSettings::parse(&value.to_string())
    }

    #[test]
    fn test_parse_full() {
        let s = parse(full()).unwrap();
        assert_eq!(s.tool_detection.unwrap().len(), 3);
        assert_eq!(s.network.unwrap().extra_roots.len(), 1);
    }

    #[test]
    fn test_parse_minimal() {
        assert_eq!(
            parse(serde_json::json!({"version": 1})).unwrap(),
            AuthorizationSettings {
                version: 1,
                methods: None,
                approval_methods: None,
                tool_detection: None,
                grant_retention_secs: None,
                sts: None,
                network: None,
            }
        );
    }

    #[test]
    fn test_parse_rejects() {
        let rejects = |patch: &dyn Fn(&mut serde_json::Value)| {
            let mut v = full();
            patch(&mut v);
            parse(v).unwrap_err()
        };
        assert!(rejects(&|v| v["grant_retention"] = 1.into()).contains("unknown field"));
        assert!(
            rejects(&|v| v["tool_detection"]["ci"]["names"] = serde_json::json!([]))
                .contains("unknown field")
        );
        assert!(
            rejects(&|v| v["sts"]["servers"]["cn"]["endpoint"] = "x".into())
                .contains("unknown field")
        );
        assert!(rejects(&|v| v["version"] = 2.into()).contains("version"));
        assert!(
            rejects(&|v| v
                .as_object_mut()
                .unwrap()
                .remove("version")
                .map(drop)
                .unwrap())
            .contains("version")
        );
        assert!(
            rejects(&|v| v["methods"] = serde_json::json!(["fido"])).contains("unknown method")
        );
        assert!(
            rejects(&|v| v["approval_methods"] = serde_json::json!(["fido"]))
                .contains("approval_methods: unknown method")
        );
        assert!(
            rejects(&|v| v["tool_detection"]["CI"] = serde_json::json!({}))
                .contains("invalid label")
        );
        assert!(
            rejects(&|v| v["sts"]["endpoint"] = "http://sts.example".into()).contains("not https")
        );
        assert!(
            rejects(&|v| v["network"]["proxy"] = "socks5://p:1080".into())
                .contains("not http or https")
        );
        assert!(
            rejects(&|v| v["network"]["extra_roots"] = serde_json::json!(["junk"]))
                .contains("extra_roots[0]")
        );
        assert!(
            rejects(
                &|v| v["network"]["extra_roots"] = serde_json::json!([format!("{CERT}\n{CERT}")])
            )
            .contains("extra_roots[0]")
        );
        assert!(AuthorizationSettings::parse("// comment\n{\"version\": 1}").is_err());
    }

    #[test]
    fn test_effective_absent() {
        assert_eq!(
            EffectiveSettings::effective(PolicyState::Absent, None),
            EffectiveSettings::default()
        );
    }

    #[test]
    fn test_effective_unapproved_tightens_only() {
        let file = parse(full()).unwrap();
        let s = EffectiveSettings::effective(PolicyState::Unapproved, Some(&file));
        assert_eq!(s.methods, vec!["platform"]);
        // Capped at the default.
        assert_eq!(s.grant_retention_secs, DEFAULT_GRANT_RETENTION_SECS);
        assert_eq!(s.tool_detection.len(), 3);
        let json: serde_json::Value = serde_json::from_str(&s.to_json()).unwrap();
        assert!(json.get("sts").is_none());
        assert!(json.get("network").is_none());

        let mut v = full();
        v["grant_retention_secs"] = 600.into();
        v["methods"] = serde_json::json!([]);
        let file = parse(v).unwrap();
        let s = EffectiveSettings::effective(PolicyState::Unapproved, Some(&file));
        assert_eq!(s.grant_retention_secs, 600);
        assert_eq!(s.methods, vec!["platform"]);
    }

    #[test]
    fn test_effective_approved() {
        let mut v = full();
        v["grant_retention_secs"] = 86400.into();
        v["approval_methods"] = serde_json::json!(["platform"]);
        let file = parse(v).unwrap();
        let s = EffectiveSettings::effective(PolicyState::Approved, Some(&file));
        assert_eq!(s.grant_retention_secs, 86400);
        assert_eq!(s.approval_methods, vec!["platform"]);
        assert_eq!(s.sts.as_ref().unwrap().region.as_deref(), Some("us-east-1"));
        let json: serde_json::Value = serde_json::from_str(&s.to_json()).unwrap();
        assert_eq!(json["sts"]["servers"]["cn"]["region"], "cn-north-1");
        assert_eq!(
            s.network.as_ref().unwrap().proxy.as_ref().unwrap().as_str(),
            "http://proxy.corp.example:3128/"
        );

        // Lockdown takes only what tightens, as unapproved files do.
        let s = EffectiveSettings::effective(PolicyState::Tampered, Some(&file));
        assert_eq!(s.grant_retention_secs, DEFAULT_GRANT_RETENTION_SECS);
        assert!(s.sts.is_none());
        assert!(s.network.is_none());
        assert!(s.approval_methods.is_empty());
        assert_eq!(s.tool_detection.len(), 3);
    }

    #[test]
    fn test_anchor() {
        assert_eq!(EffectiveSettings::anchor(None).methods, vec!["platform"]);
        let file =
            parse(serde_json::json!({"version": 1, "approval_methods": ["platform"]})).unwrap();
        assert_eq!(
            EffectiveSettings::anchor(Some(&file)).methods,
            vec!["platform"]
        );
    }

    #[test]
    fn test_state_order() {
        use PolicyState::*;
        assert_eq!(Approved.max(Unapproved), Unapproved);
        assert_eq!(Unapproved.max(Approved), Unapproved);
        assert_eq!(Unapproved.max(Tampered), Tampered);
        assert_eq!(Tampered.max(Approved), Tampered);
        assert_eq!(Absent.max(Unapproved), Unapproved);
    }

    #[test]
    fn test_effective_labels() {
        let file = parse(full()).unwrap();
        let labels = EffectiveSettings::effective(PolicyState::Unapproved, Some(&file)).labels();
        let ai = labels.iter().find(|l| l.name == "ai-agent").unwrap();
        assert!(ai.process_names.contains(&"claude".to_owned()));
        assert!(ai.process_names.contains(&"my-agent".to_owned()));
        assert!(ai.env_names.contains(&"MY_AGENT_ACTIVE".to_owned()));
        let ci = labels.iter().find(|l| l.name == "ci").unwrap();
        assert_eq!(ci.env_names, vec!["CI", "GITHUB_ACTIONS"]);
        assert!(ci.process_names.is_empty());
    }
}
