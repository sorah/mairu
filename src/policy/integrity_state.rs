//! Whether the policy files and server configs are what a human approved: digests, the state the stores' answers
//! add up to, and the approval anchor in force.

use crate::proto::platform::IntegrityStatus as Status;

pub type Digest = [u8; 32];

/// The digest of both files: `SHA-256("mairu.policy.v1\0" || part(policy.cedar) || part(authorization.json))`.
pub fn policy_digest(policy: &super::files::Content, settings: &super::files::Content) -> Digest {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"mairu.policy.v1\0");
    for content in [policy, settings] {
        match content {
            super::files::Content::Absent => hasher.update([0x00]),
            super::files::Content::Text(text) => {
                hasher.update([0x01]);
                hasher.update((text.len() as u64).to_be_bytes());
                hasher.update(text.as_bytes());
            }
            // Never equal to the digest of readable content, which is all an approval can record.
            super::files::Content::Unreadable(e) => {
                hasher.update([0x02]);
                hasher.update(e.as_bytes());
            }
        }
    }
    hasher.finalize().into()
}

/// Fields that neither decide where credentials come from nor are public.
const SERVER_FIELDS_NOT_COUNTED: &[&str] = &[
    "client_secret",
    "client_expires_at",
    "default_grant_type",
    "local_port",
];

/// The config fields a server digest counts, as canonical JSON: sorted keys, no whitespace.
pub fn server_counted_json(server: &crate::config::Server) -> String {
    let mut value = serde_json::to_value(server).unwrap_or_default();
    value["id"] = serde_json::Value::from(server.id());
    strip_uncounted(&mut value);
    let mut out = String::new();
    canonical(&value, &mut out);
    out
}

/// `SHA-256("mairu.server.v1\0" || canonical JSON)`.
pub fn server_digest(server: &crate::config::Server) -> Digest {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"mairu.server.v1\0");
    hasher.update(server_counted_json(server).as_bytes());
    hasher.finalize().into()
}

fn strip_uncounted(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.retain(|k, _| !SERVER_FIELDS_NOT_COUNTED.contains(&k.as_str()));
            map.values_mut().for_each(strip_uncounted);
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(strip_uncounted),
        _ => {}
    }
}

fn canonical(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: std::collections::BTreeMap<_, _> = map.iter().collect();
            out.push('{');
            for (i, (k, v)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::Value::from(k.as_str()).to_string());
                out.push(':');
                canonical(v, out);
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(v, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// What the human confirms: SHA-256 over the policy digest and the server digests in server id order.
pub fn approval_digest(
    digest: &Digest,
    servers: &std::collections::BTreeMap<String, Digest>,
) -> Digest {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"mairu.approval.v1\0");
    hasher.update(digest);
    for d in servers.values() {
        hasher.update(d);
    }
    hasher.finalize().into()
}

/// Before any approval, or after an administrator reset the record.
pub fn default_anchor() -> crate::proto::platform::ApprovalAnchor {
    crate::proto::platform::ApprovalAnchor {
        methods: vec![crate::authorization::METHOD_PLATFORM.to_owned()],
        ssh_agent_keys: vec![],
        windows_hello_keys: vec![],
    }
}

/// `"policy"`, or `"policy-dev"` under the dev profile: records are not shared between profiles.
pub fn record_name() -> &'static str {
    match crate::config::Profile::current() {
        crate::config::Profile::Default => "policy",
        crate::config::Profile::Dev => "policy-dev",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// The record holds the server with this digest.
    Approved,
    /// The record does not hold the server.
    Unapproved,
    /// The record holds the server with another digest; its roles are refused.
    Changed,
}

impl ServerState {
    pub fn of(
        record: Option<&crate::proto::platform::IntegrityRecord>,
        id: &str,
        digest: &Digest,
    ) -> Self {
        match record.and_then(|r| r.server_digests.get(id)) {
            None => ServerState::Unapproved,
            Some(d) if d.as_slice() == digest => ServerState::Approved,
            Some(_) => ServerState::Changed,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ServerState::Approved => "approved",
            ServerState::Unapproved => "unapproved",
            ServerState::Changed => "changed",
        }
    }
}

/// What the stores' answers add up to.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub state: super::settings::PolicyState,
    /// The store results, with stale strong stores counted as holding the strong record.
    pub results: Vec<crate::proto::platform::IntegrityStoreResult>,
    /// Among the strong stores, the record with the highest generation.
    pub strong: Option<crate::proto::platform::IntegrityRecord>,
    /// The record whose anchor and server digests are in force.
    pub record: Option<crate::proto::platform::IntegrityRecord>,
    pub anchor: crate::proto::platform::ApprovalAnchor,
    /// Strong stores to overwrite with the strong record, which they missed while unavailable.
    pub rewrite: Vec<crate::proto::platform::IntegrityStoreKind>,
    /// Stores to write the approved record to, which do not hold one.
    pub backfill: Vec<crate::proto::platform::IntegrityStoreKind>,
}

impl Decision {
    /// `files_absent`: neither file exists. `hardened`: the agent is hardened.
    pub fn decide(
        results: Vec<crate::proto::platform::IntegrityStoreResult>,
        digest: &Digest,
        files_absent: bool,
        hardened: bool,
    ) -> Self {
        use super::settings::PolicyState;
        let strong_kind = |r: &crate::proto::platform::IntegrityStoreResult| {
            crate::platform::integrity::is_strong(r.store())
        };
        let strong = results
            .iter()
            .filter(|r| strong_kind(r))
            .filter_map(|r| r.stored.as_ref())
            .max_by_key(|r| r.generation)
            .cloned();

        let mut results = results;
        let mut rewrite = vec![];
        if let Some(strong) = &strong {
            for r in results.iter_mut().filter(|r| strong_kind(r)) {
                if let Some(held) = &r.stored
                    && held.generation < strong.generation
                {
                    rewrite.push(r.store());
                    r.status = if strong.digest == digest {
                        Status::Matched.into()
                    } else {
                        Status::Mismatched.into()
                    };
                    r.stored = Some(strong.clone());
                }
            }
        }

        let any_record = results.iter().any(|r| r.stored.is_some())
            || results.iter().any(|r| r.status() == Status::Mismatched);
        let strong_available = results
            .iter()
            .any(|r| strong_kind(r) && r.status() != Status::Unavailable);
        let weak_matched = results
            .iter()
            .find(|r| !strong_kind(r) && r.status() == Status::Matched)
            .and_then(|r| r.stored.clone());
        let state = if files_absent && !any_record {
            PolicyState::Absent
        } else if results.iter().any(|r| r.status() == Status::Mismatched) {
            PolicyState::Tampered
        } else if results
            .iter()
            .any(|r| strong_kind(r) && r.status() == Status::Matched)
        {
            PolicyState::Approved
        } else if strong_available {
            PolicyState::Unapproved
        } else if !hardened && weak_matched.is_some() {
            PolicyState::Approved
        } else {
            PolicyState::Unapproved
        };

        let weak_record = || {
            results
                .iter()
                .filter(|r| !strong_kind(r))
                .filter_map(|r| r.stored.as_ref())
                .max_by_key(|r| r.generation)
                .cloned()
        };
        let record = match (&strong, hardened) {
            (Some(s), _) => Some(s.clone()),
            (None, false) => weak_record(),
            (None, true) => None,
        };
        let anchor = record
            .as_ref()
            .and_then(|r| r.approval.clone())
            .unwrap_or_else(default_anchor);
        let backfill = if state == PolicyState::Approved {
            results
                .iter()
                .filter(|r| r.status() == Status::NotRecorded)
                .map(|r| r.store())
                .collect()
        } else {
            vec![]
        };
        Self {
            state,
            results,
            strong,
            record,
            anchor,
            rewrite,
            backfill,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::settings::PolicyState;
    use crate::proto::platform::IntegrityStoreKind as K;

    const DIGEST: Digest = [7; 32];

    fn record(
        digest: u8,
        generation: u64,
        methods: &[&str],
    ) -> crate::proto::platform::IntegrityRecord {
        crate::proto::platform::IntegrityRecord {
            digest: vec![digest; 32],
            approval: Some(crate::proto::platform::ApprovalAnchor {
                methods: methods.iter().map(|m| m.to_string()).collect(),
                ..Default::default()
            }),
            generation,
            server_digests: [("contoso".to_owned(), vec![1; 32])].into(),
        }
    }

    fn res(
        store: K,
        status: Status,
        stored: Option<crate::proto::platform::IntegrityRecord>,
    ) -> crate::proto::platform::IntegrityStoreResult {
        crate::proto::platform::IntegrityStoreResult {
            store: store.into(),
            status: status.into(),
            detail: String::new(),
            stored,
        }
    }

    fn matched(store: K, generation: u64) -> crate::proto::platform::IntegrityStoreResult {
        res(
            store,
            Status::Matched,
            Some(record(7, generation, &["platform"])),
        )
    }

    fn mismatched(store: K, generation: u64) -> crate::proto::platform::IntegrityStoreResult {
        res(
            store,
            Status::Mismatched,
            Some(record(9, generation, &["platform"])),
        )
    }

    fn not_recorded(store: K) -> crate::proto::platform::IntegrityStoreResult {
        res(store, Status::NotRecorded, None)
    }

    fn unavailable(store: K) -> crate::proto::platform::IntegrityStoreResult {
        res(store, Status::Unavailable, None)
    }

    fn state(
        results: Vec<crate::proto::platform::IntegrityStoreResult>,
        absent: bool,
        hardened: bool,
    ) -> PolicyState {
        Decision::decide(results, &DIGEST, absent, hardened).state
    }

    #[test]
    fn test_state_table() {
        let pd = K::ProtectedDirectory;
        let ss = K::SecretService;
        // Both files absent, no record.
        assert_eq!(
            state(vec![not_recorded(pd), not_recorded(ss)], true, true),
            PolicyState::Absent
        );
        assert_eq!(state(vec![], true, true), PolicyState::Absent);
        // A record while both files are absent.
        assert_eq!(
            state(vec![mismatched(pd, 1), not_recorded(ss)], true, true),
            PolicyState::Tampered
        );
        // Any store mismatched.
        assert_eq!(
            state(vec![matched(pd, 1), mismatched(ss, 1)], false, true),
            PolicyState::Tampered
        );
        assert_eq!(
            state(vec![not_recorded(pd), mismatched(ss, 1)], false, true),
            PolicyState::Tampered
        );
        // A strong store matched.
        assert_eq!(
            state(vec![matched(pd, 1), not_recorded(ss)], false, true),
            PolicyState::Approved
        );
        assert_eq!(
            state(vec![matched(pd, 1), unavailable(ss)], false, true),
            PolicyState::Approved
        );
        // Strong available, none matched, whatever the weak store says.
        assert_eq!(
            state(vec![not_recorded(pd), matched(ss, 1)], false, true),
            PolicyState::Unapproved
        );
        assert_eq!(
            state(vec![not_recorded(pd), matched(ss, 1)], false, false),
            PolicyState::Unapproved
        );
        // No strong store: a weak match approves only an unhardened agent.
        assert_eq!(
            state(vec![unavailable(pd), matched(ss, 1)], false, false),
            PolicyState::Approved
        );
        assert_eq!(
            state(vec![unavailable(pd), matched(ss, 1)], false, true),
            PolicyState::Unapproved
        );
        // Otherwise.
        assert_eq!(
            state(vec![unavailable(pd), not_recorded(ss)], false, false),
            PolicyState::Unapproved
        );
        assert_eq!(state(vec![], false, true), PolicyState::Unapproved);
    }

    #[test]
    fn test_backfill() {
        let d = Decision::decide(
            vec![
                matched(K::ProtectedDirectory, 3),
                not_recorded(K::SecretService),
            ],
            &DIGEST,
            false,
            true,
        );
        assert_eq!(d.state, PolicyState::Approved);
        assert_eq!(d.backfill, vec![K::SecretService]);
        assert!(d.rewrite.is_empty());
        let d = Decision::decide(
            vec![
                not_recorded(K::ProtectedDirectory),
                mismatched(K::SecretService, 3),
            ],
            &DIGEST,
            false,
            true,
        );
        assert!(d.backfill.is_empty());
    }

    #[test]
    fn test_generation() {
        // A strong store with a lower generation is overwritten before the state is decided.
        let d = Decision::decide(
            vec![
                mismatched(K::ProtectedDirectory, 2),
                matched(K::DataProtectionKeychain, 5),
                not_recorded(K::SecretService),
            ],
            &DIGEST,
            false,
            true,
        );
        assert_eq!(d.rewrite, vec![K::ProtectedDirectory]);
        assert_eq!(d.state, PolicyState::Approved);
        assert_eq!(d.strong.as_ref().unwrap().generation, 5);
        assert_eq!(d.results[0].status(), Status::Matched);

        // A weak store with a higher generation is ignored.
        let mut weak = record(7, 99, &["ssh-agent"]);
        weak.digest = vec![7; 32];
        let d = Decision::decide(
            vec![
                matched(K::ProtectedDirectory, 2),
                res(K::SecretService, Status::Matched, Some(weak)),
            ],
            &DIGEST,
            false,
            true,
        );
        assert_eq!(d.strong.as_ref().unwrap().generation, 2);
        assert_eq!(d.anchor.methods, vec!["platform"]);
        assert!(d.rewrite.is_empty());
    }

    #[test]
    fn test_anchor_in_force() {
        // The strong record's.
        let d = Decision::decide(
            vec![
                res(
                    K::ProtectedDirectory,
                    Status::Mismatched,
                    Some(record(9, 1, &["ssh-agent"])),
                ),
                res(
                    K::SecretService,
                    Status::Matched,
                    Some(record(7, 1, &["platform"])),
                ),
            ],
            &DIGEST,
            false,
            true,
        );
        assert_eq!(d.anchor.methods, vec!["ssh-agent"]);
        // On a hardened agent a weak record never anchors.
        let weak_only = vec![
            not_recorded(K::ProtectedDirectory),
            res(
                K::SecretService,
                Status::Mismatched,
                Some(record(9, 1, &["ssh-agent"])),
            ),
        ];
        let d = Decision::decide(weak_only.clone(), &DIGEST, false, true);
        assert_eq!(d.anchor, default_anchor());
        assert_eq!(d.record, None);
        // On an unhardened agent it does.
        let d = Decision::decide(weak_only, &DIGEST, false, false);
        assert_eq!(d.anchor.methods, vec!["ssh-agent"]);
        // No record at all.
        let d = Decision::decide(vec![], &DIGEST, false, false);
        assert_eq!(d.anchor, default_anchor());
    }

    #[test]
    fn test_server_states() {
        let r = record(7, 1, &[]);
        assert_eq!(
            ServerState::of(Some(&r), "contoso", &[1; 32]),
            ServerState::Approved
        );
        assert_eq!(
            ServerState::of(Some(&r), "contoso", &[2; 32]),
            ServerState::Changed
        );
        assert_eq!(
            ServerState::of(Some(&r), "new", &[1; 32]),
            ServerState::Unapproved
        );
        assert_eq!(
            ServerState::of(None, "contoso", &[1; 32]),
            ServerState::Unapproved
        );
    }

    fn server(json: serde_json::Value) -> crate::config::Server {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn test_server_digest() {
        let base = serde_json::json!({
            "id": "contoso",
            "url": "https://contoso.example/",
            "oauth": {
                "client_id": "abc",
                "client_secret": "s3cret",
                "scope": ["profile"],
                "default_grant_type": "code",
                "code_grant": {"authorization_endpoint": "https://contoso.example/authorize", "local_port": 1234},
            },
        });
        let digest = server_digest(&server(base.clone()));
        let json = server_counted_json(&server(base.clone()));
        assert!(!json.contains("s3cret"));
        assert!(!json.contains("local_port"));
        assert!(!json.contains(' '));
        assert!(
            json.starts_with(r#"{"aws_sso":null,"id":"contoso","oauth":{"#),
            "{json}"
        );

        // Secrets and operational fields do not count.
        let mut v = base.clone();
        v["oauth"]["client_secret"] = "other".into();
        v["oauth"]["default_grant_type"] = "device_code".into();
        v["oauth"]["code_grant"]["local_port"] = 9999.into();
        assert_eq!(server_digest(&server(v)), digest);

        // Where credentials come from does.
        let mut v = base.clone();
        v["url"] = "https://evil.example/".into();
        assert_ne!(server_digest(&server(v)), digest);
        let mut v = base.clone();
        v["oauth"]["code_grant"]["authorization_endpoint"] = "https://evil.example/".into();
        assert_ne!(server_digest(&server(v)), digest);
        let mut v = base;
        v["id"] = "other".into();
        assert_ne!(server_digest(&server(v)), digest);

        let sso = |region: &str, port: u16| {
            server(serde_json::json!({
                "id": "sso", "url": "https://d-123.awsapps.com/start",
                "aws_sso": {"region": region, "local_port": port},
            }))
        };
        assert_eq!(
            server_digest(&sso("us-east-1", 1)),
            server_digest(&sso("us-east-1", 2))
        );
        assert_ne!(
            server_digest(&sso("us-east-1", 1)),
            server_digest(&sso("eu-west-1", 1))
        );
    }

    #[test]
    fn test_policy_digest() {
        use crate::policy::files::Content;
        let text = |s: &str| Content::Text(s.to_owned());
        let absent = policy_digest(&Content::Absent, &Content::Absent);
        assert_ne!(absent, policy_digest(&text(""), &Content::Absent));
        assert_ne!(absent, policy_digest(&Content::Absent, &text("")));
        assert_ne!(
            policy_digest(&text("a"), &text("b")),
            policy_digest(&text("b"), &text("a"))
        );
        assert_ne!(
            policy_digest(&text("ab"), &Content::Absent),
            policy_digest(&text("a"), &text("b"))
        );
        assert_eq!(
            policy_digest(&text("x"), &text("y")),
            policy_digest(&text("x"), &text("y"))
        );
    }

    #[test]
    fn test_approval_digest() {
        let one: std::collections::BTreeMap<String, Digest> = [("a".to_owned(), [1; 32])].into();
        let two: std::collections::BTreeMap<String, Digest> = [("a".to_owned(), [2; 32])].into();
        assert_ne!(
            approval_digest(&DIGEST, &one),
            approval_digest(&DIGEST, &two)
        );
        assert_ne!(
            approval_digest(&DIGEST, &one),
            approval_digest(&[8; 32], &one)
        );
    }
}
