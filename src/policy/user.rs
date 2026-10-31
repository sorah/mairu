//! The user's `policy.cedar`: parsing, the `forbid` policies an unapproved file contributes, and the full check of
//! `mairu policy check`.

pub const FILE_NAME: &str = "policy.cedar";

/// A policy of `policy.cedar`, carrying its id as its Cedar policy id.
#[derive(Debug, Clone)]
pub struct UserPolicy {
    /// The `@id` annotation, or `policy.cedar#<n>`.
    pub id: String,
    /// `policy.cedar#<n>`, counting from 1 in file order.
    pub position: String,
    pub annotated: bool,
    pub policy: cedar_policy::Policy,
    /// The source text, with an `@id` added when it has none.
    pub text: String,
}

impl UserPolicy {
    pub fn effect(&self) -> cedar_policy::Effect {
        self.policy.effect()
    }

    /// `no-ai-prod (policy.cedar#3)`, or `policy.cedar#3` without an `@id`.
    pub fn label(&self) -> String {
        if self.annotated {
            format!("{} ({})", self.id, self.position)
        } else {
            self.position.clone()
        }
    }

    /// `principal, action == Mairu::Action::"AssumeRole", resource in Mairu::Server::"contoso"`.
    pub fn scope(&self) -> String {
        let principal = match self.policy.principal_constraint() {
            cedar_policy::PrincipalConstraint::Any => "principal".to_owned(),
            cedar_policy::PrincipalConstraint::Eq(uid) => format!("principal == {uid}"),
            cedar_policy::PrincipalConstraint::In(uid) => format!("principal in {uid}"),
            cedar_policy::PrincipalConstraint::Is(t) => format!("principal is {t}"),
            cedar_policy::PrincipalConstraint::IsIn(t, uid) => {
                format!("principal is {t} in {uid}")
            }
        };
        let action = match self.policy.action_constraint() {
            cedar_policy::ActionConstraint::Any => "action".to_owned(),
            cedar_policy::ActionConstraint::Eq(uid) => format!("action == {uid}"),
            cedar_policy::ActionConstraint::In(uids) => format!(
                "action in [{}]",
                uids.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        let resource = match self.policy.resource_constraint() {
            cedar_policy::ResourceConstraint::Any => "resource".to_owned(),
            cedar_policy::ResourceConstraint::Eq(uid) => format!("resource == {uid}"),
            cedar_policy::ResourceConstraint::In(uid) => format!("resource in {uid}"),
            cedar_policy::ResourceConstraint::Is(t) => format!("resource is {t}"),
            cedar_policy::ResourceConstraint::IsIn(t, uid) => format!("resource is {t} in {uid}"),
        };
        format!("{principal}, {action}, {resource}")
    }

    /// Strict validation of this policy alone.
    pub fn validate(&self, schema: &cedar_policy::Schema) -> Result<(), String> {
        let mut set = cedar_policy::PolicySet::new();
        set.add(self.policy.clone()).map_err(|e| e.to_string())?;
        super::validate(schema, &set)
    }

    /// Whether the policy can be satisfied with `context.presence.verified == false`. Conservative: only a `when`
    /// that requires `context.presence.verified` as a conjunct, or an `unless` that names its negation as a
    /// disjunct, counts as requiring a human check.
    pub fn applies_without_check(&self) -> bool {
        let Ok(est) = self.policy.to_json() else {
            return true;
        };
        let conditions = est["conditions"].as_array().cloned().unwrap_or_default();
        !conditions.iter().any(|c| match c["kind"].as_str() {
            Some("when") => requires_verified(&c["body"]),
            Some("unless") => excludes_unverified(&c["body"]),
            _ => false,
        })
    }

    /// Whether the policy reads `context.tools` or `context.tool_matches`.
    pub fn uses_tools(&self) -> bool {
        self.policy
            .to_json()
            .map(|est| mentions_tools(&est))
            .unwrap_or(true)
    }
}

fn is_context_attr(expr: &serde_json::Value, attrs: &[&str]) -> bool {
    expr["left"] == serde_json::json!({"Var": "context"})
        && expr["attr"].as_str().is_some_and(|a| attrs.contains(&a))
}

fn is_verified(expr: &serde_json::Value) -> bool {
    let access = &expr["."];
    access["attr"] == "verified" && is_context_attr(&access["left"]["."], &["presence"])
}

fn is_bool(expr: &serde_json::Value, value: bool) -> bool {
    expr["Value"] == serde_json::Value::Bool(value)
}

fn is_verified_eq(expr: &serde_json::Value, value: bool) -> bool {
    let eq = &expr["=="];
    (is_verified(&eq["left"]) && is_bool(&eq["right"], value))
        || (is_bool(&eq["left"], value) && is_verified(&eq["right"]))
}

/// `context.presence.verified` must hold for `expr` to be true.
fn requires_verified(expr: &serde_json::Value) -> bool {
    if is_verified(expr) || is_verified_eq(expr, true) {
        return true;
    }
    let and = &expr["&&"];
    !and.is_null() && (requires_verified(&and["left"]) || requires_verified(&and["right"]))
}

/// `expr` is true whenever `context.presence.verified` is false.
fn excludes_unverified(expr: &serde_json::Value) -> bool {
    if is_verified(&expr["!"]["arg"]) || is_verified_eq(expr, false) {
        return true;
    }
    let or = &expr["||"];
    !or.is_null() && (excludes_unverified(&or["left"]) || excludes_unverified(&or["right"]))
}

fn mentions_tools(value: &serde_json::Value) -> bool {
    const TOOLS: &[&str] = &["tools", "tool_matches"];
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(k, v)| {
            ((k == "." || k == "has") && is_context_attr(v, TOOLS)) || mentions_tools(v)
        }),
        serde_json::Value::Array(items) => items.iter().any(mentions_tools),
        _ => false,
    }
}

/// The static policies of a `policy.cedar`, in file order.
#[derive(Debug, Clone)]
pub struct PolicyFile {
    pub policies: Vec<UserPolicy>,
}

impl PolicyFile {
    /// Fails on a parse error or a template; either makes the whole file unusable.
    pub fn parse(source: &str) -> Result<Self, String> {
        let parsed: cedar_policy::PolicySet = source
            .parse()
            .map_err(|e: cedar_policy::ParseErrors| format!("parse error: {e}"))?;
        // Parsing names policies and templates `policy<N>` in file order.
        let index = |id: &cedar_policy::PolicyId| {
            id.to_string()
                .strip_prefix("policy")
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(usize::MAX)
        };
        if let Some(t) = parsed.templates().min_by_key(|t| index(t.id())) {
            return Err(format!(
                "templates are not allowed ({FILE_NAME}#{})",
                index(t.id()).saturating_add(1)
            ));
        }
        let mut parsed: Vec<&cedar_policy::Policy> = parsed.policies().collect();
        parsed.sort_by_key(|p| index(p.id()));
        let policies = parsed
            .into_iter()
            .enumerate()
            .map(|(i, p)| {
                let position = format!("{FILE_NAME}#{}", i + 1);
                let (id, annotated, text) = match p.annotation("id") {
                    Some(id) => (id.to_owned(), true, p.to_string()),
                    None => (position.clone(), false, format!("@id(\"{position}\")\n{p}")),
                };
                UserPolicy {
                    policy: p.new_id(cedar_policy::PolicyId::new(&id)),
                    id,
                    position,
                    annotated,
                    text,
                }
            })
            .collect();
        Ok(Self { policies })
    }

    /// Problems with ids: duplicates and the reserved `builtin-` prefix. Keyed by index into `policies`.
    fn id_problems(&self) -> std::collections::BTreeMap<usize, String> {
        let mut counts: std::collections::HashMap<&str, usize> = Default::default();
        for p in &self.policies {
            *counts.entry(p.id.as_str()).or_default() += 1;
        }
        let mut problems = std::collections::BTreeMap::new();
        for (i, p) in self.policies.iter().enumerate() {
            if p.id.starts_with(super::BUILTIN_PREFIX) {
                problems.insert(
                    i,
                    format!("ids starting with {:?} are reserved", super::BUILTIN_PREFIX),
                );
            } else if counts[p.id.as_str()] > 1 {
                problems.insert(i, format!("duplicate id {:?}", p.id));
            }
        }
        problems
    }

    /// What an unapproved file contributes: its `forbid` policies that validate, and a note for everything else.
    pub fn unapproved_forbids(
        source: &str,
        schema: &cedar_policy::Schema,
    ) -> (Vec<UserPolicy>, Vec<String>) {
        let file = match Self::parse(source) {
            Ok(f) => f,
            Err(e) => return (vec![], vec![format!("ignored {FILE_NAME}: {e}")]),
        };
        let problems = file.id_problems();
        let mut notes = vec![];
        let mut forbids = vec![];
        let mut permits = vec![];
        for (i, p) in file.policies.into_iter().enumerate() {
            if p.effect() == cedar_policy::Effect::Permit {
                permits.push(p.label());
                continue;
            }
            if let Err(e) = p.validate(schema) {
                notes.push(format!(
                    "dropped forbid {}: validation error: {e}",
                    p.label()
                ));
            } else if let Some(problem) = problems.get(&i) {
                notes.push(format!("dropped forbid {}: {problem}", p.label()));
            } else {
                forbids.push(p);
            }
        }
        if !permits.is_empty() {
            notes.push(format!(
                "ignored permit policies while {FILE_NAME} is unapproved: {}",
                permits.join(", ")
            ));
        }
        (forbids, notes)
    }

    /// The full validation of `mairu policy check`, `permit` policies included. Errors name the policy.
    pub fn errors(&self, schema: &cedar_policy::Schema) -> Vec<String> {
        let problems = self.id_problems();
        let mut errors = vec![];
        for (i, p) in self.policies.iter().enumerate() {
            if let Err(e) = p.validate(schema) {
                errors.push(format!("{}: validation error: {e}", p.label()));
            }
            if let Some(problem) = problems.get(&i) {
                errors.push(format!("{}: {problem}", p.label()));
            }
        }
        errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC_EXAMPLE: &str = r#"
// Read-only access needs no human check.
@id("readonly-free")
permit (
  principal,
  action == Mairu::Action::"AssumeRole",
  resource == Mairu::Role::"contoso:123456789012/ReadOnly"
);

// Everything else on contoso: once per terminal session, 15 minutes idle, 8 hours at most.
@id("contoso-session")
permit (principal, action == Mairu::Action::"AssumeRole", resource in Mairu::Server::"contoso")
when {
  !context.tools.contains("ai-agent") &&
  context.presence.verified &&
  context.presence.idle <= 900 &&
  context.presence.age <= 28800
};

// Never hand production to AI agents, on any server.
@id("no-ai-prod")
forbid (principal, action, resource in Mairu::Account::"999999999999")
when { context.tools.contains("ai-agent") };

// Production, whatever the role is called: credentials whose real account is production
// need a fresh human check (gate 2).
@id("prod-by-real-account")
forbid (principal, action == Mairu::Action::"UseCredentials", resource in Mairu::Account::"999999999999")
unless { context.presence.verified && context.presence.scope == "request" };
"#;

    const TTY_LESS: &str = r#"
// IDEs and other callers without a tty: reuse a grant for up to 1 hour idle.
@id("tty-less-callers-1h-idle")
permit (principal, action == Mairu::Action::"AssumeRole", resource)
when {
  !context.tools.contains("ai-agent") &&
  context.presence.verified &&
  context.session == "parent" &&
  context.presence.scope == "session" &&
  context.presence.idle <= 3600 &&
  context.presence.age <= 43200
};
"#;

    fn schema() -> cedar_policy::Schema {
        super::super::schema().unwrap()
    }

    #[test]
    fn test_spec_examples_validate() {
        for source in [SPEC_EXAMPLE, TTY_LESS] {
            let file = PolicyFile::parse(source).unwrap();
            assert_eq!(file.errors(&schema()), Vec::<String>::new());
        }
    }

    #[test]
    fn test_parse_order_and_ids() {
        let file = PolicyFile::parse(
            r#"
            @id("a") permit (principal, action, resource);
            forbid (principal, action, resource) when { context.hardened };
            @id("c") forbid (principal, action, resource);
            "#,
        )
        .unwrap();
        let ids: Vec<_> = file.policies.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "policy.cedar#2", "c"]);
        assert_eq!(file.policies[1].label(), "policy.cedar#2");
        assert_eq!(file.policies[2].label(), "c (policy.cedar#3)");
        assert!(
            file.policies[1]
                .text
                .starts_with("@id(\"policy.cedar#2\")\n")
        );
        assert!(file.policies[2].text.starts_with("@id(\"c\")"));
    }

    #[test]
    fn test_templates_rejected() {
        let err = PolicyFile::parse(
            r#"
            @id("a") permit (principal, action, resource);
            @id("t") permit (principal == ?principal, action, resource);
            "#,
        )
        .unwrap_err();
        assert!(err.contains("templates"), "{err}");
        assert!(err.contains("policy.cedar#2"), "{err}");
    }

    #[test]
    fn test_unapproved_forbids() {
        let (forbids, notes) = PolicyFile::unapproved_forbids(SPEC_EXAMPLE, &schema());
        let ids: Vec<_> = forbids.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["no-ai-prod", "prod-by-real-account"]);
        assert_eq!(
            notes,
            vec![
                "ignored permit policies while policy.cedar is unapproved: readonly-free (policy.cedar#1), contoso-session (policy.cedar#2)"
            ]
        );
    }

    #[test]
    fn test_unapproved_forbids_drops() {
        let (forbids, notes) = PolicyFile::unapproved_forbids(
            r#"
            @id("ok") forbid (principal, action, resource) when { context.hardened };
            @id("typo") forbid (principal, action, resource) when { context.presense.verified };
            @id("dup") forbid (principal, action, resource);
            @id("dup") forbid (principal, action, resource);
            @id("builtin-human") forbid (principal, action, resource);
            forbid (principal, action, resource) when { context.cwd == "/" };
            "#,
            &schema(),
        );
        let ids: Vec<_> = forbids.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["ok"]);
        assert_eq!(notes.len(), 5, "{notes:?}");
        assert!(notes[0].starts_with("dropped forbid typo (policy.cedar#2): validation error"));
        assert!(notes[1].starts_with("dropped forbid dup (policy.cedar#3): duplicate id"));
        assert!(notes[2].starts_with("dropped forbid dup (policy.cedar#4): duplicate id"));
        assert!(notes[3].contains("builtin-human (policy.cedar#5): ids starting with"));
        // Strict mode needs `has` before an optional attribute.
        assert!(notes[4].starts_with("dropped forbid policy.cedar#6: validation error"));
    }

    #[test]
    fn test_unapproved_forbids_parse_error() {
        let (forbids, notes) = PolicyFile::unapproved_forbids(
            r#"
            @id("ok") forbid (principal, action, resource);
            @id("broken") forbid (principal, action, resource) when { context. };
            "#,
            &schema(),
        );
        assert!(forbids.is_empty());
        assert_eq!(notes.len(), 1);
        assert!(
            notes[0].starts_with("ignored policy.cedar: parse error"),
            "{notes:?}"
        );
    }

    #[test]
    fn test_flags() {
        let file = PolicyFile::parse(&format!(
            r#"{SPEC_EXAMPLE}{TTY_LESS}
            @id("unless-form") permit (principal, action, resource)
            unless {{ !context.presence.verified || context.hardened }};
            @id("eq-form") permit (principal, action, resource)
            when {{ true == context.presence.verified }};
            @id("or-form") permit (principal, action, resource)
            when {{ context.presence.verified || context.hardened }};
            @id("has-tools") permit (principal, action, resource)
            when {{ context has tool_matches && context.presence.verified }};
            "#
        ))
        .unwrap();
        let flags: Vec<(&str, bool, bool)> = file
            .policies
            .iter()
            .map(|p| (p.id.as_str(), p.applies_without_check(), p.uses_tools()))
            .collect();
        assert_eq!(
            flags,
            vec![
                ("readonly-free", true, false),
                ("contoso-session", false, true),
                ("no-ai-prod", true, true),
                ("prod-by-real-account", true, false),
                ("tty-less-callers-1h-idle", false, true),
                ("unless-form", false, false),
                ("eq-form", false, false),
                ("or-form", true, false),
                ("has-tools", false, true),
            ]
        );
    }

    #[test]
    fn test_scope() {
        let file = PolicyFile::parse(SPEC_EXAMPLE).unwrap();
        assert_eq!(
            file.policies[0].scope(),
            r#"principal, action == Mairu::Action::"AssumeRole", resource == Mairu::Role::"contoso:123456789012/ReadOnly""#
        );
        assert_eq!(
            file.policies[2].scope(),
            r#"principal, action, resource in Mairu::Account::"999999999999""#
        );
    }
}
