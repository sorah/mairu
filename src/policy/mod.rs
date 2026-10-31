//! The Cedar engine: the embedded schema and built-in policies, request building, and evaluation that fails
//! closed.

const SCHEMA: &str = include_str!("mairu.cedarschema");
const BUILTIN_HUMAN: &str = include_str!("builtin/human.cedar");
const BUILTIN_UNHARDENED: &str = include_str!("builtin/unhardened.cedar");

/// Policy ids starting with this are reserved for the built-in policies.
pub const BUILTIN_PREFIX: &str = "builtin-";

const ACTION_ASSUME_ROLE: &str = r#"Mairu::Action::"AssumeRole""#;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid schema: {0}")]
    Schema(String),
    #[error("invalid policy: {0}")]
    Parse(String),
    #[error("policy validation failed: {0}")]
    Validation(String),
}

/// A validated policy set with the schema it was validated against.
pub struct Engine {
    schema: cedar_policy::Schema,
    policies: cedar_policy::PolicySet,
    action: cedar_policy::EntityUid,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("policies", &self.policy_ids())
            .finish()
    }
}

impl Engine {
    /// `builtin-human` for a hardened agent, `builtin-unhardened` otherwise.
    pub fn builtin(hardened: bool) -> Result<Self, PolicyError> {
        Self::new(if hardened {
            BUILTIN_HUMAN
        } else {
            BUILTIN_UNHARDENED
        })
    }

    /// Parses policies whose ids come from their `@id` annotations, and validates them in strict mode.
    pub fn new(source: &str) -> Result<Self, PolicyError> {
        let (schema, _warnings) = cedar_policy::Schema::from_cedarschema_str(SCHEMA)
            .map_err(|e| PolicyError::Schema(e.to_string()))?;
        let parsed: cedar_policy::PolicySet = source
            .parse()
            .map_err(|e: cedar_policy::ParseErrors| PolicyError::Parse(e.to_string()))?;
        let mut policies = cedar_policy::PolicySet::new();
        for policy in parsed.policies() {
            let id = policy.annotation("id").ok_or_else(|| {
                PolicyError::Parse(format!("a policy lacks an @id annotation: {policy}"))
            })?;
            policies
                .add(policy.new_id(cedar_policy::PolicyId::new(id)))
                .map_err(|e| PolicyError::Parse(e.to_string()))?;
        }
        let validation = cedar_policy::Validator::new(schema.clone())
            .validate(&policies, cedar_policy::ValidationMode::Strict);
        if !validation.validation_passed() {
            let errors: Vec<String> = validation
                .validation_errors()
                .map(ToString::to_string)
                .collect();
            return Err(PolicyError::Validation(errors.join("; ")));
        }
        let action = ACTION_ASSUME_ROLE
            .parse()
            .map_err(|e: cedar_policy::ParseErrors| PolicyError::Schema(e.to_string()))?;
        Ok(Self {
            schema,
            policies,
            action,
        })
    }

    pub fn policy_ids(&self) -> Vec<String> {
        self.policies
            .policies()
            .map(|p| p.id().to_string())
            .collect()
    }

    /// The entities of a request; built once and evaluated with each candidate presence.
    pub fn prepare(&self, facts: &Facts) -> Result<Prepared, String> {
        let principal = entity_uid("Mairu::User", &facts.uid.to_string())?;
        let resource = entity_uid(
            "Mairu::Role",
            &format!("{}:{}", facts.server_id, facts.role),
        )?;
        let account_id = account_id(&facts.role);

        let mut entities = vec![
            serde_json::json!({
                "uid": {"type": "Mairu::User", "id": facts.uid.to_string()},
                "attrs": {"name": facts.user_name, "uid": facts.uid},
                "parents": [],
            }),
            serde_json::json!({
                "uid": {"type": "Mairu::Server", "id": facts.server_id},
                "attrs": {"url": facts.server_url},
                "parents": [],
            }),
        ];
        let mut role_attrs = serde_json::json!({
            "name": facts.role,
            "server": {"__entity": {"type": "Mairu::Server", "id": facts.server_id}},
        });
        let mut parents = vec![serde_json::json!({"type": "Mairu::Server", "id": facts.server_id})];
        if let Some(account) = &account_id {
            entities.push(serde_json::json!({
                "uid": {"type": "Mairu::Account", "id": account},
                "attrs": {},
                "parents": [],
            }));
            parents.push(serde_json::json!({"type": "Mairu::Account", "id": account}));
            role_attrs["account_id"] = serde_json::Value::from(account.clone());
        }
        entities.push(serde_json::json!({
            "uid": {"type": "Mairu::Role", "id": format!("{}:{}", facts.server_id, facts.role)},
            "attrs": role_attrs,
            "parents": parents,
        }));
        let entities = cedar_policy::Entities::from_json_value(
            serde_json::Value::Array(entities),
            Some(&self.schema),
        )
        .map_err(|e| e.to_string())?;

        let mut context = serde_json::Map::new();
        context.insert("session".to_owned(), facts.session.into());
        context.insert("hardened".to_owned(), facts.hardened.into());
        context.insert("intent".to_owned(), facts.intent.into());
        for (key, value) in [
            ("tty", &facts.tty),
            ("exec_command", &facts.exec_command),
            ("exec_command_line", &facts.exec_command_line),
            ("cwd", &facts.cwd),
            ("chained_role_arn", &facts.chained_role_arn),
        ] {
            if let Some(v) = value {
                context.insert(key.to_owned(), v.clone().into());
            }
        }
        Ok(Prepared {
            principal,
            resource,
            entities,
            context,
        })
    }

    /// Any error, whether building the request or evaluating a policy, makes the decision `Deny`.
    pub fn evaluate(&self, prepared: &Prepared, presence: &Presence) -> Evaluation {
        let mut context = prepared.context.clone();
        context.insert("presence".to_owned(), presence.to_json());
        let request = cedar_policy::Context::from_json_value(
            serde_json::Value::Object(context),
            Some((&self.schema, &self.action)),
        )
        .map_err(|e| e.to_string())
        .and_then(|context| {
            cedar_policy::Request::new(
                prepared.principal.clone(),
                self.action.clone(),
                prepared.resource.clone(),
                context,
                Some(&self.schema),
            )
            .map_err(|e| e.to_string())
        });
        let request = match request {
            Ok(r) => r,
            Err(e) => return Evaluation::error(e),
        };
        let response = cedar_policy::Authorizer::new().is_authorized(
            &request,
            &self.policies,
            &prepared.entities,
        );
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(ToString::to_string)
            .collect();
        let allowed = response.decision() == cedar_policy::Decision::Allow && errors.is_empty();
        let forbids = if allowed {
            vec![]
        } else {
            response
                .diagnostics()
                .reason()
                .filter(|id| {
                    self.policies
                        .policy(id)
                        .is_some_and(|p| p.effect() == cedar_policy::Effect::Forbid)
                })
                .map(ToString::to_string)
                .collect()
        };
        Evaluation {
            allowed,
            forbids,
            errors,
        }
    }
}

fn entity_uid(type_name: &str, id: &str) -> Result<cedar_policy::EntityUid, String> {
    let type_name: cedar_policy::EntityTypeName = type_name
        .parse()
        .map_err(|e: cedar_policy::ParseErrors| e.to_string())?;
    Ok(cedar_policy::EntityUid::from_type_name_and_id(
        type_name,
        cedar_policy::EntityId::new(id),
    ))
}

/// The account a role names: an AWS SSO role `123456789012/Name`, or an IAM role ARN.
pub fn account_id(role: &str) -> Option<String> {
    let twelve_digits = |s: &str| s.len() == 12 && s.bytes().all(|b| b.is_ascii_digit());
    if let Some((account, _)) = role.split_once('/')
        && twelve_digits(account)
    {
        return Some(account.to_owned());
    }
    let mut parts = role.splitn(6, ':');
    let (Some("arn"), Some(partition), Some("iam"), Some(""), Some(account), Some(resource)) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return None;
    };
    (partition.starts_with("aws") && twelve_digits(account) && resource.starts_with("role/"))
        .then(|| account.to_owned())
}

/// What the agent knows about a request, apart from presence.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub uid: u32,
    pub user_name: String,
    pub server_id: String,
    pub server_url: String,
    pub role: String,
    /// `"tty"`, `"parent"` or `"none"`.
    pub session: &'static str,
    pub tty: Option<String>,
    pub hardened: bool,
    /// `"exec"`, `"credential-process"` or `"unknown"`.
    pub intent: &'static str,
    pub exec_command: Option<String>,
    pub exec_command_line: Option<String>,
    pub cwd: Option<String>,
    pub chained_role_arn: Option<String>,
}

/// A request's entities and the context apart from `presence`.
pub struct Prepared {
    principal: cedar_policy::EntityUid,
    resource: cedar_policy::EntityUid,
    entities: cedar_policy::Entities,
    context: serde_json::Map<String, serde_json::Value>,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("principal", &self.principal)
            .field("resource", &self.resource)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    None,
    Request,
    Process,
    Session,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::None => "none",
            Scope::Request => "request",
            Scope::Process => "process",
            Scope::Session => "session",
        }
    }
}

/// `context.presence`: what human check covers a request. Ages are in seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presence {
    pub verified: bool,
    pub scope: Scope,
    pub method: Option<String>,
    pub age: i64,
    pub idle: i64,
}

impl Presence {
    pub fn none() -> Self {
        Self {
            verified: false,
            scope: Scope::None,
            method: None,
            age: 0,
            idle: 0,
        }
    }

    /// A check that would be made for this very request.
    pub fn fresh(method: &str) -> Self {
        Self {
            verified: true,
            scope: Scope::Request,
            method: Some(method.to_owned()),
            age: 0,
            idle: 0,
        }
    }

    pub fn remembered(scope: Scope, method: &str, age: i64, idle: i64) -> Self {
        Self {
            verified: true,
            scope,
            method: Some(method.to_owned()),
            age,
            idle,
        }
    }

    fn to_json(&self) -> serde_json::Value {
        let mut presence = serde_json::json!({
            "verified": self.verified,
            "scope": self.scope.as_str(),
            "age": self.age,
            "idle": self.idle,
        });
        if let Some(m) = &self.method {
            presence["method"] = serde_json::Value::from(m.clone());
        }
        presence
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub allowed: bool,
    /// Ids of the `forbid` policies that determined a `Deny`.
    pub forbids: Vec<String>,
    pub errors: Vec<String>,
}

impl Evaluation {
    fn error(e: String) -> Self {
        Self {
            allowed: false,
            forbids: vec![],
            errors: vec![e],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        Facts {
            uid: 1000,
            user_name: "alice".to_owned(),
            server_id: "contoso".to_owned(),
            server_url: "https://contoso.awsapps.com/start".to_owned(),
            role: "123456789012/Admin".to_owned(),
            session: "tty",
            tty: Some("/dev/pts/3".to_owned()),
            hardened: true,
            intent: "exec",
            exec_command: Some("terraform".to_owned()),
            exec_command_line: Some("terraform apply".to_owned()),
            cwd: Some("/home/alice/src".to_owned()),
            chained_role_arn: None,
        }
    }

    fn allowed(engine: &Engine, presence: Presence) -> bool {
        let prepared = engine.prepare(&facts()).unwrap();
        let eval = engine.evaluate(&prepared, &presence);
        assert!(eval.errors.is_empty(), "{:?}", eval.errors);
        eval.allowed
    }

    #[test]
    fn test_builtins_validate() {
        assert_eq!(
            Engine::builtin(true).unwrap().policy_ids(),
            vec!["builtin-human"]
        );
        assert_eq!(
            Engine::builtin(false).unwrap().policy_ids(),
            vec!["builtin-unhardened"]
        );
    }

    #[test]
    fn test_builtin_human() {
        let engine = Engine::builtin(true).unwrap();
        assert!(!allowed(&engine, Presence::none()));
        assert!(allowed(&engine, Presence::fresh("platform")));
        // Session grants: 5 min idle, 12 h max.
        assert!(allowed(
            &engine,
            Presence::remembered(Scope::Session, "platform", 3600, 300)
        ));
        assert!(!allowed(
            &engine,
            Presence::remembered(Scope::Session, "platform", 3600, 301)
        ));
        assert!(allowed(
            &engine,
            Presence::remembered(Scope::Session, "platform", 43200, 0)
        ));
        assert!(!allowed(
            &engine,
            Presence::remembered(Scope::Session, "platform", 43201, 0)
        ));
        // Process leases: 1 h idle, no age limit.
        assert!(allowed(
            &engine,
            Presence::remembered(Scope::Process, "platform", 86400 * 7, 3600)
        ));
        assert!(!allowed(
            &engine,
            Presence::remembered(Scope::Process, "platform", 60, 3601)
        ));
    }

    #[test]
    fn test_builtin_unhardened_permits_everything() {
        let engine = Engine::builtin(false).unwrap();
        assert!(allowed(&engine, Presence::none()));
    }

    #[test]
    fn test_forbid_reports_its_id() {
        let engine = Engine::new(
            r#"
            @id("allow")
            permit (principal, action, resource);
            @id("no-admin")
            forbid (principal, action, resource in Mairu::Account::"123456789012")
            when { context has exec_command && context.exec_command == "terraform" };
            "#,
        )
        .unwrap();
        let prepared = engine.prepare(&facts()).unwrap();
        let eval = engine.evaluate(&prepared, &Presence::none());
        assert!(!eval.allowed);
        assert_eq!(eval.forbids, vec!["no-admin"]);
    }

    #[test]
    fn test_evaluation_error_is_deny() {
        // Overflows at evaluation for any age > 0. Cedar skips an erroring policy, which here would allow.
        let engine = Engine::new(
            r#"
            @id("allow")
            permit (principal, action, resource);
            @id("overflow")
            forbid (principal, action, resource)
            when { context.presence.age + 9223372036854775807 < 0 };
            "#,
        )
        .unwrap();
        let prepared = engine.prepare(&facts()).unwrap();
        let eval = engine.evaluate(
            &prepared,
            &Presence::remembered(Scope::Session, "platform", 1, 0),
        );
        assert!(!eval.errors.is_empty());
        assert!(!eval.allowed);
    }

    #[test]
    fn test_policy_without_id_is_refused() {
        assert!(matches!(
            Engine::new("permit (principal, action, resource);"),
            Err(PolicyError::Parse(_))
        ));
    }

    #[test]
    fn test_strict_validation() {
        let err = Engine::new(
            r#"@id("typo") permit (principal, action, resource) when { context.presense.verified };"#,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyError::Validation(_)), "{err}");
    }

    #[test]
    fn test_account_parent() {
        let engine = Engine::new(
            r#"@id("acct") permit (principal, action, resource in Mairu::Account::"123456789012");"#,
        )
        .unwrap();
        assert!(allowed(&engine, Presence::none()));
        let mut f = facts();
        f.role = "arn:aws:iam::210987654321:role/Admin".to_owned();
        let prepared = engine.prepare(&f).unwrap();
        assert!(!engine.evaluate(&prepared, &Presence::none()).allowed);
    }

    #[test]
    fn test_account_id() {
        assert_eq!(
            account_id("123456789012/Admin").as_deref(),
            Some("123456789012")
        );
        assert_eq!(
            account_id("arn:aws:iam::123456789012:role/path/Admin").as_deref(),
            Some("123456789012")
        );
        assert_eq!(account_id("12345/Admin"), None);
        assert_eq!(account_id("arn:aws:iam::123456789012:user/x"), None);
        assert_eq!(account_id("admin"), None);
    }
}
