# 011-user-policy

## Summary

Until now the agent decides with built-in policies only ([007](007-authorization.md#built-in-policies), [009](009-caller-identity.md#gate-2), [010](010-tool-detection.md#policies-with-labels)). This step lets the user write their own: Cedar policies in `~/.config/mairu/policy.cedar`, and settings that are not policies in `~/.config/mairu/authorization.json`. The agent reads both files itself. Clients never send policy content.

These files live in the user's home directory, where any process of the user can edit them. So far nothing records that a human approved their content, so every file is **unapproved**: the agent applies the built-ins **plus only the `forbid` policies** of `policy.cedar`, and only the settings that tighten. Adding a `forbid` can only remove permissions, so unapproved content can only tighten. The `mairu policy` commands `init`, `check`, `show`, `explain` and `schema` help write, validate and inspect the policy, and `GetPolicy` reports what is in force.

## Motivation

- The built-in policies fit everyone a little. Users need rules of their own: production roles that always need a fresh check, servers that never serve AI agents, read-only roles that need no check at all.
- The existing safety net, `disallow_roles` in `config.json`, is a flat deny list that the same code it restrains can edit.
- Authorization policy is written in [Cedar](https://www.cedarpolicy.com/), the policy language behind Amazon Verified Permissions. Its semantics match AWS IAM, which mairu's users already know:
  - The default is deny.
  - A `forbid` overrides any `permit`.
  - A human check is just another condition on the request, like `aws:MultiFactorAuthPresent`.
- Restrictions are safe to apply as soon as they are written, whoever wrote them. Relaxations are not: same-user code could add a `permit` for itself. Applying only `forbid` policies from unapproved files lets users tighten immediately, and keeps relaxing for an explicit approval that cannot be forged by editing a file.

## Explanation

### Files

```text
you edit         ~/.config/mairu/{policy.cedar, authorization.json}
agent reads      the same files itself (clients never send policy)
```

| File | Content |
|---|---|
| `config_dir()/policy.cedar` | Cedar policies. Only static policies are allowed; templates are rejected. |
| `config_dir()/authorization.json` | Settings that are not policies ([Settings](#settings)) |

- Both are ordinary files the user edits. The agent reads them itself; clients never send policy content.
- Either file may be absent.
- The schema and the built-in policies are embedded in the binary. `mairu policy schema` prints the schema for use with Cedar's own tooling (for example `cedar validate --schema`).

Example `policy.cedar`:

```cedar
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
```

While the file is unapproved, only `no-ai-prod` and `prod-by-real-account` apply. The two `permit` policies are ignored ([Effective policy](#effective-policy)).

**Which context to rely on.** The context attributes of [007 Cedar schema](007-authorization.md#cedar-schema), [009 Caller identity](009-caller-identity.md#caller-identity) and [010 Labels and signals](010-tool-detection.md#labels-and-signals) differ in who determines them:

| Class | Attributes | May be used to |
|---|---|---|
| agent-determined | `presence`, `hardened`, `session`, `tty`, `caller` | grant |
| requester-chosen | `intent`, `exec_command`, `exec_command_line`, `cwd`, `chained_role_arn` | narrow or forbid only |
| guardrail | `tools`, `tool_matches` (names and marks anyone can produce or avoid) | restrict or grant, knowingly |

- **Determined by the agent**: `presence`, `hardened`, `session`, `tty`, and `caller`. These cannot be influenced by the requester beyond actually being in that position.
- **Reported by the client**: `intent`, `exec_command`, `exec_command_line`, `cwd` and `chained_role_arn`. A verified client reports them truthfully, but whoever runs `mairu` chooses them: same-user code can `cd` into any directory or exec any command. Use them to **narrow** a `permit` that also requires `context.presence.verified`, or in a `forbid`. Never rely on them alone to grant access.
- **Guardrail**: `tools` and `tool_matches`. The agent collects them, but from process names, environment names and session marks that same-user code can produce or avoid.

`mairu policy check` lists every `permit` that can apply without a human check, and every `permit` that depends on a tool label, so these are always visible.

### Settings

```text
authorization.json
├── methods            # order to ask for AssumeRole
├── tool_detection     # labels and their process / env names
├── grant_retention_secs
├── sts                # how gate 2 reaches STS
└── network            # proxy and extra TLS roots for the agent's outbound connections
```

```jsonc
{
  "version": 1,
  // Order in which to try ways of asking the human for AssumeRole. Default: ["platform"].
  "methods": ["platform"],
  "tool_detection": {
    // Each key is a label in context.tools. "ai-agent" extends the built-in lists.
    "ai-agent": {"process_names": ["my-agent"], "env_names": ["MY_AGENT_ACTIVE"]},
    "ci": {"env_names": ["CI", "GITHUB_ACTIONS"]},
    "terraform": {"process_names": ["terraform", "tofu"]}
  },
  "grant_retention_secs": 43200,
  // How gate 2 reaches sts:GetCallerIdentity. Default: the global endpoint, sts.amazonaws.com.
  "sts": {
    "region": "us-east-1",
    "endpoint": "https://vpce-0123-abcd.sts.us-east-1.vpce.amazonaws.com",  // optional, https only
    "servers": {"cn": {"region": "cn-north-1"}}  // per server, for other partitions
  },
  // The hardened agent's outbound connections: no proxy and the system roots by default.
  "network": {
    "proxy": "http://proxy.corp.example:3128",
    "extra_roots": ["-----BEGIN CERTIFICATE-----\n…"]   // PEM, added to the system roots
  }
}
```

- The file is plain JSON; the comments are for documentation only.
- Every field except `version` is optional.
- Unknown fields are rejected, so a typo never silently weakens anything.
- `methods`: the method names known so far are `"platform"`, the platform's own facility: polkit on Linux ([007 Polkit](007-authorization.md#polkit)). A policy can require a specific method through `context.presence.method`.
- `tool_detection`: each key is a label (lowercase `[a-z0-9-]+`) with optional `process_names` and `env_names`, matched as in [010 Labels and signals](010-tool-detection.md#labels-and-signals). `"ai-agent"` extends the built-in lists rather than replacing them.
- `grant_retention_secs`: how long a grant is kept at all (default 43200, [007 Grants and leases](007-authorization.md#grants-and-leases)). Freshness itself is a policy matter.
- `sts`: the region and endpoint of the gate-2 call ([009 Caller identity](009-caller-identity.md#caller-identity)). `endpoint` is optional and must be `https`. `servers` sets the region per server id, for servers in other partitions.
  - `sts` is **never taken from an unapproved file**. An endpoint that answered `GetCallerIdentity` falsely could report any identity, so unapproved files fall back to the default.
  - A hardened agent keeps ignoring the environment's endpoint and region overrides whatever the file says.
- `network`: for hosts that reach AWS and the credential servers only through a proxy, or through TLS inspection with their own CA ([004 Hardened agent environment](004-peer-verification.md#hardened-agent-environment)). `proxy` is an `http` or `https` URL used for every outbound connection of the agent; `extra_roots` are PEM certificates trusted in addition to the system roots.
  - `network` is **never taken from an unapproved file**, for the same reason as `sts`: a proxy with an extra root sees every session token.

### Effective policy

```text
ABSENT      built-ins
UNAPPROVED  built-ins + your forbid policies only
```

| State | When | Policies | Settings |
|---|---|---|---|
| `ABSENT` | Both files absent | Built-ins for the hardening state | Defaults |
| `UNAPPROVED` | Either file present | Built-ins **plus only the `forbid` policies** of `policy.cedar` | Defaults, plus the tightening settings below |

- The built-ins are those for the hardening state: on a hardened agent `builtin-human` and `builtin-ai-agent-per-request` ([010](010-tool-detection.md#policies-with-labels)); on an unhardened agent `builtin-unhardened` ([007](007-authorization.md#built-in-policies)). The always-on gate-2 built-ins join every effective policy set wherever gate 2 runs ([009](009-caller-identity.md#gate-2)).
- **Forbid-only.** Adding a `forbid` can only remove permissions, so unapproved content can only tighten. `permit` policies are ignored.
  - If `policy.cedar` does not parse, it is ignored as a whole.
  - `forbid` policies that fail validation are dropped one by one. Each drop is reported in `GetPolicy.notes`, for example `dropped forbid policy.cedar#3: validation error …`.
- **Settings while unapproved**: the defaults, plus
  - `tool_detection` additions, which only add guardrail labels;
  - a smaller `grant_retention_secs`, which tightens.
  `methods` in the file is ignored, since reordering or adding methods can relax. `sts` is ignored ([Settings](#settings)).
- On an unhardened agent the built-in already permits everything, so only the user's `forbid` policies have any effect there. That is how an unhardened user can still deny a role.

The agent reads the files:

- at agent start;
- before every authorization decision, cached by `(dev, ino, mtime, size)` of both files plus a 5 s TTL.

`disallow_roles` in `config.json` keeps working as before, outside Cedar ([007 Decision procedure](007-authorization.md#decision-procedure)).

### Policy commands

```text
mairu policy init [--force]     write templates
mairu policy check              validate locally, list policies and risky permits
mairu policy show               what the agent has in force (GetPolicy)
mairu policy explain …          what would happen if…
mairu policy schema             print the Cedar schema
```

- `mairu policy init [--force]`: writes the hardened built-in policies, with explanatory comments, into `policy.cedar`, plus a minimal `authorization.json`. The user then edits them. Without `--force`, it refuses to overwrite existing files.

Callers without a tty, such as IDEs running `credential-process`, are asked roughly once an hour under the built-ins ([007 Built-in policies](007-authorization.md#built-in-policies)). The README documents this relaxation for users who want fewer prompts:

```cedar
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
```

Like every `permit` in the user's file, it is ignored while the file is unapproved ([Effective policy](#effective-policy)).
- `mairu policy check`: client-local, no agent involved.
  - Validates both files ([Validation](#validation)).
  - Lists every policy: id, effect, scope.
  - Flags every `permit` that applies without a human check, and every `permit` that depends on a tool label.
  - Warns about policies without `@id`, shown as `policy.cedar#<n>`.
- `mairu policy show`: from `GetPolicy`, prints the effective policies and settings, the policy state, and notes such as dropped policies.
- `mairu policy explain <server> <role> [--assume-role ARN] [--tool LABEL]… [--intent exec|credential-process] [--cwd PATH] [--exec CMD]`:
  - Fetches the effective policy through `GetPolicy`.
  - Evaluates it locally for every candidate presence of [007 Decision procedure](007-authorization.md#decision-procedure): none, process lease, session grant at a given age and idle time, and fresh per method.
  - Prints each decision with its determining policy ids. This answers "what would happen if…".
- `mairu policy schema`: prints the schema.

#### Validation

A policy file is valid when:

- it parses as a set of **static** Cedar policies;
- `Validator::validate(…, ValidationMode::Strict)` against the embedded schema passes; strict mode, for example, requires `has` before an optional attribute;
- every `@id` is unique, and none starts with `builtin-` (reserved);
- `authorization.json` matches [Settings](#settings).

Policies without `@id` are shown as `policy.cedar#<n>`.

**`GetPolicy`**, as clients see it, returns:

- `effective_policies`: the Cedar text in force, built-ins included;
- `effective_settings_json`: the settings in force;
- `integrity`: `ABSENT` or `UNAPPROVED`;
- `notes`: such as dropped policies.

## Drawbacks

- Users cannot relax anything yet: their `permit` policies are written but ignored, and so are `methods`, `sts` and `network`. Only the built-ins grant.
- A syntax error in `policy.cedar` drops the whole file, including its `forbid` policies, until it is fixed. `check`, `show` and `doctor` make that visible, but the user must look.
- Cedar is a new language for most users. `init`, `check` and `explain` exist to soften that.
- Requester-chosen context cannot be used to grant, which rules out conveniences such as "no check inside this directory".
- Unknown fields in `authorization.json` are rejected, so a file written for a newer mairu fails on an older one.

## Considered Alternatives

- **A JSON rule file** (`policy.json` with `defaults{require, ai_agents}` and `rules[{server, role, require, ai_agents}]`), from the first design. Replaced by Cedar: IAM-like semantics, a real validator with strict mode, and conditions over any context attribute instead of a fixed set of knobs.
- **Merging unapproved files per attribute** ("defaults ⊓ file", the stricter value per rule), from the first design. With Cedar, applying only the `forbid` policies is tighten-only by construction, with no per-attribute merge rules.
- **Ignoring unapproved files entirely.** `forbid` rules then would not work without an approval, and on hosts with nowhere to record one they would never work. Applying the `forbid` policies at once keeps deny rules useful everywhere.
- **Settings inside Cedar.** Methods, keys, labels and STS endpoints are not decisions about a request. They live in `authorization.json`.
- **Cedar templates.** Rejected: static policies only, so validation and listing stay simple.
- **Clients sending the policy.** The agent reads the files itself, so a client cannot present content of its choosing.
- **Ignoring unknown fields.** A misspelled field would silently weaken the intended setting, so unknown fields are rejected.
- **Partial parsing of a broken file.** Applying whatever parses could keep a `forbid` but also silently lose one. A file that does not parse is ignored as a whole, and the failure is reported.

## Prior Art

- AWS IAM: default deny, an explicit deny wins over any allow, and `aws:MultiFactorAuthPresent` as a request condition. The same semantics carry over.
- Amazon Verified Permissions and the Cedar CLI: the schema printed by `mairu policy schema` can be used with `cedar validate --schema`.

## Security and Privacy Considerations

```text
relaxing the policy by editing     ✗ unapproved files contribute forbids only
forbid skipped by an error         ✗ strict validation; errors count as Deny
```

| Threat | Mitigation |
|---|---|
| Editing the policy to relax it | Only `forbid` policies apply from an unapproved file; `methods`, `sts` and `network` are ignored |
| A `forbid` silently skipped because its evaluation errors | Strict schema validation at load and in `check`; any evaluation error makes the candidate `Deny` ([007](007-authorization.md#decision-procedure)) |
| A `permit` that relies only on requester-chosen context (`cwd`, `exec_command`, …) | Documented; `check` lists every permit that needs no human check |
| A `permit` that depends on a forgeable tool label | Documented as a guardrail; `check` lists such permits |
| A forged `GetCallerIdentity` answer through an endpoint in the file | `sts` is never taken from an unapproved file |
| A proxy and a CA in the file, to read session tokens | `network` is never taken from an unapproved file |

- The files are read by the agent with the user's own permissions. They hold no secrets.
- `mairu policy check` runs entirely in the client, with no agent involved.

## Mission Scope

### Out of scope

- Approving a policy, recording that approval, and detecting changes after approval.
- Integrity of `servers.d`.
- Cedar templates, and policy files outside `config_dir()`.
- Integrity for `.mairu.json` trust records.

### Expected Outcomes

- `forbid` policies in `policy.cedar` take effect at once, on hardened and unhardened agents alike.
- `permit` policies, `methods`, `sts` and `network` from the files have no effect.
- `mairu policy init`, `check`, `show`, `explain` and `schema` work as described.
- A broken file or a policy that fails validation is reported in `GetPolicy.notes` and by `check`, and never causes a `permit` to apply.

## Implementation Plan

Stack layer: `hardening/user-policy`, on top of `hardening/tool-detection`.

### Files

| File | Change |
|---|---|
| `src/policy/files.rs` | New. Reads `policy.cedar` and `authorization.json` from `config_dir()`; cache by `(dev, ino, mtime, size)` plus a 5 s TTL |
| `src/policy/settings.rs` | New. `authorization.json` schema (`serde`, `deny_unknown_fields`); effective settings |
| `src/policy/mod.rs` | Effective policy set: built-ins, always-on built-ins, the file's `forbid` policies; validation; notes |
| `src/policy/templates/{policy.cedar,authorization.json}` | New. What `mairu policy init` writes |
| `src/tool_detection.rs` | Labels from the effective `tool_detection` settings |
| `src/caller_identity.rs` | STS region and endpoint from the effective settings (the defaults, at this step) |
| `src/authorization.rs` | Method order and `grant_retention_secs` from the effective settings |
| `src/cmd/policy.rs` | New. `init`, `check`, `show`, `explain`, `schema` |
| `src/main.rs` | The `policy` subcommand |
| `src/agent.rs` | `GetPolicy` |
| `proto/mairu.proto` | `GetPolicy`, `PolicyIntegrity` |
| `README.md` | Writing `policy.cedar`, the context trust table, the commands, the relaxation for callers without a tty |

### Settings schema

```rust
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationSettings {
    pub version: u32,                                   // 1
    pub methods: Option<Vec<String>>,
    pub tool_detection: Option<std::collections::BTreeMap<String, ToolDetectionEntry>>,
    pub grant_retention_secs: Option<u64>,
    pub sts: Option<StsSettings>,
    pub network: Option<NetworkSettings>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDetectionEntry {
    #[serde(default)] pub process_names: Vec<String>,
    #[serde(default)] pub env_names: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StsSettings {
    pub region: Option<String>,
    pub endpoint: Option<url::Url>,                     // https only
    #[serde(default)] pub servers: std::collections::BTreeMap<String, StsServerSettings>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StsServerSettings {
    pub region: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSettings {
    pub proxy: Option<url::Url>,                        // http or https
    #[serde(default)] pub extra_roots: Vec<String>,     // PEM
}
```

- Validation beyond `serde`: `version == 1`; method names known to this binary; labels match `^[a-z0-9-]+$`; `sts` endpoints use `https`; `network.proxy` uses `http` or `https`; every `extra_roots` entry parses as one certificate.
- The file is parsed with `serde_json`; comments are not accepted.

**Effective settings** (`settings::effective(state, file)`):

| Setting | `ABSENT` | `UNAPPROVED` |
|---|---|---|
| `methods` | `["platform"]` | `["platform"]`; the file's value is ignored |
| `tool_detection` | built-in `ai-agent` | built-in, plus the file's labels and names |
| `grant_retention_secs` | 43200 | `min(43200, file)` |
| `sts` | default | default; the file's value is ignored |

### Effective policy set

```text
effective_policy_set(state, hardened, policy.cedar)
  built-ins(hardened)                     builtin-human + builtin-ai-agent-per-request | builtin-unhardened
  + always-on gate-2 built-ins            only where gate 2 runs
  + UNAPPROVED: forbid policies of policy.cedar that validate; notes for the rest
```

1. Parse `policy.cedar` as a `PolicySet`. On a parse error, use no user policies and add a note.
2. Reject templates (`PolicySet::templates()` non-empty) with a note, and use no user policies.
3. Keep only policies with `Effect::Forbid`.
4. Validate each kept policy alone with `ValidationMode::Strict`. Drop each one that fails, with a note naming it (`@id`, or `policy.cedar#<n>`) and the validation error.
5. Reject duplicate `@id`s and ids starting with `builtin-`: drop the offending policies with a note.
6. Add the built-ins.

The result is what the decision procedure of [007](007-authorization.md#decision-procedure) evaluates, at both gates. Any Cedar evaluation error still makes that candidate `Deny`.

`mairu policy check` runs the full validation on the whole file, `permit` policies included, and reports instead of dropping. It flags:

- a `permit` that can apply without a human check, that is, one that can be satisfied with `context.presence.verified == false`;
- a `permit` that mentions `context.tools` or `context.tool_matches`.

### Protocol

```proto
service Agent {
  // ... existing RPCs ...
  rpc GetPolicy(GetPolicyRequest) returns (GetPolicyResponse);
}

enum PolicyIntegrity {
  POLICY_INTEGRITY_UNSPECIFIED = 0;
  POLICY_INTEGRITY_ABSENT = 1;
  POLICY_INTEGRITY_APPROVED = 2;
  POLICY_INTEGRITY_UNAPPROVED = 3;
  POLICY_INTEGRITY_TAMPERED = 4;
}

message GetPolicyRequest {}
message GetPolicyResponse {
  string effective_policies = 1;        // Cedar text actually in force, built-ins included
  string effective_settings_json = 2;   // authorization.json as in force
  PolicyIntegrity integrity = 3;
  repeated string notes = 6;            // e.g. "dropped forbid policy.cedar#3: validation error …"
}
```

- At this step `integrity` is `ABSENT` or `UNAPPROVED`. The other values are reserved for the states that need an approval record.
- Fields 4, 5 and 7 are reserved for integrity details.
- `GetPolicy` requires a trusted peer ([004](004-peer-verification.md#agent-side)) and no authorization.

### `explain`

- Runs in the client with the `cedar-policy` crate, the embedded schema, and `effective_policies` from `GetPolicy`.
- Builds the entities of [007 Cedar schema](007-authorization.md#cedar-schema) from its arguments: the role (and its declared account), the server, `--assume-role`, `--tool` labels, `--intent`, `--cwd` and `--exec`.
- Evaluates every candidate presence: none; a process lease; a session grant at a given age and idle time; and a fresh check for each effective method.
- Prints each decision with its determining policy ids.

### Tests

- Effective policy set: a `permit` in an unapproved file is ignored; a `forbid` applies; a file that does not parse contributes nothing and produces a note; a `forbid` that fails strict validation is dropped with a note; duplicate and `builtin-` ids are dropped.
- Effective settings: `methods`, `sts` and `network` from the file are ignored; `tool_detection` additions apply; a larger `grant_retention_secs` is capped at the default.
- `authorization.json` with an unknown field is rejected.
- File cache: an edit is seen within 5 s, and immediately when `(dev, ino, mtime, size)` changes.
- `check` flags a `permit` that needs no human check and a `permit` that depends on a label.
- End to end: add a `forbid` for a role without approving anything; the next request for that role is refused with `REASON_FORBIDDEN` and the policy id.
- Cedar: every block above validates strictly against the schema.

## Current Status

Implemented on `hardening/user-policy`. Implementors MUST keep this section updated as they work.

### Checklist

- [x] `policy.cedar` and `authorization.json` read by the agent from `config_dir()`, with the file cache
- [x] `authorization.json` schema: `methods`, `tool_detection`, `grant_retention_secs`, `sts`; unknown fields rejected
- [x] Effective policy for `ABSENT` and `UNAPPROVED`: built-ins plus `forbid` policies only; tightening settings only; notes for dropped policies
- [x] Validation: static policies, strict mode, unique ids, reserved `builtin-` prefix
- [x] `GetPolicy` and `PolicyIntegrity`
- [x] `mairu policy init|check|show|explain|schema`

### Updates

- 2026-10-29: Split out of hardening.md, policy.md and platform-helper.md.
- 2026-10-31: Implemented.
  - Parsing, the unapproved `forbid` set and the `check` analysis live in a new `src/policy/user.rs`; `files.rs` holds the cache and the `Effective` policy (engine, settings, labels, state, notes); `mod.rs` builds the engine from the built-ins, the always-on built-ins and the kept `forbid` policies.
  - Cache: every decision stats both files; a changed `(dev, ino, mtime, size)` reloads at once, otherwise the files are re-read once the last load is 5 s old. Files are read through the opened descriptor, so the key describes exactly what was read. A file that is not a regular file, is unreadable, or exceeds 1 MiB is ignored with a note, and still counts as present (`UNAPPROVED`).
  - Policy numbering is 1-based in file order (`policy.cedar#1`). Policies without `@id` get `@id("policy.cedar#<n>")` prepended in `effective_policies`, so the text parses back with every id; `explain` relies on that. Every policy whose id is duplicated anywhere in the file is dropped, not only the later ones.
  - Besides the dropped-policy notes, `GetPolicy.notes` also names the ignored `permit` policies and the ignored `methods`, `sts` and `network` settings, so `show` explains every ignored part.
  - `effective_settings_json` shows `version`, `methods`, `grant_retention_secs` and the file's `tool_detection` additions (not the built-in `ai-agent` names).
  - "Can apply without a human check" is decided syntactically and conservatively from Cedar's JSON form: a `permit` is not flagged only when a `when` requires `context.presence.verified` (or `== true`) as a top-level conjunct, or an `unless` names `!context.presence.verified` (or `== false`) as a top-level disjunct.
  - `explain` takes `--age` and `--idle` (default 0) for the lease and grant candidates, uses the current terminal as `tty`, or `parent` without one, takes the hardening state from the presence of `builtin-unhardened` in the effective set, and also evaluates gate 2 on a hardened agent, for credentials of the account the role (or `--assume-role`) declares.
  - `caller_identity.rs` and the hardened agent's network setup are unchanged: `sts` and `network` are never taken from an unapproved file, and there is no other state yet, so the effective values are always the defaults. 012 wires them for `APPROVED`.
  - `mairu doctor` prints the policy state and notes, computed locally from the files (doctor keeps to `PingAgent` and `GetAgentStatus`).
  - Verified in Docker (`011-user-policy` scenario, hardened install, polkit answering through a rules file, fake credential server and STS): absent state and built-ins in `show`; `init`/`check`; a `forbid` refusing at once with `REASON_FORBIDDEN` and its id, without prompt or fetch; an ignored `permit`; a gate-2 `forbid` by the real account prompting at `use-credentials`; a broken file ignored as a whole; strict-validation, duplicate and `builtin-` drops with notes; `tool_detection` labels and a shorter `grant_retention_secs` taking effect; `methods`/`sts`/`network` ignored (credentials still checked at the default STS endpoint); unknown fields rejected; edits seen by the next request; `doctor`; and a `forbid` on an unhardened agent.
