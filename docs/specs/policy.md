# Authorization and policy

When `mairu agent` asks the human before vending credentials, how it remembers the answer, and the [Cedar](https://www.cedarpolicy.com/) policy that decides both.

Related specs:

- [hardening.md](hardening.md): threat model, terminology, trust chain, and the mutual verification every request here depends on.
- [platform-helper.md](platform-helper.md): the platform facilities that ask the human (polkit, LocalAuthentication), the integrity stores, and the `mairu.platform` protocol.

## 1. Overview

The agent asks the human before vending credentials, and remembers the answer for a while. This spec defines:

- when authorization applies (§2), and the session identity that answers are remembered against (§3)
- grants per terminal session, leases per running `mairu exec`, and the decision procedure that consults the policy (§4)
- AI-agent detection as a guardrail (§5)
- presence methods: the platform's own facility, and the key-based ssh-agent and Windows Hello methods (§6)
- what the human sees (§7) and revocation (§8)
- the Cedar policy, its settings, built-ins, integrity records, approval anchor and commands (§9)
- the agent protocol for all of the above (§10)

A human check is just another condition in the policy, as MFA is in AWS IAM: the agent asks only when some fresh presence would make the policy permit the request.

The threat model, terminology and the trust chain that bounds everything here are in [hardening §1.1, §2](hardening.md). Peer verification ([hardening §5](hardening.md)) must succeed before anything in this spec applies.

## 2. When authorization applies

Authorization runs in `AssumeRole`, after the peer trust check and server/user-config loading, and **before** the credential cache lookup. `ApprovePolicy` always requires authorization (§9.9). `ListRoles`, `ListSessions`, `GetServer`, `RefreshSession`, the login RPCs and `ShutdownAgent` require only a trusted peer.

## 3. Session identity

```
SessionIdentity =
  Tty    { sid, leader_start_time }   if tty_nr != 0 and /proc/<sid> exists with session == sid
  Parent { ppid, start_time }         else if ppid > 1 and the parent is alive
  none                                otherwise: no grants (every request prompts unless leased)
```

- Pairing each id with a start time defeats id reuse.
- Each GUI terminal tab, each SSH login and **each tmux pane** is its own POSIX session: the pane shell is created through `forkpty` → `setsid`. A grant therefore covers one pane, and survives detach/reattach within the idle window.
- Tools that run commands without a controlling tty and in a fresh session, such as an AI agent's shell tool (observed: Claude Code runs each command under `setsid` with no tty), fall into `Parent`. That parent is usually short-lived, so grants rarely carry over.

## 4. Grants, leases and the decision procedure

The agent remembers human checks as grants and leases, and the Cedar policy (§9) decides whether a remembered check is good enough for a given request. The agent never hardcodes "this role needs a prompt": it only asks whether some presence would make the policy permit the request, which is how MFA conditions behave in AWS IAM.

**Clock.** `CLOCK_BOOTTIME`, so suspended time counts toward ages and idle times. `std::time::Instant` uses `CLOCK_MONOTONIC` on Linux, which excludes suspend.

**Grant.**

- Key: `(SessionIdentity, server_id, Rolespec)`. `server_id` is the canonical id from the server config. `Rolespec` includes the chained `assume_role` fields, since a chained role is different access.
- Value: `{created, last_used, method}`.
- Recorded after every successful human check when the peer has a session identity.
- When a grant is what permits a request, `last_used = now`.
- Dropped after `grant_retention_secs` (default 43200, §9.5) to bound memory. Freshness itself is a policy matter (`context.presence.age`, `context.presence.idle`).

**Lease.**

- Key: `(peer pid, peer start_time, server_id, Rolespec)`. Value: `{created, method}` and the peer's pidfd.
- Recorded after every successful human check whose intent is `exec`.
- Valid while the pidfd's process is alive. Swept every 60 s and checked on lookup.

All authorization state is in memory only. Restarting the agent forgets every grant and lease.

**Request digest.** SHA-256 over the prost encoding of `{action, server_id, rolespec, ClientContext without authorization_response}`. It binds ssh-agent challenges to the exact request, which the retry must repeat.

**Decision procedure** (`src/authorization.rs`, `Authorizer::authorize_assume_role`):

1. `UserConfig::is_role_disallowed` (existing `disallow_roles`) → `REASON_FORBIDDEN`. This check stays outside Cedar and behaves as today.
2. Build the Cedar request (§9.3): principal, action, resource entities, and the base context including AI signals (§5).
3. Evaluate the effective policy set (§9.8) with each **remembered presence** in turn. The first candidate that is `Allow` permits the request; for a grant, also touch `last_used`.

   | Candidate | `presence` |
   |---|---|
   | nothing remembered | `{verified: false, scope: "none", age: 0, idle: 0}` |
   | the lease for (peer, server, rolespec), if any | `{verified: true, scope: "process", method, age: now − created, idle: 0}` |
   | the grant for (session, server, rolespec), if any | `{verified: true, scope: "session", method, age: now − created, idle: now − last_used}` |

4. Otherwise, for each method `m` in the effective method order (§9.5) that is usable for this request, evaluate a **fresh** candidate: `{verified: true, scope: "request", method: m, age: 0, idle: 0}`. The first `m` whose candidate is `Allow` is the method to ask with:
   - **ssh-agent** and **windows-hello**, the key-based methods (§6.2, §6.3):
     - The request carries a valid response (`sshsig` or `windows_hello_signature`) for an outstanding challenge of that method → verify → permit.
     - It carries `declined` → continue with the next method.
     - Otherwise → issue a challenge for that method → `REASON_CHALLENGE`.
   - **platform** (`Platform::authorize`):
     - `ALLOWED` → permit.
     - `DENIED`/`CANCELLED` → `REASON_DENIED`.
     - `UNAVAILABLE`/`no-authentication-agent` → `REASON_NO_AUTHENTICATION_AGENT`.
     - Any other `UNAVAILABLE` → continue with the next method.

   If a fresh candidate allows but no method can ask → `REASON_UNAVAILABLE`, with a detail listing what was tried.
5. On a permit from step 4, record the lease (exec intent) and the grant (session identity present).
6. Otherwise refuse:
   - If any evaluation in steps 3–4 was `Deny` with a `forbid` among its determining policies → `REASON_FORBIDDEN`, listing those policy ids.
   - Otherwise → `REASON_NOT_PERMITTED`: no `permit` applies, even after a human check.

   `AuthorizationError.ai_agent` is set when AI signals were present.

**Fail closed on evaluation errors.** Cedar skips a policy whose evaluation errors, which would silently drop a `forbid`. Any candidate whose response carries errors is therefore treated as `Deny`, and the errors are logged. Strict validation (§9.9) keeps this from happening in practice.

Concurrent requests with the same grant key wait on one platform prompt through the existing `crate::singleflight::Singleflight`. ssh-agent challenges are per request and are not coalesced.

## 5. AI-agent detection (guardrail)

Signals, all positive-only (they can add caution, never remove it):

- **Ancestry.** Walk from the peer up through `ppid`, stopping at pid 1, at a uid change, or after 64 hops. Match each ancestor's `comm`, `exe` basename, `argv[0]` basename and `argv[1]` basename (interpreters such as `node script`) exactly against `process_names` (built-ins plus `ai_agent_detection.process_names`, §9.5). The built-in default is `["claude", "codex", "gemini", "cursor-agent", "aider", "opencode", "goose", "amp", "crush", "qwen", "copilot"]`; recheck it against current agents during implementation.
- **Environment names.** The client sends the names (never values) of its environment variables. They are matched against `env_names`. The built-in default is `["AI_AGENT", "CLAUDECODE", "GEMINI_CLI", "CODEX_SANDBOX"]`; `AI_AGENT` and `CLAUDECODE` were observed in Claude Code's tool environment, and the rest need verifying. The agent cannot read `/proc/<pid>/environ` of a hardened (non-dumpable) peer, so the genuine client reports them. Same-user code can only *add* markers, by launching mairu with them, which only makes things stricter.

The result is `context.ai_agent` and `context.ai_agent_names` (§9.2). What happens to AI-agent requests is up to the policy; the built-in policy (§9.6) requires a human check for every new AI-agent request and never lets AI agents reuse session grants.

Evasion is possible (`setsid` + double fork, `systemd-run --user`, a renamed binary), which is why this is a guardrail: the authorization prompt remains the boundary. Detected signals appear in the prompt details (`ai_agent=…`) and in `doctor`.

## 6. Presence methods

A presence method asks the human and proves the answer to the agent. Methods are tried in the order of `methods` in `authorization.json` (§9.5). A policy can require one through `context.presence.method`.

| Method | Mechanism | Proof |
|---|---|---|
| `platform` | The platform's facility: polkit on Linux, LocalAuthentication on macOS ([platform-helper §6](platform-helper.md)) | A yes/no from a verified backend |
| `ssh-agent` | FIDO touch through the forwarded SSH agent (§6.2) | Signature over a challenge |
| `windows-hello` | Windows Hello key credential on WSL2 (§6.3) | Signature over a challenge |

### 6.1 Platform method

The agent calls `Platform::authorize` with action `ACTION_ASSUME_ROLE` or `ACTION_APPROVE_POLICY`, the peer as the subject, and the details of §7. Results map as in §4 (step 4). The Linux backend, including the `pkttyagent` fallback for headless sessions, is specified in [platform-helper §6.1](platform-helper.md), and the macOS one in [platform-helper §11](platform-helper.md).

### 6.2 ssh-agent presence (FIDO touch through the forwarded agent)

This is a platform-independent method. On headless hosts, and inside tmux over SSH in particular, it beats a tty password because a signature cannot be replayed.

**Registration** (`authorization.json`, §9.5), as `ssh_agent_keys[]`:

- `{"key": "<OpenSSH public key line>"}` is accepted only for `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`.
- Other key types require `"presence": "unverified-confirm"`. The agent cannot verify presence for them; the user must load them with `ssh-add -c`.
- Optional `"require_user_verification": true` additionally requires the UV flag (a PIN or biometric on the key).

**Challenge.** In step 4 of §4, when keys are registered and ssh-agent is the selected method, the agent:

1. creates `AuthorizationStatement{nonce, agent_instance_id, peer pid/start_time, action, server_id, rolespec, request_digest, expires_at = now + 60 s}` and serializes it once
2. stores `PendingChallenge{statement bytes, peer, request_digest, expires_at}` under a fresh `challenge_id`, keeping at most 4 outstanding per peer and evicting expired ones
3. returns `REASON_CHALLENGE` with `AuthorizationChallenge{challenge_id, statement, key_fingerprints, expires_at}`

**Client relay** (`src/ssh_agent_presence.rs`):

1. Connect to `$SSH_AUTH_SOCK` and send `SSH_AGENTC_REQUEST_IDENTITIES`. Pick the first identity whose `SHA256:` fingerprint is in `key_fingerprints`. If there is no socket or no key, retry with `declined`.
2. Print the context (§7) with `:: mairu :: Touch your security key (<comment>) to authorize …`, or "confirm on your SSH agent" for confirm keys.
3. Build the SSHSIG signed-data blob for namespace `co.0w0.mairu.authorize`, hash `sha512`, message = `statement` bytes, and send `SSH_AGENTC_SIGN_REQUEST`. Wrap the result into a binary SSHSIG.
4. Retry once with `authorization_response{challenge_id, sshsig}` and the same `ClientContext`.

**Verification** (agent):

1. The challenge exists and is **removed** (single use).
2. It has not expired.
3. The peer `(pid, start_time)` matches.
4. `request_digest` matches the retried request.
5. The SSHSIG namespace is `co.0w0.mairu.authorize`.
6. The public key equals a registered key.
7. The signature verifies with the `ssh-key` crate (`PublicKey::verify` supports sk-ed25519 and sk-p256).
8. For `sk-*` keys, mairu **parses the flags byte itself**, because `ssh-key` does not check it: the trailer after the inner signature is `flags (u8) || counter (u32)`. It requires `UP (0x01)`, plus `UV (0x04)` when configured.

A failure at any step returns `REASON_INVALID_RESPONSE`.

**Residual risk.** Same-user code can also reach the forwarded agent socket and request a signature. It still needs a physical touch, the challenge is bound to the requesting process and request, and a touch satisfies one pending request. An attacker who times a request to coincide with the user's own can steal one touch. This is documented.

**tmux note.** `SSH_AUTH_SOCK` in a long-lived pane points at a forwarded socket that disappears when that SSH login ends. The README recommends a stable symlink (`~/.ssh/rc` updating `~/.ssh/agent.sock`, plus `set -g update-environment` / `SSH_AUTH_SOCK=~/.ssh/agent.sock`). `doctor` reports reachability, and a stale socket declines to the next method.

### 6.3 Windows Hello presence (WSL2)

This is a key-based method, like ssh-agent (§6.2), for WSL2 distributions with interop enabled ([hardening §8](hardening.md)). It follows the pattern of WSL-Hello-sudo (`pam_wsl_hello`):
- a TPM-backed Windows Hello key credential signs a challenge from Linux
- Linux verifies the signature against a registered public key

The helper's output is never trusted on its own; only the signature counts.

**Helper.** `mairu-windows-hello.exe` is a small Rust binary in this repository (`windows-hello-helper/`), built for `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc` with the `windows` crate. It is published with releases. It uses `Windows.Security.Credentials.KeyCredentialManager` with credential name `co.0w0.mairu`:
- `create`: `RequestCreateAsync(…, FailIfExists)` creates the key, then prints the base64 SubjectPublicKeyInfo of the public key.
- `public-key`: `OpenAsync` the existing key, then print its public key.
- `sign`: read base64 bytes on stdin, `OpenAsync`, then `RequestSignAsync`, which shows the Windows Hello dialog. Print the base64 signature.

The client locates the helper through its own unprotected configuration: `config.json` `windows_hello_helper`, default `$(wslpath "$(cmd.exe /c echo %LOCALAPPDATA%)")/mairu/mairu-windows-hello.exe`. A replaced helper can trigger prompts, but cannot forge a signature.

**Registration.**
1. `mairu policy enroll-windows-hello` runs `create` (or `public-key` if the key already exists).
2. It prints the entry to add to `authorization.json` `windows_hello_keys` (§9.5).
3. The user approves the new policy as usual.

**Challenge and verification.** This is the same flow as §6.2, with `AuthorizationChallenge.method = "windows-hello"`:

1. The client pipes the `statement` bytes to `sign` through WSL interop, and retries with `windows_hello_signature`.
2. The agent verifies the signature over the statement bytes with the registered key: RSA-2048 with SHA-256. Microsoft's documentation contradicts itself on the padding ("PKCS #1 RSA PSS"), so the scheme is **Q-W2** ([hardening §8](hardening.md)). Implementation fixes it empirically and pins it with a test vector.
3. Windows Hello itself requires the PIN or biometric, so a valid signature means a verified user.

**Residual risk.** This is the same as ssh-agent:
- Same-user code (Windows-side, or Linux-side through interop) can run its own program against the same key credential and cause a Windows Hello dialog. The human still has to pass it.
- The challenge binds the signature to one request and peer.
- Timing-based phishing remains possible.

On WSL2 with interop enabled, the root path in [hardening §8](hardening.md) dominates anyway.

## 7. What the human sees

While waiting, the client prints context to its terminal through `crate::terminal` (the existing `/dev/tty`-or-stderr writer):

```
:: mairu :: Authorization required: 123456789012/Admin on contoso
:: mairu ::   command: terraform apply
:: mairu ::   cwd:     /home/u/src/infra
:: mairu ::   from:    /dev/pts/3 (zsh, tmux pane)   ai-agent: claude (ancestor)
:: mairu :: Approve in the system dialog.             # or: enter your password below / touch your security key
```

The same keys go into polkit `details`:

- `server`, `role`
- `command`: shell-escaped, truncated to 512 bytes
- `cwd`, `tty`
- `requester`: peer exe path and pid
- `intent`, `ai_agent`

## 8. Revocation: `mairu lock`

`mairu lock` sends `RevokeAuthorizations{SCOPE_ALL}`.

- `--session` limits it to the caller's session identity.
- `--running` also revokes leases, so running `mairu exec` processes prompt again on their next refresh.
- Outstanding ssh-agent challenges are always dropped.

No authorization is required, since this only tightens.

## 9. Protected policy (Cedar)

Authorization policy is written in [Cedar](https://www.cedarpolicy.com/), the policy language behind Amazon Verified Permissions. It is evaluated with the `cedar-policy` crate (4.x, `default-features = false`, since no extension types are used).

The semantics match AWS IAM:
- The default is deny.
- A `forbid` overrides any `permit`.
- A human check is just another condition on the request, like `aws:MultiFactorAuthPresent`.

### 9.1 Files

| File | Content |
|---|---|
| `config_dir()/policy.cedar` | Cedar policies. Only static policies are allowed; templates are rejected. |
| `config_dir()/authorization.json` | Settings that are not policies (§9.5) |

Both are ordinary files the user edits. Only their integrity record lives elsewhere (§9.7). The agent reads them itself; clients never send policy content.

Integrity records are keyed by **uid, never by path**. An agent started with a different `HOME` or `XDG_CONFIG_HOME` reads files whose digest does not match, and ends up in `TAMPERED` → lockdown.

The schema (§9.2) and built-in policies (§9.6) are embedded in the binary. `mairu policy schema` prints the schema for use with Cedar's own tooling (for example `cedar validate --schema`).

### 9.2 Schema (`src/policy/mairu.cedarschema`)

```cedarschema
namespace Mairu {
  // The local Unix user the agent runs for. Entity id: the uid.
  entity User = {
    name: String,
    uid: Long
  };

  // A credential server from servers.d. Entity id: the server id.
  entity Server = {
    url: String
  };

  // An AWS account named by a role. Entity id: the 12-digit account id, shared across servers.
  entity Account;

  // A role on a server. Entity id: "<server id>:<role>".
  // Parents: its Server, and its Account when the role names one.
  entity Role in [Server, Account] = {
    name: String,
    server: Server,
    account_id?: String
  };

  type Presence = {
    // A human check (ssh-agent touch or platform prompt) covers this request.
    verified: Bool,
    // "none"; "request": checked for this very request; "process": the lease of this running
    // `mairu exec`; "session": a grant for this terminal session.
    scope: String,
    // "ssh-agent", "windows-hello" or "platform"; absent when not verified.
    method?: String,
    // Seconds since the covering human check; 0 when not verified.
    age: Long,
    // Seconds since a session grant was last used; 0 for other scopes.
    idle: Long
  };

  action AssumeRole appliesTo {
    principal: [User],
    resource: [Role],
    context: {
      presence: Presence,
      // AI-agent signals (§5).
      ai_agent: Bool,
      ai_agent_names: Set<String>,
      // "tty", "parent" or "none" (§3); tty is the device path when "tty".
      session: String,
      tty?: String,
      // Whether the agent runs hardened ([hardening §4.2](hardening.md)).
      hardened: Bool,
      // Present only on WSL2: whether Windows interop is enabled, which makes root reachable ([hardening §8](hardening.md)).
      wsl_interop?: Bool,
      // Reported by the client: truthful about what it will do, but chosen by whoever runs it (§9.4).
      intent: String,
      exec_command?: String,
      exec_command_line?: String,
      cwd?: String,
      chained_role_arn?: String
    }
  };
}
```

Reference for the context attributes:

| Attribute | Values | Source |
|---|---|---|
| `presence.*` | as commented | agent (§4) |
| `ai_agent`, `ai_agent_names` | names that matched | agent ancestry + client env names |
| `session`, `tty` | `"tty"` `"parent"` `"none"`, `/dev/pts/N` | agent, from the kernel |
| `hardened` | | agent |
| `wsl_interop` | present only on WSL2 | agent ([hardening §8](hardening.md)) |
| `intent` | `"exec"` `"credential-process"` `"unknown"` | client |
| `exec_command` | basename of `argv[0]` | client, `exec` only |
| `exec_command_line` | shell-escaped argv, truncated to 4 KiB | client, `exec` only |
| `cwd` | absolute path | client |
| `chained_role_arn` | ARN | client (`--assume-role`, `.mairu.json`) |

Cedar strings are UTF-8, so non-UTF-8 bytes in paths and argv are replaced with U+FFFD.

The schema may only grow by adding optional attributes, so approved policies stay valid across upgrades. Any other change re-validates them as described in §9.8.

### 9.3 Entities and request

For each evaluation the agent builds:

- **principal**: `Mairu::User::"<uid>"` with `name` (from `getpwuid`) and `uid`.
- **action**: `Mairu::Action::"AssumeRole"`.
- **resource**: `Mairu::Role::"<server id>:<role>"` with `name`, `server` and `account_id`. Its parents are:
  - `Mairu::Server::"<server id>"` (`url`)
  - `Mairu::Account::"<account id>"`, when the role names an account: an AWS SSO role `^\d{12}/`, or an `arn:aws:iam::\d{12}:role/` ARN.
- **context**: as in the schema, with `presence` set per candidate (§4).

`Request::new(…, Some(&schema))` and `Entities::from_json_value(…, Some(&schema))` check every request against the schema.

Example `policy.cedar`:

```cedar
// Read-only access needs no human check.
@id("readonly-free")
permit (
  principal,
  action == Mairu::Action::"AssumeRole",
  resource == Mairu::Role::"contoso:123456789012/ReadOnly"
);

// Admin: touch the security key for every new command.
// A running `mairu exec` keeps its approval.
@id("admin-touch")
permit (
  principal,
  action == Mairu::Action::"AssumeRole",
  resource == Mairu::Role::"contoso:123456789012/Admin"
) when {
  context.presence.verified &&
  ["request", "process"].contains(context.presence.scope) &&
  context.presence has method && context.presence.method == "ssh-agent"
};

// Everything else on contoso: once per terminal session, 15 minutes idle, 8 hours at most.
@id("contoso-session")
permit (principal, action == Mairu::Action::"AssumeRole", resource in Mairu::Server::"contoso")
when {
  !context.ai_agent &&
  context.presence.verified &&
  context.presence.idle <= 900 &&
  context.presence.age <= 28800
};

// Never hand production to AI agents, on any server.
@id("no-ai-prod")
forbid (principal, action, resource in Mairu::Account::"999999999999")
when { context.ai_agent };
```

### 9.4 Which context can be trusted

- **Determined by the agent**: `presence`, `hardened`, `wsl_interop`, `session`, `tty`, and the ancestry half of `ai_agent`. These cannot be influenced by the requester beyond actually being in that position.
- **Reported by the client**: `intent`, `exec_command`, `exec_command_line`, `cwd`, `chained_role_arn`, and the environment half of `ai_agent`. A verified client reports them truthfully, but whoever runs `mairu` chooses them: same-user code can `cd` into any directory or exec any command. Use them to **narrow** a `permit` that also requires `context.presence.verified`, or in a `forbid`. Never rely on them alone to grant access.

`mairu policy check` and `mairu policy approve` list every `permit` that can apply without a human check, so these are always visible at approval time.

### 9.5 Settings (`authorization.json`)

```jsonc
{
  "version": 1,
  // Order in which to try ways of asking the human for AssumeRole.
  // Default: the key-based methods with registered keys ("ssh-agent", "windows-hello"), then "platform".
  "methods": ["ssh-agent", "platform"],
  // Methods allowed to approve the next policy change (§9.9). Recorded in the approval anchor (§9.7).
  // Default: the key-based methods with registered keys; ["platform"] only when no key is registered.
  "approval_methods": ["ssh-agent"],
  "ssh_agent_keys": [
    {"key": "sk-ssh-ed25519@openssh.com AAAA... me@laptop"},
    {"key": "sk-ecdsa-sha2-nistp256@openssh.com AAAA... spare", "require_user_verification": true},
    {"key": "ssh-ed25519 AAAA... confirm-key", "presence": "unverified-confirm"}
  ],
  "windows_hello_keys": [
    // base64 SubjectPublicKeyInfo (§6.3)
    {"name": "desktop", "public_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."}
  ],
  "ai_agent_detection": {
    "process_names": ["my-agent"],    // added to the built-in list (§5)
    "env_names": ["MY_AGENT_ACTIVE"]  // added to the built-in list (§5)
  },
  "grant_retention_secs": 43200
}
```

- The file is plain JSON; the comments are for documentation only.
- Every field except `version` is optional.
- Unknown fields are rejected, so a typo never silently weakens anything.
- Method names:
  - `"ssh-agent"` (§6.2) and `"windows-hello"` (§6.3), the key-based methods
  - `"platform"`, the platform's own facility: polkit on Linux, LocalAuthentication on macOS

  A policy can require a specific method through `context.presence.method`.
- Putting `"platform"` in `approval_methods` while keys are registered lets a captured password approve a policy that registers someone else's key. `check` warns about it ([hardening §2.4](hardening.md)).

### 9.6 Built-in policies (`src/policy/builtin/*.cedar`)

Used when no approved `policy.cedar` exists. Ids starting with `builtin-` are reserved.

Hardened agent:

```cedar
// Humans: one check per terminal session, remembered for 5 minutes idle, 12 hours at most.
@id("builtin-human-session")
permit (principal, action == Mairu::Action::"AssumeRole", resource)
when {
  !context.ai_agent &&
  context.presence.verified &&
  context.presence.idle <= 300 &&
  context.presence.age <= 43200
};

// AI agents: a human approves every new request; a running `mairu exec` keeps its approval.
@id("builtin-ai-agent-per-request")
permit (principal, action == Mairu::Action::"AssumeRole", resource)
when {
  context.ai_agent &&
  context.presence.verified &&
  ["request", "process"].contains(context.presence.scope)
};
```

Unhardened agent (today's behavior):

```cedar
@id("builtin-unhardened")
permit (principal, action == Mairu::Action::"AssumeRole", resource);
```

Lockdown (§9.8):

```cedar
@id("builtin-lockdown")
permit (principal, action == Mairu::Action::"AssumeRole", resource)
when {
  context.presence.verified &&
  ["request", "process"].contains(context.presence.scope)
};

@id("builtin-lockdown-no-ai")
forbid (principal, action, resource)
when { context.ai_agent };
```

`mairu policy init` writes the hardened built-in policies, with explanatory comments, into `policy.cedar`, plus a minimal `authorization.json`. The user then edits and approves them.

### 9.7 Integrity records

- **Digest**: `SHA-256("mairu.policy.v1\0" || part(policy.cedar) || part(authorization.json))`, where `part(f)` is `0x00` when the file is absent, and `0x01 || u64be(len) || bytes` otherwise.
- **Record**: name `"policy"`, content `IntegrityRecord` ([platform-helper §3](platform-helper.md)): the digest plus the **approval anchor**, which holds the `approval_methods` and the corresponding registered keys from the approved `authorization.json`. Stores serialize it as JSON:

  ```json
  {"version": 1, "digest": "<hex>",
   "approval": {"methods": ["ssh-agent"], "ssh_agent_keys": ["sk-ssh-ed25519@openssh.com AAAA..."], "windows_hello_keys": []}}
  ```

  The anchor lives with the digest so that the next approval is authorized by what was *last approved*, never by whatever the home-directory files say now. Editing `authorization.json`, or tampering with it and forcing lockdown, cannot downgrade approval to a password.
- **Stores** that hold the record, and when each is available, are specified in [platform-helper §7](platform-helper.md). Linux runs two concurrently: the protected directory, which is authoritative on hardened hosts, and Secret Service, which is weak.

### 9.8 Integrity state and effective policy

**Record** (approve) writes the record (digest and approval anchor) to every available store. It fails if none is available.

**Approval anchor in force:**
- Hardened: the protected directory's record. Secret Service is never consulted for it.
- Unhardened: the Secret Service record. This is weak, since same-user code can rewrite it.
- No record (never approved, or reset by root): `["platform"]`.

**Verify** collects per-store statuses, then:

| Situation | State |
|---|---|
| Both files absent and no store has a record | `ABSENT` |
| Any store `MISMATCHED` (including a record existing while both files are absent) | `TAMPERED` |
| Hardened, protected directory `NOT_RECORDED` | `UNAPPROVED`. Re-approve after hardening, whatever Secret Service says. |
| Hardened, protected directory `MATCHED`, Secret Service `NOT_RECORDED` | `APPROVED`, and backfill the Secret Service record |
| Hardened, protected directory `MATCHED`, Secret Service `MATCHED` or `UNAVAILABLE` | `APPROVED` |
| Unhardened, Secret Service `MATCHED` | `APPROVED` |
| Unhardened, Secret Service `NOT_RECORDED` or `UNAVAILABLE` | `UNAPPROVED` |

An `APPROVED` policy that no longer validates against this binary's schema, for example after an upgrade, is treated as `UNAPPROVED`, and the user is warned to re-approve.

**Effective policy:**

| State | Policies | Settings |
|---|---|---|
| `ABSENT` | Built-ins for the hardening state | Defaults |
| `APPROVED` | `policy.cedar`, or the built-ins when only `authorization.json` exists | `authorization.json` |
| `UNAPPROVED` | Built-ins **plus only the `forbid` policies** of `policy.cedar`. Adding a `forbid` can only remove permissions, so unapproved content can only tighten. `permit` policies are ignored. If the file does not parse it is ignored, and `forbid` policies that fail validation are dropped one by one. | Defaults, plus `ai_agent_detection` additions and a smaller `grant_retention_secs` (both tighten). `methods` and keys in the file are ignored, since registering a key relaxes. Key-based methods use only the keys of the approval anchor in force (§9.8), followed by `"platform"`. |
| `TAMPERED` | **Lockdown**: lockdown built-ins plus the file's `forbid` policies (same rules as `UNAPPROVED`) | As `UNAPPROVED`: the keys in the file are not trusted, but the anchored keys are. `doctor` and every client print a warning, and clients emit the lockdown notification ([platform-helper §8.1](platform-helper.md)). |

Verification runs:
- at agent start
- before every authorization decision, cached by `(dev, ino, mtime, size)` of both files plus a 5 s TTL
- after `ApprovePolicy`

Rollback: only the latest digest is kept. Restoring older files plus their record works against Secret Service only; the protected directory, which is authoritative when hardened, does not allow it.

### 9.9 Validation and commands

**Validation** happens at approval, at load, and in `mairu policy check`. A policy file is valid when:
- it parses as a set of **static** Cedar policies
- `Validator::validate(…, ValidationMode::Strict)` against the embedded schema passes; strict mode, for example, requires `has` before an optional attribute
- every `@id` is unique, and none starts with `builtin-`
- `authorization.json` matches §9.5

Policies without `@id` are shown as `policy.cedar#<n>`, and `check` warns about them.

**Commands:**

- `mairu policy init [--force]`: writes the templates (§9.6).
- `mairu policy check`: client-local, no agent involved. Validates both files, lists every policy (id, effect, scope), and flags any `permit` that applies without a human check (§9.4).
- `mairu policy show`: from `GetPolicy`, prints the effective policies and settings, the integrity state, per-store statuses, and notes such as dropped policies.
- `mairu policy explain <server> <role> [--assume-role ARN] [--ai-agent] [--intent exec|credential-process] [--cwd PATH] [--exec CMD]`:
  - Fetches the effective policy through `GetPolicy`.
  - Evaluates it locally for every candidate presence of §4: none, process lease, session grant at a given age and idle time, and fresh per method.
  - Prints each decision with its determining policy ids. This answers "what would happen if…".
- `mairu policy schema`: prints the schema.
- `mairu policy approve`:
  1. The client runs `check`, prints both files and the summary, and computes the digest.
  2. It sends `ApprovePolicy{expected_digest}`.
  3. The agent re-reads both files. If the digest differs → `FAILED_PRECONDITION` ("policy changed while approving"). This binds approval to what the human saw.
  4. The agent validates them → `INVALID_ARGUMENT` on error.
  5. The agent asks the human with action `approve-policy`. This always asks and never uses grants. It uses only the methods and keys of the **approval anchor in force** (§9.8), never those of the files being approved or of the current effective settings. Before any approval, that anchor is `["platform"]`, which is how the first key registration is bootstrapped.
  6. It records the new digest, with the new files' `approval_methods` and keys as the next anchor, into all available stores, and returns the per-store results.

**Recovery.** When every approval key is lost, root removes the record with `sudo mairu harden --reset-policy-record --user <name>`. The state becomes `UNAPPROVED`, and the anchor falls back to `["platform"]`. A stale Secret Service record then reads as `MISMATCHED`, so lockdown applies until the next approval. Requiring root here is deliberate: root is already the top of the trust chain ([hardening §2.4](hardening.md)).

## 10. Agent protocol (`proto/mairu.proto`)

```proto
import "mairu_platform.proto";

service Agent {
  // ... existing RPCs ...
  rpc GetPolicy(GetPolicyRequest) returns (GetPolicyResponse);
  rpc ApprovePolicy(ApprovePolicyRequest) returns (ApprovePolicyResponse);
  rpc RevokeAuthorizations(RevokeAuthorizationsRequest) returns (RevokeAuthorizationsResponse);
}

message PingAgentResponse {
  string version = 1;
  // Lets every client warn about, and notify of, lockdown ([platform-helper §8.1](platform-helper.md)) without an extra RPC.
  PolicyIntegrity policy_integrity = 2;
}

message AssumeRoleRequest {
  string server_id = 1;
  oneof query {
    string role = 2;
    Rolespec rolespec = 4;
  }
  bool cached = 3;
  ClientContext client_context = 5;
}

// What the client is about to do with the credentials. Reported by a verified client, so it can
// be shown to the human as fact.
message ClientContext {
  oneof intent {
    ExecIntent exec = 1;
    CredentialProcessIntent credential_process = 2;
  }
  bytes cwd = 3;
  bytes auto_config_path = 4;      // .mairu.json path when role = auto
  repeated string env_names = 5;   // names only, never values; used for AI-agent markers
  AuthorizationResponse authorization_response = 6;
}

message ExecIntent {
  repeated bytes command = 1;
  string mode = 2;                 // "ecs" | "static"
}

message CredentialProcessIntent {}

message AuthorizationChallenge {
  bytes challenge_id = 1;          // 16 random bytes
  bytes statement = 2;             // serialized AuthorizationStatement; signed byte-for-byte
  // Acceptable registered keys: OpenSSH "SHA256:..." fingerprints for ssh-agent,
  // "wh:SHA256:..." (SHA-256 of the SubjectPublicKeyInfo) for Windows Hello.
  repeated string key_fingerprints = 3;
  google.protobuf.Timestamp expires_at = 4;
  string method = 5;               // "ssh-agent" | "windows-hello"
}

message AuthorizationStatement {
  bytes nonce = 1;                 // 32 random bytes
  bytes agent_instance_id = 2;     // 16 random bytes chosen at agent start
  uint32 peer_pid = 3;
  uint64 peer_start_time = 4;
  string action = 5;               // "assume-role" | "approve-policy"
  string server_id = 6;
  Rolespec rolespec = 7;
  bytes request_digest = 8;        // §4
  google.protobuf.Timestamp expires_at = 9;
}

message AuthorizationResponse {
  bytes challenge_id = 1;
  oneof result {
    bytes sshsig = 2;              // binary SSHSIG blob
    string declined = 3;           // why the client could not sign: "no-ssh-agent", "no-helper", "no-registered-key", "sign-failed"
    bytes windows_hello_signature = 4;  // §6.3
  }
}

// Carried as the binary details of a non-OK tonic::Status (grpc-status-details-bin).
message AuthorizationError {
  enum Reason {
    REASON_UNSPECIFIED = 0;
    REASON_UNVERIFIED_PEER = 1;          // PERMISSION_DENIED
    REASON_DENIED = 2;                   // PERMISSION_DENIED: the human said no or cancelled
    REASON_FORBIDDEN = 3;                // PERMISSION_DENIED: a forbid policy, or disallow_roles
    REASON_NOT_PERMITTED = 4;            // PERMISSION_DENIED: no permit applies, even after a human check
    REASON_UNAVAILABLE = 5;              // FAILED_PRECONDITION: no method could ask the human
    REASON_CHALLENGE = 6;                // FAILED_PRECONDITION: sign `challenge` and retry
    REASON_NO_AUTHENTICATION_AGENT = 7;  // FAILED_PRECONDITION: register pkttyagent and retry
    REASON_INVALID_RESPONSE = 8;         // PERMISSION_DENIED: bad, expired or replayed response
  }
  Reason reason = 1;
  string detail = 2;
  AuthorizationChallenge challenge = 3;
  repeated string policy_ids = 4;        // @id of the determining forbid policies, for REASON_FORBIDDEN
  bool ai_agent = 5;                     // AI-agent signals were present (§5)
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
  string effective_policies = 1;        // Cedar text actually in force (§9.8), built-ins included
  string effective_settings_json = 2;   // authorization.json as in force
  PolicyIntegrity integrity = 3;
  bytes digest = 4;                     // §9.7 digest of the files as read
  repeated mairu.platform.IntegrityStoreResult stores = 5;
  repeated string notes = 6;            // e.g. "dropped forbid policy.cedar#3: validation error …"
}

message ApprovePolicyRequest {
  bytes expected_digest = 1;
  ClientContext client_context = 2;     // only authorization_response and env_names are used
}
message ApprovePolicyResponse {
  PolicyIntegrity integrity = 1;
  repeated mairu.platform.IntegrityStoreResult stores = 2;
}

message RevokeAuthorizationsRequest {
  enum Scope {
    SCOPE_UNSPECIFIED = 0;
    SCOPE_ALL = 1;
    SCOPE_CALLER_SESSION = 2;
  }
  Scope scope = 1;
  bool include_leases = 2;
}
message RevokeAuthorizationsResponse {
  uint32 revoked_grants = 1;
  uint32 revoked_leases = 2;
}
```

`GetAgentStatus` is in [hardening §7](hardening.md); `OpenUrl` and `Notify` are in [platform-helper §8.5](platform-helper.md).

### 10.1 Errors

Every authorization failure is a non-OK status whose binary details hold `AuthorizationError`, with the status code given in the enum comments. Clients decode the details first and fall back to the status message.

Existing codes keep their meanings. In particular, `UNAUTHENTICATED` still means a credential-server login is required.

## 11. Security considerations

| Threat | Mitigation |
|---|---|
| AI agent sharing the user's terminal session | Ancestry + env-name signals in `context.ai_agent`; built-in policy requires a fresh check per AI request (§5, §9.6). Guardrail only. |
| Editing the policy to relax it | Integrity records; only `forbid` policies apply when unapproved; lockdown on tamper (§9.8) |
| Rolling back the policy | The protected directory keeps only the latest record (§9.8) |
| Approval downgraded to a password by editing or tampering with `authorization.json` | Approval uses only the anchor in the last approved record (§9.7, §9.9) |
| A `forbid` silently skipped because its evaluation errors | Strict schema validation; any evaluation error makes the candidate `Deny` (§4, §9.9) |
| A `permit` that relies only on requester-chosen context (`cwd`, `exec_command`, …) | Documented (§9.4); `check` and `approve` list every permit that needs no human check |
| Schema drift after an upgrade | Approved policy re-validated at load; invalid → `UNAPPROVED` (§9.8) |
| Password capture in tmux/tty | Documented ([platform-helper §6.1](platform-helper.md)); key-based methods preferred (§6) |
| Abuse of the forwarded ssh-agent or the Windows Hello credential | Physical touch or Windows Hello required; challenge bound to peer + request; single use; 60 s (§6.2, §6.3) |

Every guarantee here is also bounded by the trust chain in [hardening §2.4](hardening.md).

Logging: authorization decisions go to the agent log at `info` (peer pid, session identity, server, rolespec, method, result, AI signals), never with credentials or signatures.

## 12. Scope

**In scope:** §2–§10, plus the `mairu policy` and `mairu lock` commands. The Windows Hello helper and its open questions (Q-W2, Q-W3 in [hardening §8.5](hardening.md)) need a Windows host with WSL2.

**Out of scope:** the platform facilities themselves ([platform-helper.md](platform-helper.md)), and integrity for `servers.d` and `.mairu.json` trust records ([hardening §13](hardening.md)).

## 13. Deliverables

Layers of the stack in [hardening §14](hardening.md) that implement this spec:

| Layer | Files |
|---|---|
| `hardening/authorization` | `src/authorization.rs` (grants, leases, decision procedure), `src/policy/{mod.rs,mairu.cedarschema,builtin/*.cedar}` (Cedar engine with built-in policies only), `proto/mairu.proto` (`ClientContext`, `AuthorizationError`, `RevokeAuthorizations`), `src/cmd/{exec,credential_process,lock}.rs`, `src/ecs_server.rs`, `Cargo.toml` (`cedar-policy`) |
| `hardening/ai-agents` | `src/authorization.rs` (signals), client `env_names` |
| `hardening/policy` | `src/policy/{files,integrity_state,settings}.rs` (user files, tighten-only and lockdown sets, approval anchor), `proto/mairu.proto` (`GetPolicy`, `ApprovePolicy`, `PingAgentResponse.policy_integrity`), `src/cmd/policy.rs` (`init`, `check`, `show`, `explain`, `schema`, `approve`) |
| `hardening/ssh-agent` | `src/ssh_agent_presence.rs`, `proto/mairu.proto` (challenge messages), client relay, `Cargo.toml` (`ssh-key`, `ssh-encoding`) |
| `hardening/wsl` | `src/windows_hello.rs` (agent verification, client relay), `windows-hello-helper/` (Windows binary, `windows` crate), `src/cmd/policy.rs` (`enroll-windows-hello`), `proto/mairu.proto` (`windows_hello_signature`), `.github/workflows/release.yml` (Windows helper builds) |

## Current Status

Spec drafted; awaiting review before implementation. Implementors MUST keep this section updated as they work.

### Checklist

- [ ] Cedar engine: schema, entities, built-in policies, fail-closed evaluation
- [ ] `Authorizer`: grants, leases, singleflight, decision procedure (§4)
- [ ] Agent RPCs: `ClientContext`, `AuthorizationError`, `GetPolicy`, `ApprovePolicy`, `RevokeAuthorizations`, `PingAgentResponse.policy_integrity`
- [ ] AI-agent signals
- [ ] Policy files: `policy.cedar` + `authorization.json`, integrity states, forbid-only when unapproved, lockdown
- [ ] Approval anchor in integrity records; recovery through `harden --reset-policy-record`
- [ ] ssh-agent presence method
- [ ] Windows Hello method and `mairu-windows-hello.exe`; settle Q-W2 and Q-W3
- [ ] `mairu lock`, `mairu policy init|check|show|explain|schema|approve|enroll-windows-hello`

### Updates

- 2026-10-23: Drafted as part of a single combined spec; redesigned around Cedar, with schema and policies validated with cedar-policy 4.14.0 in strict mode.
- 2026-10-23: Approval anchored in the integrity record; Windows Hello method added.
- 2026-10-23: Split out of the combined spec.
