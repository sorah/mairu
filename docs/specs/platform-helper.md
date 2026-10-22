# Platform abstraction and platform helper

The platform-dependent features of `mairu agent` and its clients behind one Rust trait and one protobuf contract (`mairu.platform`), served in-process or by a mutually verified out-of-process helper, and the Linux backends.

Related specs:

- [hardening.md](hardening.md): threat model, terminology, trust anchors, and the peer verification reused by the helper transport.
- [policy.md](policy.md): when the agent asks the human and what it does with the answer; the integrity records the stores here hold.

## 1. Overview

- The `Platform` trait (§2) and the `mairu.platform` protocol (§3) cover peer inspection, authorization prompts, integrity records, notifications and opening URLs, so the agent core stays platform-independent.
- Linux implements the trait in-process. Platforms where a feature needs a separate identity, such as macOS notifications, which need an app bundle, use a helper process that serves the same protocol. Both directions of that connection are verified (§4).
- In-process backends also verify the system services they call (§5).
- Backends: authorization facilities (§6), integrity stores (§7), and notifications and opening URLs (§8). Notifications and opening URLs carry no security weight, and each client chooses how they are delivered.
- Headless Linux (§9) and WSL2 (§10) are first-class environments. The macOS backends are briefed in §11.

## 2. Rust trait

`src/platform/mod.rs`:

```rust
#[async_trait::async_trait]
pub trait Platform: Send + Sync + std::fmt::Debug {
    fn capabilities(&self) -> crate::proto::platform::Capabilities;

    /// Agent side, at accept time.
    fn inspect_peer(&self, stream: &tokio::net::UnixStream) -> crate::Result<PeerIdentity>;
    /// Client side, right after connect.
    fn verify_agent(&self, stream: &std::os::unix::net::UnixStream) -> crate::Result<AgentTrust>;

    fn session_identity(&self, peer: &PeerIdentity) -> Option<SessionIdentity>;
    fn ancestry(&self, peer: &PeerIdentity) -> Vec<crate::proto::platform::Process>;

    async fn authorize(
        &self,
        req: crate::proto::platform::AuthorizeRequest,
    ) -> crate::proto::platform::AuthorizeResponse;
    async fn notify(&self, req: crate::proto::platform::NotifyRequest) -> crate::proto::platform::NotifyResponse;
    async fn open_url(&self, req: crate::proto::platform::OpenUrlRequest) -> crate::proto::platform::OpenUrlResponse;
    async fn record_integrity(
        &self,
        req: crate::proto::platform::RecordIntegrityRequest,
    ) -> crate::proto::platform::RecordIntegrityResponse;
    async fn verify_integrity(
        &self,
        req: crate::proto::platform::VerifyIntegrityRequest,
    ) -> crate::proto::platform::VerifyIntegrityResponse;
}
```

- `PeerIdentity`: `uid`, `gid`, `pid`, `pidfd: Option<OwnedFd>`, `start_time: u64`, `exe: Option<PathBuf>`, `trust: PeerTrust`.
- `SessionIdentity`: `enum { Tty { sid: i32, leader_start_time: u64 }, Parent { ppid: i32, start_time: u64 } }`.
- `crate::platform::current()` returns, chosen by `cfg` and configuration:
  - `LinuxPlatform`, in-process
  - `RemotePlatform`, the helper client of §4
  - `FallbackPlatform`: macOS and BSD until they are implemented. No verification (`Unverifiable`), authorization `UNAVAILABLE`, no integrity stores, no notifications. `open_url` uses `/usr/bin/open` on macOS.

## 3. Protocol: `proto/mairu_platform.proto`

The types here are the contract. The Linux backend uses them in-process, and an out-of-process helper serves the same messages over gRPC. Enum values are prefixed with the enum name, because proto3 enum values share their package's scope.

```proto
syntax = "proto3";
package mairu.platform;

service PlatformHelper {
  rpc GetCapabilities(GetCapabilitiesRequest) returns (Capabilities);
  rpc Authorize(AuthorizeRequest) returns (AuthorizeResponse);
  rpc Notify(NotifyRequest) returns (NotifyResponse);
  rpc OpenUrl(OpenUrlRequest) returns (OpenUrlResponse);
  rpc RecordIntegrity(RecordIntegrityRequest) returns (RecordIntegrityResponse);
  rpc VerifyIntegrity(VerifyIntegrityRequest) returns (VerifyIntegrityResponse);
}

enum PeerVerification {
  PEER_VERIFICATION_UNSPECIFIED = 0;
  PEER_VERIFICATION_NONE = 1;
  PEER_VERIFICATION_SETGID = 2;
  PEER_VERIFICATION_CODE_SIGNATURE = 3;
}

enum AuthorizationFacility {
  AUTHORIZATION_FACILITY_UNSPECIFIED = 0;
  AUTHORIZATION_FACILITY_NONE = 1;
  AUTHORIZATION_FACILITY_POLKIT = 2;
  AUTHORIZATION_FACILITY_LOCAL_AUTHENTICATION = 3;
}

enum IntegrityStoreKind {
  INTEGRITY_STORE_KIND_UNSPECIFIED = 0;
  INTEGRITY_STORE_KIND_PROTECTED_DIRECTORY = 1;
  INTEGRITY_STORE_KIND_SECRET_SERVICE = 2;
  INTEGRITY_STORE_KIND_SECURE_ENCLAVE = 3;
  INTEGRITY_STORE_KIND_KEYCHAIN = 4;
}

enum IntegrityStatus {
  INTEGRITY_STATUS_UNSPECIFIED = 0;
  INTEGRITY_STATUS_MATCHED = 1;
  INTEGRITY_STATUS_MISMATCHED = 2;
  INTEGRITY_STATUS_NOT_RECORDED = 3;
  INTEGRITY_STATUS_UNAVAILABLE = 4;
}

message GetCapabilitiesRequest {}

message Capabilities {
  PeerVerification peer_verification = 1;
  AuthorizationFacility authorization = 2;
  // Stores reachable right now, in authority order.
  repeated IntegrityStoreKind integrity_stores = 3;
  bool notifications = 4;
  bool open_url = 5;
  // Free-form diagnostics for `mairu doctor`, e.g. "session bus unreachable".
  repeated string notes = 6;
}

message Process {
  uint32 pid = 1;
  // Linux: clock ticks since boot (/proc/<pid>/stat field 22). macOS: microseconds since epoch.
  uint64 start_time = 2;
  uint32 uid = 3;
  bytes executable = 4;
  repeated bytes argv = 5;
  string name = 6;
}

message AuthorizeRequest {
  enum Action {
    ACTION_UNSPECIFIED = 0;
    ACTION_ASSUME_ROLE = 1;
    ACTION_APPROVE_POLICY = 2;
  }
  Action action = 1;
  // The process the human is approving; the polkit subject on Linux.
  Process subject = 2;
  // One line, shown where the facility allows a custom reason.
  string message = 3;
  // Keys: server, role, command, cwd, tty, requester, intent, ai_agent, policy_digest.
  map<string, string> details = 4;
}

message AuthorizeResponse {
  enum Result {
    RESULT_UNSPECIFIED = 0;
    RESULT_ALLOWED = 1;
    RESULT_DENIED = 2;
    RESULT_CANCELLED = 3;
    RESULT_UNAVAILABLE = 4;
  }
  Result result = 1;
  // Machine-readable for UNAVAILABLE: "no-authentication-agent", "polkit-action-not-installed",
  // "polkit-unavailable", "untrusted-authority", "helper-unverified", "timeout".
  string reason = 2;
  string detail = 3;
}

message NotifyRequest {
  enum Urgency {
    URGENCY_UNSPECIFIED = 0;
    URGENCY_LOW = 1;
    URGENCY_NORMAL = 2;
    URGENCY_CRITICAL = 3;
  }
  string title = 1;
  string body = 2;
  Urgency urgency = 3;
  string event = 4;  // "login-required" | "ai-agent-denied" | "policy-lockdown"
}
message NotifyResponse { bool delivered = 1; }

message OpenUrlRequest { string url = 1; }
message OpenUrlResponse { bool opened = 1; string detail = 2; }

// What a store keeps for a name ([policy §9.7](policy.md)).
message IntegrityRecord {
  bytes digest = 1;            // 32 bytes
  ApprovalAnchor approval = 2;
}

// Who may approve the next change: the approval_methods and their keys at the time of approval.
message ApprovalAnchor {
  repeated string methods = 1;             // e.g. "ssh-agent", "windows-hello", "platform"
  repeated string ssh_agent_keys = 2;      // OpenSSH public key lines
  repeated bytes windows_hello_keys = 3;   // DER SubjectPublicKeyInfo
}

message RecordIntegrityRequest {
  string name = 1;   // "policy"
  uint32 uid = 2;
  IntegrityRecord record = 3;
}
message RecordIntegrityResponse { repeated IntegrityStoreResult results = 1; }

message VerifyIntegrityRequest {
  string name = 1;
  uint32 uid = 2;
  bytes digest = 3;
}
message VerifyIntegrityResponse { repeated IntegrityStoreResult results = 1; }

message IntegrityStoreResult {
  IntegrityStoreKind store = 1;
  // For record: MATCHED means written; UNAVAILABLE means skipped.
  IntegrityStatus status = 2;
  string detail = 3;
  IntegrityRecord stored = 4;  // verify: the record the store holds, when it holds one
}
```

Helpers reject requests whose `uid` differs from their own.

## 4. Platform helper transport and mutual verification

An out-of-process helper exists for platforms where a feature needs a separate identity. On macOS, `UNUserNotificationCenter` requires an app bundle, and Secure Enclave keys bound to a keychain access group require entitlements that a bare CLI cannot carry. On Linux the in-process backend is the default; the helper is opt-in and exists to exercise the transport.

Both directions are security-critical:

- A rogue **helper** answering `RESULT_ALLOWED` bypasses authorization, and answering `MATCHED` accepts a forged policy.
- A rogue **caller** of `RecordIntegrity` records a digest of a tampered policy.

Rules:

1. The same trust anchor as client ↔ agent, checked on **both** ends of every connection.
2. **Linux/BSD:**
   1. The agent spawns `/proc/self/exe platform-helper --socket <runtime_dir>/mairu-platform-<agent pid>.sock` via `hardening::command()`. The setgid bit re-applies the marker.
   2. The helper binds and listens inside `with_privileged_gid`.
   3. The helper accepts a connection only if `SO_PEERCRED` shows `uid == own`, `gid == mairu` (when hardened) and **`pid == getppid()`**. It serves exactly one such connection, rejects all others, and exits when the connection closes or the parent dies (`crate::ppid`).
   4. The agent connects inside `with_privileged_gid`, and accepts the helper only if `SO_PEERCRED` shows `uid == own`, `gid == mairu` (when hardened) and **`pid == spawned child pid`**.
   5. On an unhardened Linux system, the checks reduce to uid plus pid pinning.
3. **macOS:**
   - The helper verifies its caller against identifier `co.0w0.mairu` with the same team ID. The agent verifies the helper against identifier `co.0w0.mairu.platform-helper` with its own team ID.
   - Use `xpc_connection_set_peer_code_signing_requirement` / `NSXPCConnection.setCodeSigningRequirement:` when on XPC, or `LOCAL_PEERTOKEN` on a socket. Pin the peer's pid and pid version.
   - Ad-hoc builds need a cdhash pin recorded at install time; §11 settles this.
4. If the helper is unverified, unreachable or crashed, `RemotePlatform` returns `RESULT_UNAVAILABLE` (`helper-unverified`) and empty capabilities. The agent fails closed. It respawns the helper at most once per 30 s.

## 5. Verifying system services (Linux in-process backend)

- **System bus.** When hardened, the agent ignores `DBUS_SYSTEM_BUS_ADDRESS`, which is attacker-controllable environment, and connects to `unix:path=/run/dbus/system_bus_socket`. The socket's parent directory must be root-owned and not group/other-writable.
- **polkit authority.** Before trusting a result, the agent checks that the owner of `org.freedesktop.PolicyKit1` is uid 0 (`org.freedesktop.DBus.GetConnectionUnixUser`). A mismatch maps to `UNAVAILABLE`/`untrusted-authority`.
- **Session bus** services (Secret Service, notifications, the desktop portal) can be claimed by any same-uid process. They are treated as untrusted conveniences, and this is why Secret Service is a secondary integrity store ([policy §9.7](policy.md)).

## 6. Authorization facilities

The `platform` presence method ([policy §6.1](policy.md)) is backed by these.

### 6.1 polkit (Linux)

`pkg/polkit/co.0w0.mairu.policy`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>mairu</vendor>
  <vendor_url>https://github.com/sorah/mairu</vendor_url>
  <action id="co.0w0.mairu.assume-role">
    <description>Provide AWS credentials</description>
    <message>Authentication is required to provide AWS credentials for $(role) on $(server)</message>
    <defaults>
      <allow_any>auth_self</allow_any>
      <allow_inactive>auth_self</allow_inactive>
      <allow_active>auth_self</allow_active>
    </defaults>
  </action>
  <action id="co.0w0.mairu.approve-policy">
    <description>Approve mairu authorization policy</description>
    <message>Authentication is required to approve the mairu authorization policy</message>
    <defaults>
      <allow_any>auth_self</allow_any>
      <allow_inactive>auth_self</allow_inactive>
      <allow_active>auth_self</allow_active>
    </defaults>
  </action>
</policyconfig>
```

- `auth_self` on `allow_any` means SSH and other remote sessions get a prompt rather than a silent "no". `auth_self_keep` is not used; mairu keeps its own grants.
- Check: `CheckAuthorization(subject, action_id, details, flags = AllowUserInteraction, cancellation_id)`.
  - `subject` is `("unix-process", {pid: u32, start-time: u64, uid: i32})` of the **peer** (the sidecar for `exec`), passed with `zbus_polkit` ≥ 5.1 (CVE-2026-78422).
  - `cancellation_id` is unique per check. If the request is dropped, for example because the client disconnected, a drop guard spawns `CancelCheckAuthorization`. The agent's own timeout is 5 min, after which it cancels and returns `CANCELLED`/`timeout`.
- `$(role)`/`$(server)` expand from `details`. Whether a given authentication agent shows the expansion or the other `details` keys varies, so the client terminal always prints the full context too ([policy §7](policy.md)). Confirm the expansion against polkit 127 during implementation.
- Result mapping. The exact signals for "no agent" and "dismissed" must be confirmed empirically on polkit 127 and pinned with a test; this table is the contract.

  | polkit outcome | `AuthorizeResponse` |
  |---|---|
  | `is_authorized` | `ALLOWED` |
  | not authorized, details `polkit.dismissed` | `CANCELLED` |
  | not authorized, `is_challenge`, no authentication agent for the subject | `UNAVAILABLE`/`no-authentication-agent` |
  | not authorized otherwise (wrong password, …) | `DENIED` |
  | `Error.Failed` "action … not registered" | `UNAVAILABLE`/`polkit-action-not-installed` |
  | system bus or authority unreachable | `UNAVAILABLE`/`polkit-unavailable` |
  | authority owner uid ≠ 0 | `UNAVAILABLE`/`untrusted-authority` |

- polkit evaluates `allow_*` from the subject's logind session. A tmux server keeps the session of the SSH login that started it, even after that login ends. Because the subject is a `unix-process` and the fallback agent below registers for that same process, prompting works regardless of the logind session's state.

**Headless fallback: `pkttyagent`.** On `REASON_NO_AUTHENTICATION_AGENT` the client (`src/polkit_tty_agent.rs`) does the following:

1. Check it can prompt: `/dev/tty` must open. Otherwise it fails with guidance; no tty means no prompt, as with an AI agent's non-interactive shell.
2. Locate `/usr/bin/pkttyagent`, a **fixed path** that must be root-owned and not group/other-writable. `PATH` is attacker-controlled, and a fake agent would receive the password.
3. Spawn `/usr/bin/pkttyagent --process <own pid>,<own start_time> --fallback --notify-fd 3` via `hardening::command()`, with stdio on `/dev/tty`. Wait up to 5 s for fd 3 to close, which means the agent is registered.
4. Print the context ([policy §7](policy.md)), then retry the RPC once.
5. Send `SIGTERM` to `pkttyagent` when the RPC returns.

The process that spawns `pkttyagent` is the one making the RPC, so polkit's subject and the registered agent are the same process. For `exec` that is the sidecar.

**Risk documented for users:** same-user code can capture a password typed at a tty prompt and replay it later. The echo is off, so output capture such as `pipe-pane -O` or `capture-pane` does not see it. Input capture does:

- reading the pane's pty concurrently
- tmux key bindings installed through the server socket
- a fake prompt written to the pty first
- ptrace of the terminal path when `kernel.yama.ptrace_scope = 0`

This is the same exposure as `sudo`'s prompt in the same pane, and `auth_self` asks for the same login password. So on a host where the user types the sudo password into tmux, same-user code can already become root, which defeats everything here ([hardening §2.2](hardening.md)). The mairu prompt adds more opportunities, not a new kind of exposure. Prefer ssh-agent presence ([policy §6.2](policy.md)). For `sudo` itself, the analogous fix is FIDO-backed PAM: `pam_u2f` locally, or `pam_ssh_agent_auth` with an `sk-` key over SSH.

### 6.2 LocalAuthentication (macOS)

Briefed in §11.

## 7. Integrity stores

The stores hold the `IntegrityRecord` (§3) of [policy §9.7](policy.md): a digest plus the approval anchor. The state machine that interprets their answers is [policy §9.8](policy.md).

- **Linux stores**, used **concurrently** (§3 `IntegrityStoreKind`):

  | Store | Available when | Location | Strength |
  |---|---|---|---|
  | `PROTECTED_DIRECTORY` | Agent hardened, and `/var/lib/mairu` is `root:mairu`, mode `2770` with no "other" bits, not FUSE | `/var/lib/mairu/users/<uid>/policy.record` (the record JSON of [policy §9.7](policy.md)), written atomically (temp + rename + fsync) inside `with_privileged_gid` | Strong: unreachable by same-user code. Authoritative when present. |
  | `SECRET_SERVICE` | Session bus reachable, `org.freedesktop.secrets` present, default collection unlocked. A locked collection is `UNAVAILABLE`; the agent never triggers an unlock prompt. | Item in the default collection: label `mairu policy record (uid N)`, attributes `{application: "co.0w0.mairu", kind: "policy-record", name: "policy", uid: "N"}`, secret = the record JSON | Weak: same-user code can read and write it. It catches offline or careless edits, and on hardened hosts any disagreement with the protected directory. |

- **macOS stores** are briefed in §11.

## 8. Convenience features: notifications and opening URLs

These carry no security weight. Nothing relies on a notification being seen or a URL being opened, and the URLs involved are not secret (PKCE and `state` protect the code flow). They are therefore chosen **per client**, from unprotected settings, and can be redirected or switched off freely. Terminal output and printed URLs never depend on these settings.

### 8.1 Who emits what

Emission always happens in a client, never on the agent's own initiative, so every notification follows the client's choice.

| Event | Emitted by | Limit |
|---|---|---|
| Open the authorize URL (`verification_uri_complete` for the device code grant) | `mairu login`, including the login inside `mairu exec` | once per login |
| Login required | `mairu exec` sidecar (ECS backend and auto-refresh) when the agent returns `UNAUTHENTICATED` | once per server per 10 min |
| AI-agent request refused | The client that receives `REASON_FORBIDDEN` or `REASON_NOT_PERMITTED` with `ai_agent = true` | once per (server, rolespec) per minute |
| Policy lockdown | Any client whose `PingAgent` reports `POLICY_INTEGRITY_TAMPERED` ([policy §10](policy.md)) | once per agent instance |

Rate-limit state is best-effort: one file per event key under `runtime_dir()/notified/`, compared by mtime.

### 8.2 Modes

`open_url` and `notify` each take one of:

| Mode | Behavior |
|---|---|
| `auto` (default) | On WSL2 with interop, use the Windows side (§10). Otherwise `local` when the client looks graphical (`WAYLAND_DISPLAY` or `DISPLAY` set, and `SSH_CONNECTION`/`SSH_TTY` unset), and `none` if not. |
| `local` | The client's own backend, `crate::platform::current()` (§8.4) |
| `agent` | Ask the agent through the `OpenUrl`/`Notify` RPCs (§8.5). The agent uses its own backend, which may be the platform helper (§4). Useful when the agent has a desktop session the client lacks, and on macOS where notifications need the helper app. |
| `command` | Run a different helper program supplied by the user (§8.3) |
| `none` | Disabled |

A failure in any mode is logged at debug level and otherwise ignored.

### 8.3 Configuration

Precedence: command-line flag, then environment, then `config.json`, then `auto`.

- `config.json` (`UserConfig`, unprotected):

  ```jsonc
  {
    "open_url": {"mode": "command", "command": ["my-open-url"]},
    "notify": {"mode": "agent"}
  }
  ```

  `command` is an argv array, required when `mode` is `command`.
- Environment:
  - `MAIRU_OPEN_URL` / `MAIRU_NOTIFY` set the mode: `auto|local|agent|command|none`.
  - `MAIRU_OPEN_URL_COMMAND` / `MAIRU_NOTIFY_COMMAND` hold a shell command line, run as `/bin/sh -c '<value> "$@"' mairu <args…>`. Setting one implies `command` mode.
- Flags: `--no-browser` on `mairu login` and `mairu exec` means `open_url = none`.

The helper command interface:

- `open_url`: argv is `command + [url]`.
- `notify`: argv is `command + [title, body]`, plus the environment variables `MAIRU_NOTIFY_URGENCY` (`low|normal|critical`) and `MAIRU_NOTIFY_EVENT` (`login-required|ai-agent-denied|policy-lockdown`).
- The command is spawned through `hardening::command()`, which drops the marker gid, with stdin set to `/dev/null`. It isn't waited on for more than 5 s, and is reaped in the background.

The README gives examples: a `notify-send` wrapper, and for tmux over SSH, a script that forwards the URL to the local machine or calls `tmux display-message`.

### 8.4 Backends (`local` and `agent` modes)

- **Linux notifications**:
  - `org.freedesktop.Notifications.Notify` on the session bus (`app_name = "mairu"`, urgency hint).
  - The address comes from `DBUS_SESSION_BUS_ADDRESS`, falling back to `unix:path=$XDG_RUNTIME_DIR/bus` when that exists.
  - Headless (no bus, or no notification daemon): `notifications = false`, and calls are no-ops.
- **Linux open URL**: `org.freedesktop.portal.OpenURI.OpenURI("", url, {})`, falling back to `xdg-open` via `hardening::command()`. A `PATH` lookup is acceptable here.
- **macOS**: [hardening §9](hardening.md).
- **Fallback**: `/usr/bin/open` on macOS, otherwise unavailable.

Every mode passes on only `http`/`https` URLs, so a URL can never reach `file://` or a custom-scheme handler. Notification title and body are truncated to 256 and 1024 bytes.

### 8.5 Agent RPCs

```proto
service Agent {
  rpc OpenUrl(mairu.platform.OpenUrlRequest) returns (mairu.platform.OpenUrlResponse);
  rpc Notify(mairu.platform.NotifyRequest) returns (mairu.platform.NotifyResponse);
}
```

Both need only a trusted peer ([hardening §5.1](hardening.md)), never authorization, and apply the URL and length rules of §8.4.

## 9. Headless Linux

The reference workflow is long-lived **tmux sessions on a remote host, reached over SSH**.

| Capability | GUI session | SSH + tmux | No session bus | No polkitd |
|---|---|---|---|---|
| Peer verification | ✓ | ✓ | ✓ | ✓ |
| ssh-agent presence | ✓ (if agent has an sk key) | ✓ (forwarded agent) | ✓ | ✓ |
| polkit prompt | GUI agent | `pkttyagent` in the pane (§6.1) | ✓ (system bus) | ✗ → `UNAVAILABLE` |
| Integrity: protected directory | ✓ (hardened) | ✓ (hardened) | ✓ (hardened) | ✓ (hardened) |
| Integrity: Secret Service | usually ✓ | usually ✗ | ✗ | — |
| Notifications, `auto` mode (§8.2) | ✓ | ✗ (no-op) | ✗ | — |
| Open URL, `auto` mode (§8.2) | ✓ | ✗ (URL printed) | ✗ | — |
| Notifications / open URL, `command` mode | as configured | as configured (e.g. forward to the local machine) | as configured | as configured |

**Fails closed:**
- A role that requires a prompt when no method can ask: no ssh-agent key and polkit unavailable, or no tty for `pkttyagent`.

**Degrades:**
- Notifications and open-url fall back to terminal output only. Users can point them at their own helper (§8.3).
- Secret Service. On hardened hosts the protected directory carries integrity alone. On unhardened headless hosts there is no store, so the policy is `UNAPPROVED` and only tightens.

**Admin guidance** (README):
- polkit's PAM stack (`/etc/pam.d/polkit-1`) can use `pam_fprintd` or `pam_u2f` on local machines.
- For SSH, the ssh-agent method is preferred, because a FIDO key on the local machine cannot be reached through PAM on the remote host.

## 10. WSL2

Profiles, interop and the root path are in [hardening §8](hardening.md). Platform-specific behavior inside a WSL2 distribution:

- **`open_url`.** On WSL2 with interop, `auto` (§8.2) resolves to `wslview` when installed, otherwise `explorer.exe` located through `wslpath`, started via `hardening::command()`. This takes precedence over WSLg's `DISPLAY`/`WAYLAND_DISPLAY`, since the Linux side usually has no browser.
- **`notify`.** `auto` resolves to `none`; `command` mode with a Windows toast helper is the documented option.
- **Authorization facility.** WSL2 normally has no polkit agent, so the `pkttyagent` fallback (§6.1) applies. The key-based methods ([policy §6](policy.md)) are preferred.
- **Integrity stores.** Secret Service is usually absent, so hardened distributions rely on the protected directory alone.
- **Q-W5** ([hardening §8.5](hardening.md)): how WSLg should influence `auto` modes beyond this.

## 11. macOS backends (implemented separately)

Together with [hardening §9](hardening.md), this is the brief for the macOS implementation. Items marked **Q** must be settled there and written back into these specs.

1. **Authorization.**
   - `LAContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason:)`, with the reason built from [policy §7](policy.md), run in the agent or helper.
   - Track lid/clamshell state (Touch ID unavailable) and fall back to password.
   - **Q:** whether to use a Secure Enclave key gated by `.userPresence` so the result is cryptographic rather than boolean. Optional, because the agent enforcing the result is itself protected.
   - Over SSH there is no UI, so the ssh-agent method ([policy §6.2](policy.md)) applies unchanged.
2. **Integrity store.** **Q:** choose between:
   - (a) a Keychain generic-password item holding the record, with an ACL restricted to mairu's code requirement, or
   - (b) a Secure Enclave P-256 key (`kSecAttrTokenIDSecureEnclave`) signing the digest, with the signature in `$HOME` and the latest record also kept in the Keychain to prevent rollback.

   Option (b) needs `keychain-access-groups`, which likely means an app bundle and a provisioning profile, i.e. the helper. Report the result through `IntegrityStoreKind` `KEYCHAIN` / `SECURE_ENCLAVE`. Whatever the choice, the store must hold the whole `IntegrityRecord`, including the approval anchor, where same-user code cannot rewrite it.
3. **Notifications.** `UNUserNotificationCenter` requires a bundle, so expect `Mairu Helper.app` (`co.0w0.mairu.platform-helper`) serving `PlatformHelper` with mutual verification (§4). **Q:** launched by the agent (`open -a` / LaunchServices) or as a LaunchAgent with XPC.
4. **Open URL.** `NSWorkspace` or `/usr/bin/open`, in the user's GUI session.
5. **AI-agent ancestry** ([policy §5](policy.md)). The same rules, using `proc_pidinfo` (process facts in [hardening §9](hardening.md)).

## 12. Security considerations

| Threat | Mitigation |
|---|---|
| Rogue platform helper or rogue helper caller | Mutual verification with pid pinning; fail closed (§4) |
| Fake polkit, D-Bus or `pkttyagent` | System bus path pinned; authority uid 0; fixed `/usr/bin/pkttyagent` with ownership check (§5, §6.1) |
| Password capture at a tty prompt | Documented (§6.1); key-based methods preferred ([policy §6](policy.md)) |
| Secret Service read or rewritten by same-user code | Secondary store; the protected directory is authoritative when hardened (§7) |
| Spoofed, redirected or suppressed notifications and URL opening | Not relied on for security; unprotected client settings by design. Helpers run with the marker dropped and receive only `http`/`https` URLs (§8). |

## 13. Scope

**In scope (Linux):** §2–§10, plus the hidden `mairu platform-helper` command.

**Out of scope, and future work:**
- macOS backends and helper app (§11)
- Agent-initiated login with browser opening
- Linux hosts without polkitd: prompts are `UNAVAILABLE` there, so roles that require a platform prompt fail closed, while key-based methods and `forbid` policies still work

## 14. Deliverables

Layers of the stack in [hardening §14](hardening.md) that implement this spec:

| Layer | Files |
|---|---|
| `hardening/peer-verification` | `src/platform/{mod,fallback}.rs`, `src/platform/linux/{mod,procfs,peer}.rs`, `proto/mairu_platform.proto`, `build.rs`, `src/proto.rs` |
| `hardening/authorization` | `src/platform/linux/polkit.rs`, `pkg/polkit/co.0w0.mairu.policy`, `Cargo.toml` (`zbus`, `zbus_polkit`, deb asset) |
| `hardening/headless` | `src/polkit_tty_agent.rs`, client retry paths, `src/cmd/doctor.rs` |
| `hardening/policy` | `src/platform/linux/integrity.rs`, `Cargo.toml` (Secret Service crate) |
| `hardening/wsl` | `src/platform/linux/wsl.rs` (Windows-side `open_url`) |
| `hardening/notify` | `src/convenience.rs` (mode resolution, helper commands, rate limits), `src/config.rs` (`UserConfig.open_url`, `UserConfig.notify`), `src/platform/linux/{notify,open_url}.rs`, `proto/mairu.proto` (`OpenUrl`, `Notify`), `src/agent.rs`, `src/cmd/{login,exec}.rs` (`--no-browser`, event emission) |
| `hardening/platform-helper` | `src/platform/remote.rs`, `src/cmd/platform_helper.rs` |

## Current Status

Spec drafted; awaiting review before implementation. Implementors MUST keep this section updated as they work.

### Checklist

Linux:
- [ ] `mairu.platform` proto and `Platform` trait
- [ ] polkit backend and policy file; system bus and authority checks
- [ ] `pkttyagent` fallback
- [ ] Protected-directory and Secret Service integrity stores
- [ ] Notifications and open-url: backends, client-chosen modes (`auto|local|agent|command|none`), agent `OpenUrl`/`Notify` RPCs
- [ ] WSL2: Windows-side `open_url`; settle Q-W5
- [ ] Platform helper with mutual verification

macOS (separate implementation, §11):
- [ ] Settle the Q items in §11 and write them back here
- [ ] LocalAuthentication backend
- [ ] Integrity store
- [ ] Helper app with mutual verification

### Updates

- 2026-10-23: Drafted as part of a single combined spec; notifications and URL opening moved to client-side emission with client-chosen modes.
- 2026-10-23: Split out of the combined spec.
