# Platform abstraction and platform helper

The platform-dependent code of mairu: process primitives that every process runs for itself, and platform services that always run in a separate platform helper process, which shares the agent's lifetime and is mutually verified with it, behind one protobuf contract (`mairu.platform`); plus the Linux backends.

Related specs:

- [hardening.md](hardening.md): threat model, terminology, trust anchors, and the peer verification reused by the helper transport.
- [policy.md](policy.md): when the agent asks the human and what it does with the answer; the integrity records the stores here hold.

Each section opens with a short visual summary. It is illustrative; the text after it is normative.

## 1. Overview

```mermaid
flowchart LR
  C["mairu client<br/>process primitives · presence relays"] -- "one connection" --> A["mairu agent<br/>tokens · policy · process primitives"]
  A -- "inherited socketpair<br/>shared lifetime, verified both ways" --> H["mairu platform-helper<br/>authorize · integrity stores · notify · open_url"]
```

```text
src/platform/
├── mod.rs        # ProcessPlatform and PlatformServices traits, PeerIdentity, SessionIdentity
├── process/      # in-process primitives per OS: linux (procfs, peer, wsl detection), fallback
├── helper.rs     # HelperClient: the agent's only PlatformServices, over the socketpair
└── services/     # backends that run only inside the helper: linux (polkit, integrity, notify, open_url, wsl), fallback
```

Platform-dependent code lives in four places, each with one home:

| Kind | Runs in | Examples | Trust |
|---|---|---|---|
| Process primitives | Every mairu process, in-process, never remoted | marker gid, peer credentials (`inspect_peer`, `verify_agent`), process facts, safe spawning | Part of the process's own trust |
| Platform services | **Only the platform helper**, on every OS | `authorize` (polkit, LocalAuthentication), integrity stores, `notify`, `open_url` | Verified both ways with the agent (§4) |
| Presence relays | The client | `pkttyagent` registration (§6.1), ssh-agent signing and the Windows Hello helper ([policy §6](policy.md)) | Untrusted by design: the agent trusts only polkitd's own answer or a verified signature |
| Convenience commands | The client | user `command` helpers for `notify` and `open_url` (§8) | No security weight |

- **The agent never runs platform-service code.** The process that holds session tokens contains no D-Bus client, Secret Service, notification, desktop portal or LocalAuthentication code paths at run time. A bug reached through those surfaces lands in the helper, which holds no tokens.
- **One code path.** The agent reaches every service through `HelperClient` (§2), always over IPC, with no in-process/IPC branching, on every OS.
- **Clients make one connection**, to the agent. They reach services only through agent RPCs (`AssumeRole`, `ApprovePolicy`, `OpenUrl`, `Notify`, …), never directly.
- **The helper shares the agent's lifetime** (§4): the agent spawns it, talks to it over an inherited socketpair, and the helper exits when the agent goes away.
- **Packaging does not matter.** The helper is `mairu platform-helper`, the same binary, by default. A separately signed executable, inside an app bundle or not, can serve the same protocol under the same checks, and nothing else in these specs changes. On macOS the helper is always such an executable, inside an app bundle installed from the single binary. Notifications need a bundle on every build, and Developer ID builds also need one for the data-protection keychain entitlement (§7, §11).
- Inside the helper, the Linux backends verify the system services they call (§5).
- Backends: authorization facilities (§6), integrity stores (§7), and notifications and opening URLs (§8). Notifications and opening URLs carry no security weight, and each client chooses how they are delivered.
- Headless Linux (§9) and WSL2 (§10) are first-class environments. The macOS backends are briefed in §11.

## 2. Rust traits

```text
agent accept                → ProcessPlatform::inspect_peer               in-process
client connect              → ProcessPlatform::verify_agent               in-process
Authorizer (policy.md)      → ProcessPlatform::session_identity, ancestry in-process
                            → PlatformServices::authorize                 helper
policy approval             → PlatformServices::record/verify_integrity   helper
OpenUrl / Notify RPCs (§8)  → PlatformServices::open_url, notify          helper
```

`src/platform/mod.rs`:

```rust
/// Runs in-process in every mairu process; never remoted.
pub trait ProcessPlatform: Send + Sync + std::fmt::Debug {
    /// Agent side, at accept time.
    fn inspect_peer(&self, stream: &tokio::net::UnixStream) -> crate::Result<PeerIdentity>;
    /// Client side, right after connect.
    fn verify_agent(&self, stream: &std::os::unix::net::UnixStream) -> crate::Result<AgentTrust>;

    fn session_identity(&self, peer: &PeerIdentity) -> Option<SessionIdentity>;
    fn ancestry(&self, peer: &PeerIdentity) -> Vec<crate::proto::platform::Process>;
}

/// The `PlatformHelper` contract (§3) as a trait. The agent only holds `HelperClient`;
/// the backends that implement it run inside the platform helper.
#[async_trait::async_trait]
pub trait PlatformServices: Send + Sync + std::fmt::Debug {
    async fn capabilities(&self) -> crate::proto::platform::Capabilities;

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
- `crate::platform::process()` returns the `ProcessPlatform` for the OS, chosen by `cfg`:
  - `LinuxProcess`
  - `FallbackProcess`: macOS and BSD until they are implemented. No verification (`Unverifiable`).
- The agent's `PlatformServices` is always `HelperClient` (§4). When the helper is unavailable, every call returns `RESULT_UNAVAILABLE` (`helper-unavailable` or `helper-unverified`) and capabilities are empty, so the agent fails closed.
- Inside the helper, `crate::platform::services()` returns the backend, chosen by `cfg`:
  - `LinuxServices` (§5–§8, §10)
  - `FallbackServices`: macOS and BSD until they are implemented. Authorization `UNAVAILABLE`, no integrity stores, no notifications. `open_url` uses `/usr/bin/open` on macOS.
- Clients never construct a `PlatformServices`.

## 3. Protocol: `proto/mairu_platform.proto`

```text
mairu.platform.PlatformHelper
├── GetCapabilities  → {peer_verification, authorization, integrity_stores, notifications, open_url, notes}
├── Authorize        → ALLOWED | DENIED | CANCELLED | UNAVAILABLE(reason)
├── Notify, OpenUrl                     # carry the client's SessionHint
└── RecordIntegrity, VerifyIntegrity, ResetIntegrity   # IntegrityRecord = generation + digest + ApprovalAnchor
```

The types here are the contract. The platform helper serves them over gRPC on the inherited socketpair (§4), and the agent is its only client. Enum values are prefixed with the enum name, because proto3 enum values share their package's scope.

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
  rpc ResetIntegrity(ResetIntegrityRequest) returns (ResetIntegrityResponse);
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

// Strong: PROTECTED_DIRECTORY, DATA_PROTECTION_KEYCHAIN. Weak: SECRET_SERVICE, LEGACY_KEYCHAIN (§7).
enum IntegrityStoreKind {
  INTEGRITY_STORE_KIND_UNSPECIFIED = 0;
  INTEGRITY_STORE_KIND_PROTECTED_DIRECTORY = 1;
  INTEGRITY_STORE_KIND_SECRET_SERVICE = 2;
  INTEGRITY_STORE_KIND_DATA_PROTECTION_KEYCHAIN = 3;
  INTEGRITY_STORE_KIND_LEGACY_KEYCHAIN = 4;
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
  // "polkit-unavailable", "untrusted-authority", "helper-unavailable", "helper-unverified", "timeout".
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
  SessionHint session = 5;
}
message NotifyResponse { bool delivered = 1; }

message OpenUrlRequest {
  string url = 1;
  SessionHint session = 2;
}
message OpenUrlResponse { bool opened = 1; string detail = 2; }

// The requesting client's desktop session, passed through by the agent (§8.4).
message SessionHint {
  string display = 1;                   // $DISPLAY
  string wayland_display = 2;           // $WAYLAND_DISPLAY
  string dbus_session_bus_address = 3;  // honored only as unix:path= under $XDG_RUNTIME_DIR
  bool ssh = 4;                         // $SSH_CONNECTION or $SSH_TTY was set
}

// What a store keeps for a name ([policy §9.7](policy.md)).
message IntegrityRecord {
  bytes digest = 1;            // 32 bytes
  ApprovalAnchor approval = 2;
  uint64 generation = 3;       // orders the records of strong stores ([policy §9.8](policy.md))
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

// macOS only: asks for an administrator authorization, then removes the record from every strong store.
message ResetIntegrityRequest {
  string name = 1;
  uint32 uid = 2;
}
message ResetIntegrityResponse { repeated IntegrityStoreResult results = 1; }

message IntegrityStoreResult {
  IntegrityStoreKind store = 1;
  // For record: MATCHED means written; UNAVAILABLE means skipped.
  IntegrityStatus status = 2;
  string detail = 3;
  IntegrityRecord stored = 4;  // verify: the record the store holds, when it holds one
}
```

Helpers reject requests whose `uid` differs from their own.

## 4. Platform helper process and mutual verification

```mermaid
sequenceDiagram
  participant A as agent
  participant H as mairu platform-helper
  A->>A: socketpair() while holding egid=mairu
  A->>H: spawn own image with one end inherited (setgid re-applies)
  H->>H: fd peer creds: same uid, gid mairu, pid equals getppid()
  A->>A: helper is the child it exec'd, keep its pidfd
  A->>H: GetCapabilities
  Note over A,H: EOF → helper exits · helper gone → agent fails closed and respawns
```

The helper is a separate process on every OS. It holds no tokens, and the agent never runs platform-service code itself (§1).

Both directions are security-critical:

- A rogue **helper** answering `RESULT_ALLOWED` bypasses authorization, and answering `MATCHED` accepts a forged policy.
- A rogue **caller** of `RecordIntegrity` records a digest of a tampered policy.

Rules:

1. **Spawn.** At startup, before serving clients, the agent:
   1. creates a `socketpair(AF_UNIX, SOCK_STREAM)` inside `with_privileged_gid`, so the credentials the kernel records for the pair carry the marker gid;
   2. spawns its own image (`/proc/self/exe platform-helper --fd <n>` on Linux) via `hardening::command()`, with that end as the only inherited fd. The setgid bit re-applies the marker, which the helper needs for the protected directory (§7);
   3. closes its copy of the helper's end.

   There is no rendezvous in the filesystem, so there is nothing to squat. The helper runs from the setgid binary, so it is non-dumpable and its fd cannot be taken over through `/proc`.
2. **The helper verifies the agent** before serving: `SO_PEERCRED` of the inherited fd must show `uid == own`, `gid == mairu` (when hardened) and **`pid == getppid()`**. On a socketpair the kernel reports the creator of the pair, which is the agent. The helper serves only that fd and exits on EOF, which is how it shares the agent's fate. `crate::ppid` remains a backstop.
3. **The agent verifies the helper by construction:** it exec'd its own image and keeps the child's pidfd. A socketpair reports its creator to both ends, so `SO_PEERCRED` cannot identify the helper, and the agent does not need it to.
4. Both ends reject requests whose `uid` differs from their own (§3).
5. **Failure.** If the helper fails verification, exits or crashes, `HelperClient` returns `RESULT_UNAVAILABLE` (`helper-unavailable` or `helper-unverified`) and empty capabilities, and the agent fails closed. It respawns the helper at most once per 30 s. `GetAgentStatus` reports the helper's state ([hardening §7.1](hardening.md)).
6. **Unhardened Linux:** the checks reduce to uid plus pid pinning.
7. **macOS:** the same process model, with the same binary (§11). The agent and the helper therefore have the same designated requirement: team-based for Developer ID builds, cdhash for ad-hoc ones ([hardening §9.1](hardening.md)). Each checks the other against its own requirement, as clients and the agent do.
   - **Q-M1 (confirmed).** On a socketpair whose end is inherited across fork and exec:
     - Before any I/O, both ends report the creator (`LOCAL_PEERPID`, `LOCAL_PEERTOKEN` with its pid version, and `LOCAL_PEERCRED`).
     - Once the child does I/O, the creator's end reports the child, by the last-I/O rule ([hardening §3.2](hardening.md)). The child's end keeps reporting the creator.
     - After the child exits, the token query fails with `EINVAL`, while `LOCAL_PEERCRED` still works.

     So the helper checks `token.pid == getppid()` and `SecCodeCheckValidity` on that token before serving. The agent keeps "trusted by construction" plus pid pinning as its primary check, because a later token query on its end still follows the last I/O.
   - **The helper bundle** (§11) is a separately signed executable on every macOS build.
     - **The helper verifies its parent** as above: `token.pid == getppid()`, the hardened runtime, and identifier `co.0w0.mairu`. Beyond that:
       - official builds: the helper's own team ID and version;
       - assembled bundles: the cdhash recorded in its own signed `Info.plist` as `MairuAgentCDHash`.
     - **"Trusted by construction" is not enough on the agent's side,** because the bundle may sit in a user-writable directory and be swapped between any check and the exec. So the agent:
       1. spawns it with the socketpair, exactly as above;
       2. before sending anything, checks the running child: `SecCodeCopyGuestWithAttributes` with the child's pid, which cannot be reused while the agent has not reaped it, then `SecCodeCheckValidity` against the flavour's identifier (§11) and the hardened runtime. Beyond that:
          - official builds: the agent's own team ID, plus a `CFBundleShortVersionString` equal to the agent's own version;
          - assembled bundles: the cdhash the agent expects (§11).

          This check is confirmed for ad-hoc builds from `gui/<uid>`, Background and SSH parents (Q-M13).
       3. if that fails, kills it and runs the unbundled `mairu platform-helper` instead. That helper cannot post notifications, and it reports the data-protection keychain `UNAVAILABLE`, so a policy approved only there falls back to tighten-only ([policy §9.8](policy.md)). A failure never relaxes anything.

## 5. Verifying system services (Linux helper backends)

```text
system bus   hardened: ignore $DBUS_SYSTEM_BUS_ADDRESS → /run/dbus/system_bus_socket (root-owned dir)
polkit       GetConnectionUnixUser("org.freedesktop.PolicyKit1") == 0, else untrusted-authority
session bus  Secret Service, notifications, portal: claimable by same uid → never trusted alone
```

- **System bus.** When hardened, the helper ignores `DBUS_SYSTEM_BUS_ADDRESS`, which is attacker-controllable environment, and connects to `unix:path=/run/dbus/system_bus_socket`. The socket's parent directory must be root-owned and not group/other-writable.
- **polkit authority.** Before trusting a result, the helper checks that the owner of `org.freedesktop.PolicyKit1` is uid 0 (`org.freedesktop.DBus.GetConnectionUnixUser`). A mismatch maps to `UNAVAILABLE`/`untrusted-authority`.
- **Session bus** services (Secret Service, notifications, the desktop portal) can be claimed by any same-uid process. They are treated as untrusted conveniences, and this is why Secret Service is a secondary integrity store ([policy §9.7](policy.md)).

## 6. Authorization facilities

```mermaid
sequenceDiagram
  participant C as client in a tmux pane
  participant A as agent
  participant H as platform helper
  participant P as polkitd
  C->>A: AssumeRole
  A->>H: Authorize(subject C)
  H->>P: CheckAuthorization(unix-process C, co.0w0.mairu.assume-role)
  P-->>H: not authorized, no authentication agent
  H-->>A: UNAVAILABLE no-authentication-agent
  A-->>C: NO_AUTHENTICATION_AGENT
  C->>C: spawn /usr/bin/pkttyagent --process C --fallback
  C->>A: AssumeRole again
  A->>H: Authorize(subject C)
  H->>P: CheckAuthorization
  P->>C: password prompt in this pane, via pkttyagent
  P-->>H: authorized
  H-->>A: ALLOWED
```

The `platform` presence method ([policy §6.1](policy.md)) is backed by these. They run in the platform helper (§4), which talks to polkitd or LocalAuthentication on the agent's behalf.

### 6.1 polkit (Linux)

```text
CheckAuthorization(unix-process{pid, start-time, uid}, action, details, AllowUserInteraction)
  authorized                          → ALLOWED
  dismissed                           → CANCELLED
  challenge, no agent for the subject → UNAVAILABLE no-authentication-agent  (client: pkttyagent, retry)
  action not registered               → UNAVAILABLE polkit-action-not-installed
  bus unreachable / owner uid ≠ 0     → UNAVAILABLE polkit-unavailable / untrusted-authority
```

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
  - `cancellation_id` is unique per check. If the request is dropped, for example because the client disconnected, the agent cancels its `Authorize` call, and a drop guard in the helper spawns `CancelCheckAuthorization`. The helper's own timeout is 5 min, after which it cancels and returns `CANCELLED`/`timeout`.
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

This is the same exposure as `sudo`'s prompt in the same pane, and `auth_self` asks for the same login password. So on a host where the user types the sudo password into tmux, same-user code can already become root, which defeats everything here ([hardening §2.2](hardening.md)). The mairu prompt adds more opportunities, not a new kind of exposure. Prefer ssh-agent presence ([policy §6.2](policy.md)). For `sudo` itself, the analogous fix is PAM backed by a key: `pam_u2f` locally, or `pam_ssh_agent_auth` with an approval-protected key over SSH.

### 6.2 LocalAuthentication (macOS)

```text
LAContext.evaluatePolicy(.deviceOwnerAuthentication, reason) → ALLOWED / DENIED     in the helper (§11)
```

Briefed in §11.

## 7. Integrity stores

```text
record "policy" = {generation, digest, approval anchor}
strong   writable only by a genuine helper · counts as approval · anchor source
├── protected directory        Linux and macOS, after harden
└── data-protection keychain   macOS Developer ID builds, through the helper bundle (§11)
weak     writable by any process of the user · catches careless edits · approves only on unhardened agents
├── Secret Service item        Linux, when reachable
└── legacy keychain item       macOS
```

The stores hold the `IntegrityRecord` (§3) of [policy §9.7](policy.md): a generation, a digest and the approval anchor. Every available store is written on approval. The state machine that interprets their answers, including how strong and weak stores combine, is [policy §9.8](policy.md).

- **Linux stores**, used **concurrently** (§3 `IntegrityStoreKind`):

  | Store | Available when | Location | Strength |
  |---|---|---|---|
  | `PROTECTED_DIRECTORY` | Helper hardened (it inherits the marker through the setgid exec, §4), and `/var/lib/mairu` is `root:mairu`, mode `2770` with no "other" bits, not FUSE | `/var/lib/mairu/users/<uid>/policy.record` (the record JSON of [policy §9.7](policy.md)), written atomically (temp + rename + fsync) by the helper inside `with_privileged_gid` | Strong: unreachable by same-user code. Authoritative when present. |
  | `SECRET_SERVICE` | Session bus reachable, `org.freedesktop.secrets` present, default collection unlocked. A locked collection is `UNAVAILABLE`; the helper never triggers an unlock prompt. | Item in the default collection: label `mairu policy record (uid N)`, attributes `{application: "co.0w0.mairu", kind: "policy-record", name: "policy", uid: "N"}`, secret = the record JSON | Weak: same-user code can read and write it. It catches offline or careless edits, and on hardened hosts any disagreement with the protected directory. |

- **macOS stores** (§11), used concurrently: the protected directory after `harden` (strong, every tier), the data-protection keychain through the helper bundle (strong, Developer ID builds), and a legacy keychain item (weak).

## 8. Convenience features: notifications and opening URLs

```text
mode = --no-browser ?? $MAIRU_OPEN_URL ?? config.json open_url ?? auto
auto      → agent
agent     OpenUrl / Notify RPC → agent → platform helper, with the client's SessionHint
command   your helper program, run by the client
none      terminal output only
```

These carry no security weight. Nothing relies on a notification being seen or a URL being opened, and the URLs involved are not secret (PKCE and `state` protect the code flow). They are therefore chosen **per client**, from unprotected settings, and can be redirected or switched off freely. Terminal output and printed URLs never depend on these settings.

### 8.1 Who emits what

```text
mairu login                    → open the authorize URL
exec sidecar, UNAUTHENTICATED  → "login required"            once / server / 10 min
refused AI-agent request       → "AI-agent request refused"  once / (server, rolespec) / min
PingAgent says TAMPERED        → "policy lockdown"           once / agent instance
```

Emission always happens in a client, never on the agent's own initiative, so every notification follows the client's choice.

| Event | Emitted by | Limit |
|---|---|---|
| Open the authorize URL (`verification_uri_complete` for the device code grant) | `mairu login`, including the login inside `mairu exec` | once per login |
| Login required | `mairu exec` sidecar (ECS backend and auto-refresh) when the agent returns `UNAUTHENTICATED` | once per server per 10 min |
| AI-agent request refused | The client that receives `REASON_FORBIDDEN` or `REASON_NOT_PERMITTED` with `ai_agent = true` | once per (server, rolespec) per minute |
| Policy lockdown | Any client whose `PingAgent` reports `POLICY_INTEGRITY_TAMPERED` ([policy §10](policy.md)) | once per agent instance |

Rate-limit state is best-effort: one file per event key under `runtime_dir()/notified/`, compared by mtime.

### 8.2 Modes

```text
per feature (open_url, notify):   auto | agent | command | none
```

`open_url` and `notify` each take one of:

| Mode | Behavior |
|---|---|
| `auto` (default) | For `open_url`: `$BROWSER` in the client's environment, run in `command` mode, when it is set. Otherwise `agent`. For `notify`: `agent`. |
| `agent` | Ask the agent through the `OpenUrl`/`Notify` RPCs (§8.5). The agent passes the request, with the client's `SessionHint`, to the platform helper, whose backend (§8.4) decides where to deliver it. The helper delivers to the client's desktop session when the hint names one, even if the agent was started elsewhere. It reports `opened`/`delivered = false`, rather than using some other session, when the hint shows SSH without a display, or no display at all. On WSL2 with interop it uses the Windows side (§10). |
| `command` | Run a different helper program supplied by the user (§8.3) |
| `none` | Disabled |

A failure in any mode is logged at debug level and otherwise ignored.

### 8.3 Configuration

```text
--no-browser  >  MAIRU_OPEN_URL / MAIRU_NOTIFY (+ *_COMMAND)  >  config.json  >  auto
helper argv   open_url → command + [url]
              notify   → command + [title, body], env MAIRU_NOTIFY_{URGENCY,EVENT}
```

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
  - `MAIRU_OPEN_URL` / `MAIRU_NOTIFY` set the mode: `auto|agent|command|none`.
  - `MAIRU_OPEN_URL_COMMAND` / `MAIRU_NOTIFY_COMMAND` hold a shell command line, run as `/bin/sh -c '<value> "$@"' mairu <args…>`. Setting one implies `command` mode.
- Flags: `--no-browser` on `mairu login` and `mairu exec` means `open_url = none`.

The helper command interface:

- `open_url`: argv is `command + [url]`.
- `notify`: argv is `command + [title, body]`, plus the environment variables `MAIRU_NOTIFY_URGENCY` (`low|normal|critical`) and `MAIRU_NOTIFY_EVENT` (`login-required|ai-agent-denied|policy-lockdown`).
- The command is spawned through `hardening::command()`, which drops the marker gid, with stdin set to `/dev/null`. It isn't waited on for more than 5 s, and is reaped in the background.

The README gives examples: a `notify-send` wrapper, and for tmux over SSH, a script that forwards the URL to the local machine or calls `tmux display-message`.

### 8.4 Backends (in the platform helper)

```text
notify     org.freedesktop.Notifications on the session bus · no bus or daemon → no-op
open_url   portal OpenURI → xdg-open · http/https only · title/body truncated
```

- **Session hint.** The client fills `SessionHint` from its own environment, and the agent passes it through unchanged. The values are requester-chosen, which is acceptable because these features carry no security weight. The helper honors `dbus_session_bus_address` only as `unix:path=` under the user's `$XDG_RUNTIME_DIR`, so a hint cannot point it at an arbitrary socket or a TCP address.
- **Linux notifications**:
  - `org.freedesktop.Notifications.Notify` on the session bus (`app_name = "mairu"`, urgency hint).
  - The address comes from the hint's `dbus_session_bus_address` when honored, otherwise the helper's `DBUS_SESSION_BUS_ADDRESS`, falling back to `unix:path=$XDG_RUNTIME_DIR/bus` when that exists.
  - Headless (no bus, or no notification daemon): `notifications = false`, and calls are no-ops.
- **Linux open URL**: `org.freedesktop.portal.OpenURI.OpenURI("", url, {})` on that bus, falling back to `xdg-open` via `hardening::command()` with `DISPLAY`/`WAYLAND_DISPLAY` from the hint. A `PATH` lookup is acceptable here.
- **macOS**: notifications from the helper bundle itself, URLs through `/usr/bin/open` (§11).
- **Fallback**: `/usr/bin/open` on macOS, otherwise unavailable.

Every mode passes on only `http`/`https` URLs, so a URL can never reach `file://` or a custom-scheme handler. Notification title and body are truncated to 256 and 1024 bytes.

### 8.5 Agent RPCs

```text
client ──OpenUrl / Notify + SessionHint──► agent ──► platform helper backend
trusted peer only · never authorization · same URL and length rules
```

```proto
service Agent {
  rpc OpenUrl(mairu.platform.OpenUrlRequest) returns (mairu.platform.OpenUrlResponse);
  rpc Notify(mairu.platform.NotifyRequest) returns (mairu.platform.NotifyResponse);
}
```

Both need only a trusted peer ([hardening §5.1](hardening.md)), never authorization. The agent applies the URL and length rules of §8.4 before forwarding to the helper, which applies them again.

## 9. Headless Linux

```mermaid
flowchart LR
  laptop["laptop: ssh-agent<br/>(its own lock)"] -- "ssh -A" --> host["remote host"]
  host --> pane["tmux pane<br/>(own session)"]
  pane --> mairu["mairu exec"]
  mairu -- "challenge" --> sock["forwarded $SSH_AUTH_SOCK"]
  sock --> laptop
  mairu -. "fallback" .-> pk["pkttyagent password<br/>in the pane"]
```

The reference workflow is long-lived **tmux sessions on a remote host, reached over SSH**.

| Capability | GUI session | SSH + tmux | No session bus | No polkitd |
|---|---|---|---|---|
| Peer verification | ✓ | ✓ | ✓ | ✓ |
| ssh-agent presence | ✓ (registered key in your agent) | ✓ (forwarded agent) | ✓ | ✓ |
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
- For SSH, the ssh-agent method is preferred: it reaches your local SSH agent, under whatever lock it applies, which PAM on the remote host cannot.

## 10. WSL2

```text
WSL2 + interop   open_url → rundll32.exe url.dll,FileProtocolHandler (explorer.exe fallback)
                 notify   → command (Windows toast helper)        auth → windows-hello, pkttyagent
WSL2 isolated    open_url → printed   notify → terminal only      auth → ssh -A from Windows
```

Profiles, interop and the root path are in [hardening §8](hardening.md). Platform-specific behavior inside a WSL2 distribution, measured on Windows 11 25H2 with WSLg 1.0.79 (Q-W5):

- **What WSLg provides.** `DISPLAY=:0`, `WAYLAND_DISPLAY=wayland-0` and a session bus. It provides no Linux browser, no `xdg-open`, and no `org.freedesktop.Notifications` owner, and `wslview` (wslu) is not installed by default. WSLg's display variables therefore never select a Linux-side backend.
- **`open_url`.** With interop on, the helper's backend opens the URL in the Windows default browser:
  1. `rundll32.exe url.dll,FileProtocolHandler <url>`, which exits 0 on success.
  2. `explorer.exe <url>` as the fallback. Its exit status is 1 even on success, so it is ignored.

  Both are located through `wslpath` and started via `hardening::command()`. The URL is passed as its own argv element, never through `cmd.exe /c start`, which mangles `&`. The helper runs in the same distribution as the agent, so it has interop whenever the agent does. WSL forwards localhost, so a loopback OAuth redirect listener in WSL is reachable from the Windows browser.
- **`notify`.** The helper has no WSL2 notification backend: the D-Bus backend applies only when `org.freedesktop.Notifications` has an owner, and WSLg provides none. `agent` mode reports `delivered = false`, and terminal output always remains. `command` mode with a Windows toast helper is the documented option.
- **`$BROWSER`.** When the client's environment sets it, `auto` honors it for `open_url` (§8.2), which also covers users who installed `wslview`.
- **Isolated profile (interop off).** URLs are printed and notifications stay on the terminal.
- **Authorization facility.** WSL2 normally has no polkit agent, so the `pkttyagent` fallback (§6.1) applies. The key-based methods ([policy §6](policy.md)) are preferred.
- **Integrity stores.** Secret Service is usually absent, so hardened distributions rely on the protected directory alone.

## 11. macOS backends (implemented separately)

```mermaid
flowchart LR
  A["mairu agent"] -- "inherited socketpair<br/>verified both ways" --> H["Mairu Helper.app<br/>embedded (official) or assembled"]
  H --> LA["LocalAuthentication<br/>(Touch ID, password)"]
  H --> KC["data-protection keychain<br/>(Developer ID) · legacy keychain"]
  H --> PD["protected directory<br/>(after harden)"]
  H --> OP["/usr/bin/open"]
  H --> UN["UNUserNotificationCenter"]
```

Together with [hardening §9](hardening.md), this is the brief for the macOS implementation. Items marked **Q** must be settled there and written back into these specs.

On macOS the platform helper always runs from an app bundle, `Mairu Helper.app` (item 3). Official builds embed it, signed with the Developer ID. Other builds assemble it from their own binary and sign it ad-hoc. Everything below runs in the helper process, never in the agent (§1, §4).

1. **Authorization.**
   - `LAContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason:)`, with the reason built from [policy §7](policy.md). It works from a plain binary, signed ad-hoc or with a Developer ID.
   - Track lid/clamshell state (Touch ID unavailable) and fall back to password.
   - `LAError -4` ("system authentication is running", for example while the screen is locked) maps to `UNAVAILABLE`, which can be retried.
   - **Secure Enclave `.userPresence` keys are not used** (tested). An unentitled binary can create one as a CryptoKit `dataRepresentation` blob. But any other binary that reads the blob can sign with it after Touch ID, under its own prompt text. A signature would then prove that someone was present at this Mac, not that mairu asked. Permanent keys need an entitlement (`-34018`). The helper that reports the `LAContext` result is itself verified (§4), so a boolean result is enough.
   - **Where the sheet appears.** coreauthd shows it on the console whenever a GUI session exists, even for a process outside that session (confirmed for a Background job and from an SSH session). With no GUI session it is `UNAVAILABLE`.
     - A request from an SSH session therefore prompts on the Mac's screen, not in the terminal. This is allowed by default, with the origin in the reason text, and a policy can forbid it ([policy §7](policy.md)).
     - The agent decides the origin, not the client: it looks up the session of the peer's audit token (`audit_token_to_asid`, then `SessionGetInfo`). `context.console_session` is true when that session has graphic access and is not remote. Confirm those session attributes for SSH logins during implementation.
     - The ssh-agent method ([policy §6.2](policy.md)) is the one that reaches a remote user.
   - **Q-M2 (addressed):** the agent runs as a LaunchAgent in `gui/<uid>` whenever a GUI login exists ([hardening §9.2](hardening.md)), and its helper inherits that session. LocalAuthentication works from either launchd domain, and from an SSH session, while a GUI session exists (confirmed), but the administrator dialog needs `gui/<uid>`.
2. **Integrity store.**
   - **The legacy keychain provides no integrity** (confirmed on macOS 27.2). Same-user code deleted an item with `security delete-generic-password` and no prompt. An unrelated unsigned binary then created a new item with the same service and account, whose access list trusts only mairu, holding forged content. mairu read it without a prompt, and the planted access list is indistinguishable from a genuine one. This applies to any requirement, team-based or cdhash. A MAC key kept in the keychain does not help either, because both items can be deleted and planted again. A legacy keychain item (`LEGACY_KEYCHAIN`) is therefore a **weak** store, like Secret Service on Linux: it catches careless edits only. The record is not secret, so the item's access list allows every application, which avoids prompts after ad-hoc rebuilds.
   - **Strong store for Developer ID builds: the data-protection keychain, through the helper bundle.**

     ```text
     Mairu Helper.app/Contents/MacOS/mairu-platform-helper   identifier co.0w0.mairu.platform-helper
       entitlement   keychain-access-groups = [<TEAMID>.co.0w0.mairu]
       profile       Contents/embedded.provisionprofile (Developer ID, App ID co.0w0.mairu.platform-helper)
     item            generic password · service co.0w0.mairu.policy-record · account <record name>
                     access group <TEAMID>.co.0w0.mairu · kSecUseDataProtectionKeychain
                     kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly · not synchronizable
     ```

     - Only code signed by the team with that entitlement can read, write or delete the item. Same-user code can neither remove nor plant it, so the record is strong without root.
     - From an unbundled, unentitled binary, `SecItemAdd` fails with `-34018` (confirmed). macOS grants `keychain-access-groups` only through a provisioning profile, and only an executable inside an app bundle can carry one. That is why this helper is a bundle.
     - Ad-hoc builds cannot hold the entitlement. A third-party Developer ID build can, with a profile for its own team.
     - This is the helper bundle of item 3. On official builds, it is signed with the entitlement and the profile.
     - After `harden`, the agent runs the root-owned copy, whose executable is setgid `mairu` ([hardening §9.5](hardening.md)).
     - The agent execs it directly, not through LaunchServices, so the socketpair is inherited. It is verified as a running child (§4).
     - A Secure Enclave key signing the record would add nothing, since it would sit behind the same access group.
     - **Q-M12**, deferred until the Developer ID is issued, then confirmed on the first official build. If part 1 fails, the agent runs the unbundled helper (§4), and Developer ID builds rely on `harden` alone, like ad-hoc builds. The parts:
       1. a restricted entitlement with an embedded profile is honored when the bundle's executable is exec'd directly by a non-LaunchServices parent, also with the setgid bit set;
       2. the item is reachable from the helper of the LaunchAgent-run agent, and from an SSH-only login (Q-M11);
       3. the item survives an upgrade of the bundle (same team, same access group);
       4. `AuthorizationCopyRights` for `system.privilege.admin` works from the helper, for `ResetIntegrity` ([policy §9.9](policy.md)). Confirmed for an unbundled ad-hoc binary: the dialog appears from a terminal and from a `gui/<uid>` LaunchAgent, and a Background job or an SSH session gets `-60007` at once, with no dialog on the console.
   - **Strong store for every tier: the protected directory through `harden`** ([hardening §9.5](hardening.md); Q-M6, Q-M9). `LOCAL_PEERCRED` reports the effective gid as `cr_groups[0]` (confirmed), so the Linux marker group carries over.
     - A setgid exec by a user **outside** the group makes a restricted process: `P_SUGID` set, `DYLD_INSERT_LIBRARIES` stripped, same-user `task_for_pid` refused (confirmed, [hardening §9.5](hardening.md)).
     - A **member** of the group gets the egid without the restriction: `P_SUGID` was 0, `DYLD_INSERT_LIBRARIES` was honoured, and `task_for_pid` worked. Hence the "user must not be a member" rule ([hardening §3.1](hardening.md)).
   - Stores by tier:

     | Tier | Strong | Weak |
     |---|---|---|
     | Developer ID with the helper bundle (official) | data-protection keychain; also the protected directory after `harden` | legacy keychain |
     | Ad-hoc, or Developer ID without a helper bundle | the protected directory after `harden` | legacy keychain |
     | Unhardened (no runtime flag) | none | legacy keychain, which approves here as on unhardened Linux |

     A hardened build without a strong store never has an approved policy, so its policy only tightens ([policy §9.8](policy.md)).
   - Every store holds the whole `IntegrityRecord`, including the approval anchor.
3. **The helper bundle, and notifications.**

   ```text
   official builds (Developer ID, embedded)
     extract   <base>/helper-<version>/Mairu Helper.app          byte-exact from MAIRU_HELPER_ARCHIVE
     check     SecStaticCodeCheckValidity: own team, identifier, CFBundleShortVersionString == own version
   other builds (ad-hoc, or Developer ID without an embedded bundle)
     assemble  <base>/helper-<version>-<own cdhash, 12 hex>/Mairu Helper.app
               Contents/Info.plist (MairuAgentCDHash = own cdhash)
               Contents/Resources/mairu.icns (embedded bytes)
               Contents/MacOS/mairu = clonefile(own binary)
     sign      /usr/bin/codesign --force --sign - --options runtime --identifier <flavour id>
   both
     write a temporary sibling directory, check it, rename it into place; never modify a bundle in place
     strip com.apple.quarantine from what mairu wrote
     register  lsregister -f <bundle>, as the user, before the first exec of that path
     spawn     <exe> --fd <n> (official) · mairu platform-helper --fd <n> (assembled)   direct exec, §4
     verify    the running child (§4)
     cleanup   unused for 30 days → lsregister -u, remove; at most 5 per flavour; never the running one
   each notification
     UNUserNotificationCenter add, from the helper; no NSApplication, no delegate, no actions
   started without --fd (a click relaunch by LaunchServices)
     exit 0 at once
   fallback (bundle unusable)
     the unbundled helper: osascript display notification, else delivered = false
   ```

   `<base>` is `~/Library/Application Support/mairu`, or `~/Library/Application Support/mairu-dev` for the dev profile ([hardening §15.1](hardening.md)).

   - **One bundle (Q-M13, confirmed 2026-10-24).** `UNUserNotificationCenter` needs the main executable of a signed bundle that LaunchServices has registered. It does not need a LaunchServices launch. The helper is therefore one bundle that posts notifications itself, on every build, and on Developer ID builds it also holds the keychain entitlement (item 2).
   - **Official builds** embed the bundle that the release pipeline built from the dedicated target `mairu-platform-helper` (objc2, UserNotifications, LocalAuthentication, and the helper code), then signed with the Developer ID, notarized and stapled ([hardening §9.4](hardening.md)).
     - The executable cannot be a copy of mairu, which would then have to embed itself. A single `mairu` binary remains the only artifact.
     - `MAIRU_HELPER_ARCHIVE` is a `tar` of the signed, stapled bundle that keeps modes and symlinks. It is embedded with `include_bytes!`, so mairu's own signature covers it.
   - **Other builds** assemble the bundle from their own binary, which runs as `mairu platform-helper`, and sign it ad-hoc.
     - `MairuAgentCDHash` in the signed `Info.plist` lets the helper verify its parent (§4).
     - Ad-hoc signing is deterministic (confirmed), so the same input always gives the same cdhash.
     - The directory carries the agent's own cdhash, because rebuilds keep the version but change the binary.
     - The agent records the cdhash of the bundle it assembled. Before using one that another process assembled, it checks that the executable and `Info.plist` are byte-identical to what it would write and that the signature is valid, then takes that bundle's cdhash.
     - These bundles carry no keychain entitlement (item 2).
   - **Flavours.** Each sets `LSUIElement` true and an icon, plus a `CFBundleIdentifier` and display name of its own:
     - official builds: `co.0w0.mairu.platform-helper`, shown as `mairu`
     - other builds: `co.0w0.mairu.platform-helper.adhoc`, shown as `mairu (ad-hoc)`
     - the dev profile: `co.0w0.mairu.dev.platform-helper`, shown as `mairu (dev)` ([hardening §15.1](hardening.md))

     Separate identifiers keep LaunchServices from resolving to another flavour's copy, and keep their rows in System Settings apart.
   - **Who writes it.**
     - The agent extracts or assembles the bundle at startup, before spawning the helper.
     - `harden` writes its root-owned copy directly into `/usr/local/libexec/mairu/`, from its own archive or by assembling and signing it as root, with no user-writable intermediate ([hardening §9.5](hardening.md)). The agent prefers that copy and registers it as the user.
     - Concurrent agents or `harden` runs each write their own temporary directory. If the target appeared meanwhile, the later writer discards its copy and checks the existing one.
   - **Extraction rules:**
     - **Byte-exact, never in place.** Since macOS Ventura, Gatekeeper checks notarized apps on every launch, and any modification makes the app show as damaged. App Management may also block a process signed by another team from modifying a notarized bundle. Each version and flavour therefore gets a fresh directory.
     - **Quarantine.** Unsandboxed tools don't quarantine the files they create by default. A process that inherited quarantine, for example one started from a terminal inside a quarantined GUI app, may get every file it writes quarantined. mairu therefore removes `com.apple.quarantine` from the bundle it wrote. Files written by a quarantined, user-approved CLI, and by its child, carried no quarantine (confirmed).
     - **Location.** Bundles under temporary directories are rejected ("Failed to find or validate client"), and a bundle under `~/Library/Application Support` registers (confirmed). An unsigned arm64 bundle does not launch at all.
     - **Registration.** A directly exec'd bundle executable gets "Notifications are not allowed" until the bundle is registered with `lsregister -f`. lsd's own automatic registration is not enough (confirmed). `open` registers as a side effect, which is why the earlier tests did not see this.
   - **Notifications.**
     - The helper posts with `UNUserNotificationCenter`. Posting needs neither `NSApplication` nor a run loop, since completion handlers run on a background queue (confirmed).
     - They appear on the console whether the agent runs in `gui/<uid>` or `user/<uid>`, or was started over SSH (confirmed).
   - **Clicks.**
     - Notifications carry no actions, and the helper sets no delegate.
     - A click makes LaunchServices start the bundle, even while the helper runs, because a process without `NSApplication` is not LaunchServices' running instance. That instance has no arguments and no `--fd`, its parent is `launchd`, and `XPC_SERVICE_NAME` starts with `application.` (confirmed).
     - It exits at once with status 0, before touching anything else. Click actions would need `NSApplication` in that instance, and are out of scope.
   - **Authorization status.**
     - The helper reads `getNotificationSettings` into `Capabilities.notes`.
     - While notifications are not authorized, `notify` reports `delivered = false`. `doctor` and the first undelivered notification tell the user to turn on "mairu" in System Settings → Notifications.
     - mairu does not route around a denial with `osascript`. That fallback is only for an unusable bundle.
   - **Q-M3 (confirmed for ad-hoc builds).** Tested on macOS 27.2 with the screen unlocked:
     - A registered ad-hoc bundle appears in System Settings → Notifications, whether launched through `open` or exec'd directly.
     - It starts out denied, before any request. `requestAuthorization` returns `UNErrorDomain` 1 with no prompt, with or without the runtime flag and `LSUIElement`. Once the user turns on "Allow notifications" in System Settings, it is authorized.
     - Whether that default comes from macOS 27 for apps without a team, or from this MDM-managed host, is unknown. It is not pursued, since no unmanaged Mac is available and the status handling above covers both.
     - The Developer ID flavour is deferred until the identity is issued.
   - **Q-M4 (confirmed): the permission survives upgrades.**
     - It is keyed by bundle id, not by cdhash. After the binary changed, both a fresh directory and an in-place rewrite stayed authorized with no user action.
     - The grant also outlives the bundle. After the bundle was deleted and unregistered, a new bundle with the same id at a new path came up authorized.
     - Any same-user bundle claiming the id inherits the permission and can post as "mairu". Notifications carry no security weight, and such a bundle never passes the running-child check (§4).
   - **Q-M5 (settled 2026-10-23): name, icon and cleanup.**
     - Display names (`CFBundleName`, `CFBundleDisplayName`) differ per flavour, as listed above. System Settings shows each bundle id as its own row, and rows with identical names cannot be told apart.
     - The icon is `pkg/macos/mairu.icns` (`CFBundleIconFile`). Without one, the row shows a blank icon.
     - Cleanup is as in the block above. Each bundle directory's mtime is touched on every spawn.
4. **Open URL.** `NSWorkspace` or `/usr/bin/open`, in the user's GUI session.
5. **AI-agent ancestry** ([policy §5](policy.md)). The same rules, using `proc_pidinfo` (process facts in [hardening §9.6](hardening.md)). This is a process primitive in the agent, not a helper service.

## 12. Security considerations

```text
rogue helper or helper caller    ✗ inherited socketpair, parent checked, child by construction, fail closed
bug via D-Bus / portal / keychain ✗ runs in the helper, which holds no tokens
fake polkit / bus / pkttyagent   ✗ pinned bus path, authority uid 0, fixed /usr/bin/pkttyagent
Secret Service rewritten         ! weak store; protected directory is authoritative
spoofed notifications / URLs     · no security weight by design
```

| Threat | Mitigation |
|---|---|
| Lending a connected fd to a genuine signed process on macOS, so its audit token stands in for the attacker | Clients reach the agent over XPC, where every message carries its sender's audit token ([hardening §9.2](hardening.md)). The helper's socketpair ends exist only inside hardened-runtime processes (§4). |
| Deleting or forging a legacy keychain item on macOS | Weak by design: it never approves on hardened builds. Strong stores are the helper bundle's data-protection keychain and the protected directory through `harden` (§7, §11). |
| Swapping the extracted or assembled helper bundle (macOS) | The agent checks the running child's code before use. On failure it runs the unbundled helper, which loses notifications and the data-protection keychain, so policy only tightens (§4). |
| Rogue platform helper or rogue helper caller | Inherited socketpair with no filesystem rendezvous; the helper checks its parent's credentials, and the agent trusts the child it exec'd; fail closed (§4) |
| A bug reached through D-Bus, Secret Service, notification, portal or LocalAuthentication code | Platform services run only in the helper, which holds no tokens (§1) |
| Session-bus input (notification daemon, desktop portal, Secret Service) reaching the same helper that answers `Authorize` and the protected directory | Accepted: one helper process by design (simpler process model). Session-bus replies are handled through typed zbus proxies and treated as untrusted. A bug there could forge helper answers, so that code is kept minimal and reviewed as security-sensitive. |
| A same-user bundle claiming the helper's bundle id (macOS) | It inherits the notification permission and can post as "mairu", which carries no security weight. It never passes the running-child check (§4, §11). |
| A notification click starting the helper bundle (macOS) | That instance has no `--fd` and exits at once (§11). |
| Fake polkit, D-Bus or `pkttyagent` | System bus path pinned; authority uid 0; fixed `/usr/bin/pkttyagent` with ownership check (§5, §6.1) |
| Password capture at a tty prompt | Documented (§6.1); key-based methods preferred ([policy §6](policy.md)) |
| Secret Service read or rewritten by same-user code | Secondary store; the protected directory is authoritative when hardened (§7) |
| Spoofed, redirected or suppressed notifications and URL opening | Not relied on for security; unprotected client settings by design. Helpers run with the marker dropped and receive only `http`/`https` URLs (§8). |

## 13. Scope

```text
in    trait · protocol · helper · polkit + pkttyagent · integrity stores · notify / open_url · headless · WSL2
out   macOS backends · agent-initiated login · hosts without polkitd (prompting roles fail closed)
```

**In scope (Linux):** §2–§10, plus the hidden `mairu platform-helper` command.

**Out of scope, and future work:**
- macOS backends (§11)
- Agent-initiated login with browser opening
- Linux hosts without polkitd: prompts are `UNAVAILABLE` there, so roles that require a platform prompt fail closed, while key-based methods and `forbid` policies still work

## 14. Deliverables

```text
peer-verification ← platform-helper ← authorization ← headless ← policy ← wsl ← notify
```

Layers of the stack in [hardening §14](hardening.md) that implement this spec:

| Layer | Files |
|---|---|
| `hardening/peer-verification` | `src/platform/mod.rs` (traits), `src/platform/process/{linux,fallback}.rs` (procfs, peer), `proto/mairu_platform.proto`, `build.rs`, `src/proto.rs` |
| `hardening/platform-helper` | `src/platform/helper.rs` (`HelperClient`, spawn, respawn), `src/cmd/platform_helper.rs` (hidden `mairu platform-helper --fd`), `src/platform/services/{mod,fallback}.rs`, agent startup wiring |
| `hardening/authorization` | `src/platform/services/linux/polkit.rs`, `pkg/polkit/co.0w0.mairu.policy`, `Cargo.toml` (`zbus`, `zbus_polkit`, deb asset) |
| `hardening/headless` | `src/polkit_tty_agent.rs`, client retry paths, `src/cmd/doctor.rs` |
| `hardening/policy` | `src/platform/services/linux/integrity.rs`, `Cargo.toml` (Secret Service crate) |
| `hardening/wsl` | `src/platform/process/linux/wsl.rs` (detection), `src/platform/services/linux/wsl.rs` (Windows-side `open_url`) |
| `hardening/notify` | `src/convenience.rs` (mode resolution `auto|agent|command|none`, helper commands, rate limits), `src/config.rs` (`UserConfig.open_url`, `UserConfig.notify`), `src/platform/services/linux/{notify,open_url}.rs`, `proto/mairu.proto` (`OpenUrl`, `Notify`), `proto/mairu_platform.proto` (`SessionHint`), `src/agent.rs`, `src/cmd/{login,exec}.rs` (`--no-browser`, event emission) |

## Current Status

Spec drafted; awaiting review before implementation. Implementors MUST keep this section updated as they work.

### Checklist

Linux:
- [ ] `mairu.platform` proto; `ProcessPlatform` and `PlatformServices` traits
- [ ] Platform helper process: inherited socketpair, mutual verification, fail closed, respawn
- [ ] polkit backend and policy file; system bus and authority checks
- [ ] `pkttyagent` fallback
- [ ] Protected-directory and Secret Service integrity stores
- [ ] Notifications and open-url: helper backends, `SessionHint`, client-chosen modes (`auto|agent|command|none`), agent `OpenUrl`/`Notify` RPCs
- [ ] WSL2: Windows-side `open_url` (Q-W5 settled)

macOS (separate implementation, §11):
- [ ] Settle the Q items in §11 and write them back here
- [ ] LocalAuthentication backend
- [ ] Integrity stores: legacy keychain (weak), protected directory after `harden` (strong)
- [ ] Helper on macOS: always the bundle (unbundled only as the fallback), spawned by the LaunchAgent-run agent and verified as a running child both ways (Q-M1 confirmed, Q-M2 addressed)
- [ ] Helper bundle: embedded (official) or assembled (`MairuAgentCDHash`), registration, notifications, click-relaunch exit, per-flavour names, icon `pkg/macos/mairu.icns`, cleanup (Q-M3 to Q-M5, Q-M13)
- [ ] Helper bundle `mairu-platform-helper` with the data-protection keychain store, and `ResetIntegrity` with an administrator authorization; settle Q-M12 (Q-M6 decided)

### Updates

- 2026-10-23: Drafted as part of a single combined spec; notifications and URL opening moved to client-side emission with client-chosen modes.
- 2026-10-23: Split out of the combined spec.
- 2026-10-23: Added show-me style visual summaries to every section (additive; Mermaid blocks validated with mermaid 11.4.1).
- 2026-10-23: Platform services always run in a separate platform helper that shares the agent's lifetime (inherited socketpair), on every OS; process primitives split into their own trait; convenience modes reduced to `auto|agent|command|none` with a session hint; no app bundle planned on macOS.
- 2026-10-23: macOS backends rewritten around Developer ID build tiers: embedded Developer ID notifier or locally assembled ad-hoc notifier, keychain store per tier.
- 2026-10-23: Notifier extraction hardened: fresh directory per version and flavour, quarantine removed and designated requirement checked before launch, launch by full path, separate bundle ids per flavour.
- 2026-10-23: Notifier cleanup is by disuse, not by version, since versions run side by side.
- 2026-10-23: Decided: a single platform helper process; session-bus exposure recorded as an accepted risk (§12).
- 2026-10-23: WSL2 `open_url` uses `rundll32.exe url.dll,FileProtocolHandler` (explorer.exe fallback); `auto` honors `$BROWSER`; WSLg findings recorded (§8.2, §10).
- 2026-10-23: Interim macOS findings: Q-M1 confirmed (socketpair reports the creator until the child does I/O); the legacy keychain has no integrity, so `KEYCHAIN` is weak and strong integrity needs `harden`; the data-protection keychain needs an entitlement; Q-M3 interim results (§4, §7, §11, §12).
- 2026-10-23: Q-M2 addressed by the LaunchAgent transport decided in [hardening §9.2](hardening.md) (§11, §12).
- 2026-10-23: macOS integrity: Developer ID builds run a signed helper bundle holding the data-protection keychain (strong), every tier gets the protected directory through `harden` (strong), the legacy keychain is weak; store kinds renamed, `generation` added to `IntegrityRecord`, `ResetIntegrity` added (§1, §3, §4, §7, §11, §12).
- 2026-10-23: macOS update 2: LocalAuthentication shows its sheet on the console from either launchd domain; Secure Enclave keys not used; `AuthorizationCopyRights` confirmed from `gui/<uid>`; Q-M3 confirmed (ad-hoc notifiers start denied), Q-M4 confirmed (permission keyed by bundle id), Q-M5 settled (§11).
- 2026-10-23: The setgid non-member case is confirmed on macOS (§11).
- 2026-10-23: From a real SSH session: LocalAuthentication prompts on the console, `AuthorizationCopyRights` returns `-60007`, and the notifier is shown on the console; the notification grant outlives its bundle (§11).
- 2026-10-23: The origin of a macOS platform prompt is derived from the peer's audit session and exposed as `context.console_session` (§11).
- 2026-10-24: Q-M3's MDM question not pursued; Q-M12 and the Developer ID notifier deferred until the Developer ID is issued (§11).
- 2026-10-24: Q-M13 opened: merge the notifier into the helper bundle if a directly exec'd bundle can post notifications; ad-hoc builds would then assemble an unentitled helper bundle (§11).
- 2026-10-24: Q-M13 confirmed: the notifier is merged into the helper bundle, which is now always a bundle on macOS, registered with `lsregister -f` before exec; extraction rules completed (directory keys, dev location, archive format, who writes it, races) (§1, §4, §8.4, §11, §12).
