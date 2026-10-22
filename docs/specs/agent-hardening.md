# Agent hardening and platform authorization

## 1. Overview

`mairu agent` holds credential-server sessions in memory and vends AWS credentials to whoever connects to its Unix socket. Today that is any process running as the user. Nothing checks who the client is, nothing lets a client check who the agent is, and nothing asks the human before credentials leave the agent.

This spec adds three things:

1. **Mutual verification** between `mairu` (clients) and `mairu agent`, anchored in a platform mechanism that same-user code cannot forge. Clients only talk to a genuine agent, and the agent only serves genuine clients.
2. **Platform authorization.** The agent asks the human, through a platform facility, before vending credentials. The answer is remembered per terminal session for a short time. User policy that relaxes or tightens this is integrity-protected.
3. **A common platform protocol** (`mairu.platform`, protobuf) and a matching Rust trait, covering authorization prompts, integrity records, notifications and opening URLs, so the agent core stays platform-independent and an out-of-process helper can serve the same contract. Notifications and opening URLs carry no security weight, and each client chooses how they are delivered (§10).

Linux is implemented first. macOS is designed here and implemented separately against this document. BSD is design-only.

### 1.1 Terminology

| Term | Meaning |
|---|---|
| client | Any `mairu` process that talks to the agent: `exec` (its sidecar), `credential-process`, `login`, `list-*`, `policy`, `lock`, `doctor`, … |
| agent | The `mairu agent` process. |
| hardened | A process whose integrity the platform enforces: on Linux/BSD, exec'd from the setgid marker binary; on macOS, running a validly signed binary with hardened runtime. |
| marker group | The Unix group `mairu`. It grants nothing; it marks processes exec'd from the hardened binary. |
| peer | The process on the other end of a Unix socket, as reported by the kernel. |
| grant | A remembered authorization keyed by (session identity, server, rolespec), with an idle timeout and a hard cap. |
| lease | A remembered authorization tied to one live `mairu exec` sidecar process, valid for that process's lifetime. |
| integrity record | A digest (or signature) of the user policy file, kept where same-user code cannot rewrite it. |
| platform helper | An optional out-of-process server of the `mairu.platform.PlatformHelper` service. |

## 2. Threat model

### 2.1 Adversary

Code running **as the same Unix user** as the human, which the human did not intend to act. Examples: a compromised dependency's install script, a malicious repository script, or an AI coding agent going beyond what it was asked to do. It can:

- read and write every file the user can, including `~/.config/mairu`, `~/.local/state/mairu` and `.mairu.json`
- connect to the user's Unix sockets, kill the user's processes, and bind sockets in the user's runtime directory
- run any binary, including genuine `mairu`, with arbitrary arguments, environment and file descriptors
- ptrace the user's ordinary, dumpable processes (subject to `kernel.yama.ptrace_scope`)
- read and write the user's Secret Service (no per-application access control on Linux) and claim names on the user's session D-Bus
- use the user's forwarded SSH agent socket
- observe the user's tmux panes (`tmux pipe-pane`, `capture-pane`)

### 2.2 Out of scope

Root, kernel compromise, physical access, and malicious credential servers or IdPs.

Credentials *after delivery* are also out of scope. Once `mairu exec` hands credentials to the user's command, same-user code that can inspect that command (its environment, its memory, or the ECS bearer token in its environment) can take them. This design protects the agent's ability to mint credentials for arbitrary roles and its session tokens. It does not protect credentials already given to an unprotected process.

### 2.3 What is a boundary and what is a guardrail

- **Boundary**:
  - The platform authorization step (polkit, macOS LocalAuthentication, or the ssh-agent FIDO touch).
  - The mutual verification that makes the prompt's contents truthful: a genuine client reports what it will actually do with the credentials.
  - Integrity of the policy that decides when to prompt.
- **Guardrails**, best-effort and never relied on alone:
  - AI-agent detection (§8.6)
  - `disallow_roles` in `config.json`
  - the `.mairu.json` trust prompt

## 3. Trust anchors

### 3.1 Linux and BSD: the setgid marker group

The hardened binary is installed root-owned, with group `mairu` and mode `2755` (setgid). When any user execs it, the kernel:

- sets the process's effective gid to `mairu`. This is the marker.
- sets `AT_SECURE`, so the dynamic loader ignores `LD_PRELOAD`, `LD_LIBRARY_PATH` and similar. Release musl binaries are static anyway.
- makes the process non-dumpable from the first instruction. Same-uid ptrace, `/proc/<pid>/mem`, `/proc/<pid>/environ` and `/proc/<pid>/fd` become inaccessible, and the existing `prctl(PR_SET_DUMPABLE, 0)` in the agent then only reaffirms it.
- **does not** apply the setgid bit if the exec happens under ptrace by an unprivileged tracer.

The marker therefore cannot be obtained by same-user code except by running the genuine binary untraced and uninjected. `SO_PEERCRED` reports the peer's *effective* gid, snapshotted by the kernel:

- for the connecting side, at `connect()`
- for the listening side, at `listen()`. A connected client socket inherits the listener's credentials.

So each side can check the other's marker without trusting anything it says.

Preconditions, checked at runtime (§4.2):

- The user must **not** be a member of `mairu`, neither as primary nor as supplementary group. A member can obtain the marker with `sg`/`newgrp`.
- `fs.protected_hardlinks = 1`, so users cannot hardlink old hardened binaries and keep running them after an upgrade. This is a warning only.

### 3.2 macOS: code signature

Identity comes from the peer's audit token, never a pid:

1. Get the audit token with `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)` on the Unix socket, or from the XPC connection.
2. Get the peer's code with `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)`.
3. Check it with `SecCodeCheckValidity` against a requirement derived from **the verifier's own** designated requirement (`SecCodeCopySelf` + `SecCodeCopyDesignatedRequirement`).

This means no team identifier is hardcoded:

- Developer ID builds match on team and identifier `co.0w0.mairu`.
- Ad-hoc builds (Homebrew from source) match only a byte-identical binary, through the cdhash.

Both sides also require the hardened-runtime flag and the absence of `com.apple.security.get-task-allow`. The agent keeps `PT_DENY_ATTACH`. Use the audit token's pid version (`audit_token_to_pidversion`) wherever a pid is recorded. Details, and the questions still open, are in §12.

## 4. Hardened installation (Linux)

### 4.1 Layout

| Path | Owner | Mode | Purpose |
|---|---|---|---|
| `/usr/local/libexec/mairu/mairu` | `root:mairu` | `2755` | Hardened binary installed by `mairu harden` |
| `/usr/bin/mairu` | `root:mairu` | `2755` | Hardened binary installed by distro packages |
| `/usr/local/libexec/mairu/.harden-manifest` | `root:root` | `0644` | Files written by `mairu harden`, for `--uninstall` |
| `/usr/share/polkit-1/actions/co.0w0.mairu.policy` | `root:root` | `0644` | polkit actions (§8.4) |
| `/var/lib/mairu` | `root:mairu` | `2770` | Protected state root. Users cannot traverse it, but the marker gid can. |
| `/var/lib/mairu/users` | `root:mairu` | `2770` | |
| `/var/lib/mairu/users/<uid>` | `<uid>:mairu` | `0700` | Per-user integrity records (§9.3). Created by the agent with the marker gid held. |

`/var/lib/mairu/users/<uid>` is owned by the user, but the user cannot reach it by path: they are neither owner nor group of `/var/lib/mairu`, and "other" has no search permission. Only a process holding the marker gid can open it, and the genuine agent only ever opens the directory for `getuid()`. User namespaces do not help, because unmapped owners keep their permission semantics.

### 4.2 Classifying the running process

`crate::hardening::Hardening::detect()` runs first in `main`, before argument handling has any side effects:

1. Look up group `mairu` (`getgrnam_r`; static musl builds read `/etc/group` only, which is fine because `harden` creates a local system group). Read `getresgid()`.
2. Classify:

   | Condition | State |
   |---|---|
   | Group absent | `Unhardened` |
   | `rgid == mairu`, or `mairu` is in `getgroups()`, or the user is listed in the group's members | `Misconfigured`: the marker is forgeable. Warn, and act as `Unhardened`. |
   | `egid == mairu` and `rgid != mairu` | `Hardened` |
   | Otherwise | `Unhardened`. The system may be hardened but this binary is not, which triggers re-exec (§4.3). |

3. When `Hardened`, immediately call `setresgid(rgid, rgid, mairu)`. The effective gid is then the real gid, and the marker stays only in the saved gid until needed.

Helpers:

- `with_privileged_gid(f)`: under a process-wide mutex, `setresgid(-1, mairu, -1)`, run `f`, then `setresgid(-1, rgid, -1)`. glibc and musl apply set\*id calls to all threads. Used around `connect()`, `bind()`+`listen()`, and access to `/var/lib/mairu`.
- `drop_privileged_gid_permanently()`: `setresgid(rgid, rgid, rgid)`, then assert that `getresgid()` returns `rgid` three times. On failure the caller aborts; it never execs with the marker.
- `command(program)`: a `std::process::Command` whose `pre_exec` performs the permanent drop. Every child process mairu spawns uses it (`xdg-open`, `pkttyagent`, the agent itself), except the exec of the user's command, which calls the drop directly. Re-exec'ing the setgid binary re-acquires the marker through the setgid bit, so dropping before spawning the agent is harmless.

Process-specific rules:

- **Executor** (`mairu exec` parent): drops permanently before `exec`'ing the user's command. Without this, the command (attacker-influenced) would inherit `egid == mairu` and pass the agent's check.
- **Sidecar** (`mairu exec` child): keeps the saved marker for reconnects, and holds the effective marker only inside `with_privileged_gid`.
- **Agent**: holds the effective marker only for `listen()` and protected-directory I/O.

### 4.3 Re-exec from non-packaged installs

`mise`, `cargo install`, `aqua` and tarball installs keep the binary in a user-writable location, where it cannot be setgid. `crate::hardening::reexec_hardened_if_available()` runs right after classification when the state is `Unhardened`. It is skipped for the `harden` subcommand and when `MAIRU_NO_HARDENED_REEXEC=1` is set; the opt-out produces an unhardened client, which a hardened agent rejects anyway, so it is safe for development.

1. For each candidate in order, `/usr/local/libexec/mairu/mairu` then `/usr/bin/mairu`:
   - canonicalize the path
   - `statfs`: reject FUSE (`f_type == 0x65735546`)
   - `stat`: regular file, `st_uid == 0`, `st_gid == mairu`, mode has `S_ISGID`, `mode & 0o022 == 0`, executable
   - every ancestor directory of the canonical path: `st_uid == 0` and `mode & 0o022 == 0`

   These checks are pure functions over `(uid, gid, mode, fs_magic)` so they can be unit-tested.
2. Exec the first valid candidate with the original `argv[1..]`, setting `MAIRU_HARDENED_REEXEC_FROM=<own canonical exe path>` and `MAIRU_HARDENED_REEXEC_VERSION=<own CARGO_PKG_VERSION>`.
3. The hardened process reads and **unsets** both variables. If the version differs from its own, it prints once to the terminal:

   ```
   :: mairu :: Using hardened mairu 0.13.0 (/usr/local/libexec/mairu/mairu) instead of mairu 0.14.0 (/home/u/.local/share/mise/installs/mairu/0.14.0/mairu).
   :: mairu :: To update the hardened copy, run: sudo /home/u/.local/share/mise/installs/mairu/0.14.0/mairu harden
   ```

   The variables only feed this message, so a forged value cannot do more than print a misleading warning.
4. If no candidate exists, the platform is Linux, and stderr is a terminal: show a one-time suggestion (`:: mairu :: Run 'sudo <exe> harden' to protect your AWS credentials from other programs …`), then create the marker file `state_dir()/hardening-suggested`. `mairu doctor` always shows the state.

The hardened copy is the single authoritative binary. Every installation execs it, whatever version invoked it.

### 4.4 `mairu harden`

Linux only (BSD later). It must run as root (`euid == 0`); otherwise it exits with the exact command to run: `sudo <canonical exe path> harden`. It is idempotent, and re-running it upgrades the binary.

1. **Group.** If `mairu` is missing, run `groupadd --system mairu`, falling back to `addgroup --system mairu` (busybox). Refuse if the group has members, or if `SUDO_UID`'s primary gid is `mairu`, and print how to fix it.
2. **Directory.** Create `/usr/local/libexec/mairu` as `root:root 0755`. Check that the ancestor chain is root-owned and not group/other-writable.
3. **Binary.**
   1. Open `/proc/self/exe`, which is the exact image running as root.
   2. Create `.mairu.tmp.<pid>` in the target directory with `O_EXCL`, mode `0600`, and copy into it.
   3. `fchown(0, mairu)`, `fchmod(0o2755)`, `fsync`.
   4. `rename` to `mairu`, then `fsync` the directory.
   5. If `/usr/sbin/setcap` or `/usr/bin/setcap` exists, run `setcap cap_ipc_lock=+ep` on the final path. This must come after the `chown`, because `chown` clears file capabilities. It is needed so the agent's `mlockall` succeeds without RLIMIT_MEMLOCK headroom.
4. **polkit.** If `/usr/share/polkit-1/actions` exists, write `co.0w0.mairu.policy` (embedded with `include_str!`) unless an identical file is already there. Otherwise warn that authorization will be unavailable.
5. **State directory.** Create `/var/lib/mairu` and `/var/lib/mairu/users` as `root:mairu 2770`.
6. **Manifest.** Record every file written in `.harden-manifest`.
7. **Next steps.** Print them: the next hardened `mairu` invocation replaces the running unhardened agent automatically (§5.3), or the user can run `mairu kill-agent`.

`mairu harden --uninstall` removes the files listed in the manifest. `--purge` also removes `/var/lib/mairu`. The group is left in place; `groupdel mairu` is documented.

### 4.5 Distribution packages

- **Debian** (`cargo deb`, `pkg/debian/postinst`):

  ```sh
  getent group mairu >/dev/null || groupadd --system mairu
  chgrp mairu /usr/bin/mairu
  chmod 2755 /usr/bin/mairu
  setcap cap_ipc_lock=+ep /usr/bin/mairu   # after chgrp: chown clears file caps
  install -d -o root -g mairu -m 2770 /var/lib/mairu /var/lib/mairu/users
  ```

  The polkit file ships as an asset at `/usr/share/polkit-1/actions/co.0w0.mairu.policy`. Add `recommends: polkitd | policykit-1`.
- **systemd distributions**: `pkg/sysusers.d/mairu.conf` (`g mairu -`) and `pkg/tmpfiles.d/mairu.conf` (`d /var/lib/mairu 2770 root mairu -`, `d /var/lib/mairu/users 2770 root mairu -`) for packagers.
- **AUR** (`mairu`, `mairu-bin`, separate repositories): install the polkit file plus the sysusers/tmpfiles snippets. A `.install` `post_install`/`post_upgrade` runs `chgrp mairu /usr/bin/mairu && chmod 2755 /usr/bin/mairu && setcap cap_ipc_lock=+ep /usr/bin/mairu`. Tracked as a follow-up.
- **Homebrew on Linux, mise, cargo, aqua, tarballs**: `sudo mairu harden`.

## 5. Mutual verification (client ↔ agent)

### 5.1 Agent side

The agent wraps every accepted stream in `PeerStream { inner: tokio::net::UnixStream, peer: Arc<PeerIdentity> }`, which implements `tonic::transport::server::Connected<ConnectInfo = Arc<PeerIdentity>>`. tonic inserts the connect info into every request's extensions. At accept:

1. `SO_PEERCRED` → `(pid, uid, gid)`. If `uid != geteuid()`, close the connection immediately. The runtime directory is already `0700`; this is defense in depth.
2. Obtain a pidfd:
   - `SO_PEERPIDFD` on Linux 6.5+ is race-free.
   - Otherwise `pidfd_open(pid)` on Linux 5.3+. This leaves a pid-reuse window between `connect()` and accept handling that only affects attribution (session identity, ancestry), never the gid check.
3. Read `/proc/<pid>/stat` (§8.2) for `start_time`, then confirm the pidfd still refers to a live process (`pidfd_send_signal(pidfd, 0)`) so the values read belong to it.
4. Compute trust:

   | Agent state | Peer gid | `PeerTrust` |
   |---|---|---|
   | Hardened | `mairu` | `Verified` |
   | Hardened | anything else | `Rejected` |
   | Unhardened or Misconfigured | any | `Unverifiable` |

Each handler calls `require_trusted(&request)`. `Rejected` peers get `PERMISSION_DENIED` with `AuthorizationError{reason: UNVERIFIED_PEER}` (§7.1) on every RPC except `PingAgent` and `GetAgentStatus`, which stay open so unverified binaries can diagnose themselves. `Unverifiable` peers are served as they are today.

### 5.2 Client side

`connect_to_agent_with_path` connects with a blocking `std::os::unix::net::UnixStream::connect` inside `with_privileged_gid`, then converts the stream to tokio. tonic calls the connector closure again on every reconnect, so reconnects behave the same. After connecting, it reads `SO_PEERCRED` of the stream, which carries the agent's credentials at `listen()`:

- `uid` must equal `geteuid()`.
- If the client is `Hardened`, `gid` must equal `mairu`. Otherwise the agent is **unverified**: never send it anything except `PingAgent`, `GetAgentStatus` or `ShutdownAgent`.

The `MAIRU_AGENT_SOCK` override remains supported. A redirected socket still has to pass this check.

### 5.3 Replacing an unverified agent

A hardened client that finds a live but unverified agent at the socket path (an old agent started before `harden`, or a squatter) does not use it. `connect_or_start` spawns a hardened agent with `--replace-unverified`. That agent's bind logic:

1. connects to the existing socket and sees an unverified agent
2. sends `ShutdownAgent` with a 2 s timeout
3. unlinks the socket file if it is a socket
4. binds and listens with the marker held

The client's connect loop treats unverified agents as not ready, and prints:

```
:: mairu :: Replacing an agent that is not hardened (pid 12345); you may need to log in again.
```

A squatter that ignores `ShutdownAgent` keeps running on an unlinked socket and is never reached again.

`mairu kill-agent` sends `ShutdownAgent` without requiring a verified agent, because shutting down an impostor is harmless. An unhardened client never replaces a hardened agent.

### 5.4 Session tokens on the wire

`CompleteOauthCode` carries authorization codes to the agent. Client-side agent verification (§5.2) is what keeps these codes away from a socket squatter.

## 6. Platform abstraction

### 6.1 Rust trait

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
  - `RemotePlatform`, the helper client of §6.3
  - `FallbackPlatform`: macOS and BSD until they are implemented. No verification (`Unverifiable`), authorization `UNAVAILABLE`, no integrity stores, no notifications. `open_url` uses `/usr/bin/open` on macOS.

### 6.2 Protocol: `proto/mairu_platform.proto`

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

message RecordIntegrityRequest {
  string name = 1;   // "policy"
  uint32 uid = 2;
  bytes digest = 3;  // 32 bytes
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
}
```

Helpers reject requests whose `uid` differs from their own.

### 6.3 Platform helper transport and mutual verification

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
   - Ad-hoc builds need a cdhash pin recorded at install time; §12 settles this.
4. If the helper is unverified, unreachable or crashed, `RemotePlatform` returns `RESULT_UNAVAILABLE` (`helper-unverified`) and empty capabilities. The agent fails closed. It respawns the helper at most once per 30 s.

### 6.4 Verifying system services (Linux in-process backend)

- **System bus.** When hardened, the agent ignores `DBUS_SYSTEM_BUS_ADDRESS`, which is attacker-controllable environment, and connects to `unix:path=/run/dbus/system_bus_socket`. The socket's parent directory must be root-owned and not group/other-writable.
- **polkit authority.** Before trusting a result, the agent checks that the owner of `org.freedesktop.PolicyKit1` is uid 0 (`org.freedesktop.DBus.GetConnectionUnixUser`). A mismatch maps to `UNAVAILABLE`/`untrusted-authority`.
- **Session bus** services (Secret Service, notifications, the desktop portal) can be claimed by any same-uid process. They are treated as untrusted conveniences, and this is why Secret Service is a secondary integrity store (§9.3).

## 7. Agent protocol changes (`proto/mairu.proto`)

```proto
import "mairu_platform.proto";

service Agent {
  // ... existing RPCs ...
  rpc GetAgentStatus(GetAgentStatusRequest) returns (GetAgentStatusResponse);
  rpc GetPolicy(GetPolicyRequest) returns (GetPolicyResponse);
  rpc ApprovePolicy(ApprovePolicyRequest) returns (ApprovePolicyResponse);
  rpc RevokeAuthorizations(RevokeAuthorizationsRequest) returns (RevokeAuthorizationsResponse);
  rpc OpenUrl(mairu.platform.OpenUrlRequest) returns (mairu.platform.OpenUrlResponse);  // §10.5
  rpc Notify(mairu.platform.NotifyRequest) returns (mairu.platform.NotifyResponse);     // §10.5
}

message PingAgentResponse {
  string version = 1;
  // Lets every client warn about, and notify of, lockdown (§10.1) without an extra RPC.
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
  repeated string key_fingerprints = 3;  // "SHA256:..." of acceptable registered keys
  google.protobuf.Timestamp expires_at = 4;
}

message AuthorizationStatement {
  bytes nonce = 1;                 // 32 random bytes
  bytes agent_instance_id = 2;     // 16 random bytes chosen at agent start
  uint32 peer_pid = 3;
  uint64 peer_start_time = 4;
  string action = 5;               // "assume-role" | "approve-policy"
  string server_id = 6;
  Rolespec rolespec = 7;
  bytes request_digest = 8;        // §8.5
  google.protobuf.Timestamp expires_at = 9;
}

message AuthorizationResponse {
  bytes challenge_id = 1;
  oneof result {
    bytes sshsig = 2;              // binary SSHSIG blob
    string declined = 3;           // why the client could not sign: "no-ssh-agent", "no-registered-key", "sign-failed"
  }
}

// Carried as the binary details of a non-OK tonic::Status (grpc-status-details-bin).
message AuthorizationError {
  enum Reason {
    REASON_UNSPECIFIED = 0;
    REASON_UNVERIFIED_PEER = 1;          // PERMISSION_DENIED
    REASON_DENIED = 2;                   // PERMISSION_DENIED: the human said no or cancelled
    REASON_DISALLOWED = 3;               // PERMISSION_DENIED: require = deny / disallow_roles
    REASON_AI_AGENT_DENIED = 4;          // PERMISSION_DENIED
    REASON_UNAVAILABLE = 5;              // FAILED_PRECONDITION: no method could ask the human
    REASON_CHALLENGE = 6;                // FAILED_PRECONDITION: sign `challenge` and retry
    REASON_NO_AUTHENTICATION_AGENT = 7;  // FAILED_PRECONDITION: register pkttyagent and retry
    REASON_INVALID_RESPONSE = 8;         // PERMISSION_DENIED: bad, expired or replayed response
  }
  Reason reason = 1;
  string detail = 2;
  AuthorizationChallenge challenge = 3;
}

enum HardeningState {
  HARDENING_STATE_UNSPECIFIED = 0;
  HARDENING_STATE_UNHARDENED = 1;
  HARDENING_STATE_HARDENED = 2;
  HARDENING_STATE_MISCONFIGURED = 3;
}

enum PolicyIntegrity {
  POLICY_INTEGRITY_UNSPECIFIED = 0;
  POLICY_INTEGRITY_ABSENT = 1;
  POLICY_INTEGRITY_APPROVED = 2;
  POLICY_INTEGRITY_UNAPPROVED = 3;
  POLICY_INTEGRITY_TAMPERED = 4;
}

message GetAgentStatusRequest {}
message GetAgentStatusResponse {
  string version = 1;
  HardeningState agent_hardening = 2;
  PeerView caller = 3;
  mairu.platform.Capabilities capabilities = 4;
  PolicyIntegrity policy_integrity = 5;
  uint32 grants = 6;
  uint32 leases = 7;
  string platform_backend = 8;          // "linux" | "remote" | "fallback"
  repeated string authorization_methods = 9;  // effective order, e.g. ["ssh-agent", "platform"]
}

message PeerView {
  bool verified = 1;
  uint32 pid = 2;
  uint64 start_time = 3;
  string session = 4;                   // e.g. "tty sid=4242 /dev/pts/3", "parent pid=777", "none"
  repeated string ai_agent_signals = 5; // e.g. "ancestor comm=claude", "env AI_AGENT"
}

message GetPolicyRequest {}
message GetPolicyResponse {
  string effective_json = 1;
  PolicyIntegrity integrity = 2;
  bytes file_digest = 3;                // empty when the file is absent
  repeated mairu.platform.IntegrityStoreResult stores = 4;
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

### 7.1 Errors

Every authorization failure is a non-OK status whose binary details hold `AuthorizationError`, with the status code given in the enum comments. Clients decode the details first and fall back to the status message.

Existing codes keep their meanings. In particular, `UNAUTHENTICATED` still means a credential-server login is required.

### 7.2 Compatibility

- New fields are optional. An old client talking to a new agent sends no `ClientContext`, and the agent then treats intent as unknown: no lease, and `command` is shown as "(unknown)".
- An old agent ignores unknown fields.
- Versions already diverge noisily (the existing `PingAgent` warning). Hardened deployments run one binary, so mixed versions are transitional.

## 8. Authorization

### 8.1 When it applies

Authorization runs in `AssumeRole`, after the peer trust check and server/user-config loading, and **before** the credential cache lookup. `ApprovePolicy` always requires authorization (§9.5). `ListRoles`, `ListSessions`, `GetServer`, `RefreshSession`, the login RPCs and `ShutdownAgent` require only a trusted peer.

### 8.2 Process facts (Linux)

`src/platform/linux/procfs.rs` parses `/proc/<pid>/stat` by splitting at the **last** `)` (comm may contain spaces and parentheses), giving:

- field 4 `ppid`
- 5 `pgrp`
- 6 `session`
- 7 `tty_nr`
- 22 `starttime` (clock ticks since boot)

It also reads `/proc/<pid>/comm`, `/proc/<pid>/exe` (readlink; may fail), and `/proc/<pid>/cmdline` (argv split on NUL, and only used for display and AI matching). Every read is followed by a pidfd or start-time liveness check so the values cannot belong to a recycled pid.

### 8.3 Session identity

```
SessionIdentity =
  Tty    { sid, leader_start_time }   if tty_nr != 0 and /proc/<sid> exists with session == sid
  Parent { ppid, start_time }         else if ppid > 1 and the parent is alive
  none                                otherwise: no grants (every request prompts unless leased)
```

- Pairing each id with a start time defeats id reuse.
- Each GUI terminal tab, each SSH login and **each tmux pane** is its own POSIX session: the pane shell is created through `forkpty` → `setsid`. A grant therefore covers one pane, and survives detach/reattach within the idle window.
- Tools that run commands without a controlling tty and in a fresh session, such as an AI agent's shell tool (observed: Claude Code runs each command under `setsid` with no tty), fall into `Parent`. That parent is usually short-lived, so grants rarely carry over.

### 8.4 polkit (Linux)

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
- `$(role)`/`$(server)` expand from `details`. Whether a given authentication agent shows the expansion or the other `details` keys varies, so the client terminal always prints the full context too (§8.8). Confirm the expansion against polkit 127 during implementation.
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
4. Print the context (§8.8), then retry the RPC once.
5. Send `SIGTERM` to `pkttyagent` when the RPC returns.

The process that spawns `pkttyagent` is the one making the RPC, so polkit's subject and the registered agent are the same process. For `exec` that is the sidecar.

**Risk documented for users:** a tty password prompt can be captured by same-user code (`tmux pipe-pane`, terminal emulator or `pkttyagent` memory via ptrace) and replayed later. Prefer ssh-agent presence (§8.7) on shared or headless hosts.

### 8.5 Grants, leases and the evaluation order

**Clock.** `CLOCK_BOOTTIME`, so suspended time counts toward idle expiry. `std::time::Instant` uses `CLOCK_MONOTONIC` on Linux, which excludes suspend.

**Grant.**

- Key: `(SessionIdentity, server_id, Rolespec)`. `server_id` is the canonical id from the server config. `Rolespec` includes the chained `assume_role` fields, since a chained role is different access.
- Value: `{created, last_used}`.
- Valid iff `now − last_used ≤ grant_idle_timeout_secs` (default 300) **and** `now − created ≤ grant_max_lifetime_secs` (default 43200). A hit sets `last_used = now`.
- Created when the effective `require == session` and there are no AI signals.

**Lease.**

- Key: `(peer pid, peer start_time, server_id, Rolespec)`. Value: the peer's pidfd.
- Valid while the pidfd's process is alive.
- Created on any allowed prompt whose intent is `exec`. This includes `require = always` and AI-prompted requests: the human approved this exact command, and ECS refreshes must not prompt again.
- Swept every 60 s and checked on lookup.

All authorization state is in memory only. Restarting the agent forgets every grant and lease.

**Request digest.** SHA-256 over the prost encoding of `{action, server_id, rolespec, ClientContext without authorization_response}`. It binds ssh-agent challenges to the exact request, which the retry must repeat.

**Evaluation order** (`src/authorization.rs`, `Authorizer::authorize_assume_role`):

1. Effective policy (§9.4): pick the rule for `(server, rolespec)` (§9.2).
2. `require == deny`, or `UserConfig::is_role_disallowed` → `REASON_DISALLOWED`.
3. AI signals (§8.6) present:
   - `ai_agents == deny` → `REASON_AI_AGENT_DENIED`
   - `prompt` → skip grants (step 6)
   - `allow` → no change
4. `require == none` → allow.
5. Lease hit → allow.
6. Grant hit → allow.
7. Ask the human, using the methods in policy order (§8.7, §9.2):
   - **ssh-agent** (only when keys are registered and usable):
     - The request carries a valid `authorization_response.sshsig` for an outstanding challenge → verify (§8.7) → allow.
     - It carries `declined` → try the next method.
     - Otherwise → issue a challenge → `REASON_CHALLENGE`.
   - **platform** (`Platform::authorize`):
     - `ALLOWED` → allow.
     - `DENIED`/`CANCELLED` → `REASON_DENIED`.
     - `UNAVAILABLE`/`no-authentication-agent` → `REASON_NO_AUTHENTICATION_AGENT`.
     - Any other `UNAVAILABLE` → try the next method.
   - No method left → `REASON_UNAVAILABLE`, with a detail listing what was tried.
8. On allow from step 7: record a lease (exec intent) and a grant (step-3 rules permitting), then continue into the existing credential logic.

Concurrent requests with the same grant key wait on one platform prompt through the existing `crate::singleflight::Singleflight`. ssh-agent challenges are per request and are not coalesced.

### 8.6 AI-agent detection (guardrail)

Signals, all positive-only (they can add caution, never remove it):

- **Ancestry.** Walk from the peer up through `ppid`, stopping at pid 1, at a uid change, or after 64 hops. Match each ancestor's `comm`, `exe` basename, `argv[0]` basename and `argv[1]` basename (interpreters such as `node script`) exactly against `process_names`. The built-in default is `["claude", "codex", "gemini", "cursor-agent", "aider", "opencode", "goose", "amp", "crush", "qwen", "copilot"]`; recheck it against current agents during implementation.
- **Environment names.** The client sends the names (never values) of its environment variables. They are matched against `env_names`. The built-in default is `["AI_AGENT", "CLAUDECODE", "GEMINI_CLI", "CODEX_SANDBOX"]`; `AI_AGENT` and `CLAUDECODE` were observed in Claude Code's tool environment, and the rest need verifying. The agent cannot read `/proc/<pid>/environ` of a hardened (non-dumpable) peer, so the genuine client reports them. Same-user code can only *add* markers, by launching mairu with them, which only makes things stricter.

Evasion is possible (`setsid` + double fork, `systemd-run --user`, a renamed binary), which is why this is a guardrail: the authorization prompt remains the boundary. Detected signals appear in the prompt details (`ai_agent=…`) and in `doctor`.

### 8.7 ssh-agent presence (FIDO touch through the forwarded agent)

This is a platform-independent method. On headless hosts, and inside tmux over SSH in particular, it beats a tty password because a signature cannot be replayed.

**Registration** (policy, §9.2), as `authorization.ssh_agent_keys[]`:

- `{"key": "<OpenSSH public key line>"}` is accepted only for `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`.
- Other key types require `"presence": "unverified-confirm"`. The agent cannot verify presence for them; the user must load them with `ssh-add -c`.
- Optional `"require_user_verification": true` additionally requires the UV flag (a PIN or biometric on the key).

**Challenge.** On step 7, when keys are registered and the method is selected, the agent:

1. creates `AuthorizationStatement{nonce, agent_instance_id, peer pid/start_time, action, server_id, rolespec, request_digest, expires_at = now + 60 s}` and serializes it once
2. stores `PendingChallenge{statement bytes, peer, request_digest, expires_at}` under a fresh `challenge_id`, keeping at most 4 outstanding per peer and evicting expired ones
3. returns `REASON_CHALLENGE` with `AuthorizationChallenge{challenge_id, statement, key_fingerprints, expires_at}`

**Client relay** (`src/ssh_agent_presence.rs`):

1. Connect to `$SSH_AUTH_SOCK` and send `SSH_AGENTC_REQUEST_IDENTITIES`. Pick the first identity whose `SHA256:` fingerprint is in `key_fingerprints`. If there is no socket or no key, retry with `declined`.
2. Print the context (§8.8) with `:: mairu :: Touch your security key (<comment>) to authorize …`, or "confirm on your SSH agent" for confirm keys.
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

### 8.8 What the human sees

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

### 8.9 Revocation: `mairu lock`

`mairu lock` sends `RevokeAuthorizations{SCOPE_ALL}`.

- `--session` limits it to the caller's session identity.
- `--running` also revokes leases, so running `mairu exec` processes prompt again on their next refresh.
- Outstanding ssh-agent challenges are always dropped.

No authorization is required, since this only tightens.

## 9. Protected policy

### 9.1 Location

`config_dir()/policy.json`, i.e. `~/.config/mairu/policy.json`. Values stay in the home directory, readable and editable. Only integrity records live elsewhere (§9.3).

The agent reads the file itself; clients never send policy content. Integrity records are keyed by **uid, never by path**, so an agent started with a different `HOME` or `XDG_CONFIG_HOME` reads a file whose digest does not match and ends up in `TAMPERED` → lockdown.

### 9.2 Schema

```jsonc
{
  "version": 1,
  "defaults": {
    "require": "session",            // "none" | "session" | "always" | "deny"
    "ai_agents": "prompt"            // "allow" | "prompt" | "deny"
  },
  "grant_idle_timeout_secs": 300,
  "grant_max_lifetime_secs": 43200,
  "rules": [
    // server: server id or URL. role: exact role, or "*".
    // assume_role_arn: absent = only rolespecs without chaining; "*" = any chained ARN; or an exact ARN.
    {"server": "contoso", "role": "123456789012/ReadOnly", "require": "none"},
    {"server": "contoso", "role": "123456789012/Admin", "require": "always", "ai_agents": "deny"},
    {"server": "contoso", "role": "*", "assume_role_arn": "arn:aws:iam::999999999999:role/Prod", "require": "deny"}
  ],
  "ai_agent": {
    "process_names": ["my-agent"],   // added to the built-in list
    "env_names": ["MY_AGENT_ACTIVE"] // added to the built-in list
  },
  "authorization": {
    "methods": ["ssh-agent", "platform"],  // default: ["ssh-agent", "platform"] when keys exist, else ["platform"]
    "ssh_agent_keys": [
      {"key": "sk-ssh-ed25519@openssh.com AAAA... me@laptop"},
      {"key": "ssh-ed25519 AAAA... confirm-key", "presence": "unverified-confirm"}
    ]
  }
}
```

The file is plain JSON; the comments above are for documentation only. Every field is optional except `version`. Unknown fields are rejected at approval time, so typos never silently weaken policy.

Method names are `"ssh-agent"` (§8.7) and `"platform"`, which is the platform's own facility: polkit on Linux, LocalAuthentication on macOS.

**Rule selection.** Among the rules matching `(server, rolespec)`, the highest specificity wins:

- role: exact = 2, `*` = 0
- `assume_role_arn`: exact = 1, `*` or absent = 0

Ties resolve to the stricter value per attribute. Attributes the winning rule leaves unset come from `defaults`, then from built-ins.

**Strictness orders:**

- `require`: none < session < always < deny
- `ai_agents`: allow < prompt < deny
- timeouts: smaller is stricter

**Built-in defaults:**

| | require | ai_agents | methods |
|---|---|---|---|
| Hardened agent | `session` | `prompt` | `["platform"]` |
| Unhardened agent | `none` | `allow` | `["platform"]` |

The unhardened defaults reproduce today's behavior.

### 9.3 Integrity records and stores

- **Digest**: `SHA-256("mairu.policy.v1\0" || file bytes)`. Record name `"policy"`.
- **Linux stores**, used **concurrently** (§6.2 `IntegrityStoreKind`):

  | Store | Available when | Location | Strength |
  |---|---|---|---|
  | `PROTECTED_DIRECTORY` | Agent hardened, and `/var/lib/mairu` is `root:mairu`, mode `2770` with no "other" bits, not FUSE | `/var/lib/mairu/users/<uid>/policy.sha256` (hex + `\n`), written atomically (temp + rename + fsync) inside `with_privileged_gid` | Strong: unreachable by same-user code. Authoritative when present. |
  | `SECRET_SERVICE` | Session bus reachable, `org.freedesktop.secrets` present, default collection unlocked. A locked collection is `UNAVAILABLE`; the agent never triggers an unlock prompt. | Item in the default collection: label `mairu policy digest (uid N)`, attributes `{application: "co.0w0.mairu", kind: "policy-digest", name: "policy", uid: "N"}`, secret = hex digest | Weak: same-user code can read and write it. It catches offline or careless edits, and on hardened hosts any disagreement with the protected directory. |

- **macOS stores** are designed in §12.

### 9.4 Integrity state and effective policy

**Record** (approve) writes the digest to every available store. It fails if none is available.

**Verify** collects per-store statuses, then:

| Situation | State |
|---|---|
| File absent and no store has a record | `ABSENT` |
| Any store `MISMATCHED` (including a record existing while the file is absent) | `TAMPERED` |
| Hardened, protected directory `NOT_RECORDED` | `UNAPPROVED`. Re-approve after hardening, whatever Secret Service says. |
| Hardened, protected directory `MATCHED`, Secret Service `NOT_RECORDED` | `APPROVED`, and backfill the Secret Service record |
| Hardened, protected directory `MATCHED`, Secret Service `MATCHED` or `UNAVAILABLE` | `APPROVED` |
| Unhardened, Secret Service `MATCHED` | `APPROVED` |
| Unhardened, Secret Service `NOT_RECORDED` or `UNAVAILABLE` | `UNAPPROVED` |

**Effective policy:**

| State | Effective policy |
|---|---|
| `ABSENT` | Built-in defaults |
| `APPROVED` | The file |
| `UNAPPROVED` | **Tighten-only merge**: for every request, the stricter of the built-in defaults and the file, per attribute. Unapproved `ai_agent` additions apply, since they only tighten. Unapproved `authorization` (methods, keys) is **ignored**, since adding keys relaxes. An unparseable file is ignored, with a warning. |
| `TAMPERED` | **Lockdown**: `require = max(always, file rule if parseable)`, `ai_agents = deny`, `methods = ["platform"]` (registered keys are not trusted), grant creation disabled. `doctor` and every client print a warning, and clients emit the lockdown notification (§10.1). |

Verification runs at agent start, before every authorization decision (cached by file `(dev, ino, mtime, size)` plus a 5 s TTL), and after `ApprovePolicy`.

Rollback: only the latest digest is kept. Restoring an older file plus its record works against Secret Service only; the protected directory, which is authoritative when hardened, does not allow it.

### 9.5 Approval: `mairu policy approve`

1. The client reads `policy.json`, prints it with a summary of rule changes, and computes the digest.
2. It sends `ApprovePolicy{expected_digest}`.
3. The agent re-reads the file. If the digest differs → `FAILED_PRECONDITION` ("policy.json changed while approving"). This binds approval to what the human saw.
4. The agent validates the file (schema, known version, keys parse, presence rules) → `INVALID_ARGUMENT` on error.
5. The agent authorizes with action `approve-policy`. This always asks, never uses grants, and uses the *currently effective* methods: in lockdown or before any keys are registered, that is the platform only, which is how the first key registration is bootstrapped.
6. It records the digest into all available stores and returns the per-store results.

`mairu policy show` prints the effective policy, the integrity state and per-store statuses (`GetPolicy`).

## 10. Convenience features: notifications and opening URLs

These carry no security weight. Nothing relies on a notification being seen or a URL being opened, and the URLs involved are not secret (PKCE and `state` protect the code flow). They are therefore chosen **per client**, from unprotected settings, and can be redirected or switched off freely. Terminal output and printed URLs never depend on these settings.

### 10.1 Who emits what

Emission always happens in a client, never on the agent's own initiative, so every notification follows the client's choice.

| Event | Emitted by | Limit |
|---|---|---|
| Open the authorize URL (`verification_uri_complete` for the device code grant) | `mairu login`, including the login inside `mairu exec` | once per login |
| Login required | `mairu exec` sidecar (ECS backend and auto-refresh) when the agent returns `UNAUTHENTICATED` | once per server per 10 min |
| AI-agent request denied | The client that receives `REASON_AI_AGENT_DENIED` | once per (server, rolespec) per minute |
| Policy lockdown | Any client whose `PingAgent` reports `POLICY_INTEGRITY_TAMPERED` (§7) | once per agent instance |

Rate-limit state is best-effort: one file per event key under `runtime_dir()/notified/`, compared by mtime.

### 10.2 Modes

`open_url` and `notify` each take one of:

| Mode | Behavior |
|---|---|
| `auto` (default) | `local` when the client looks graphical (`WAYLAND_DISPLAY` or `DISPLAY` set, and `SSH_CONNECTION`/`SSH_TTY` unset), otherwise `none` |
| `local` | The client's own backend, `crate::platform::current()` (§10.4) |
| `agent` | Ask the agent through the `OpenUrl`/`Notify` RPCs (§10.5). The agent uses its own backend, which may be the platform helper (§6.3). Useful when the agent has a desktop session the client lacks, and on macOS where notifications need the helper app. |
| `command` | Run a different helper program supplied by the user (§10.3) |
| `none` | Disabled |

A failure in any mode is logged at debug level and otherwise ignored.

### 10.3 Configuration

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

### 10.4 Backends (`local` and `agent` modes)

- **Linux notifications**:
  - `org.freedesktop.Notifications.Notify` on the session bus (`app_name = "mairu"`, urgency hint).
  - The address comes from `DBUS_SESSION_BUS_ADDRESS`, falling back to `unix:path=$XDG_RUNTIME_DIR/bus` when that exists.
  - Headless (no bus, or no notification daemon): `notifications = false`, and calls are no-ops.
- **Linux open URL**: `org.freedesktop.portal.OpenURI.OpenURI("", url, {})`, falling back to `xdg-open` via `hardening::command()`. A `PATH` lookup is acceptable here.
- **macOS**: §12.
- **Fallback**: `/usr/bin/open` on macOS, otherwise unavailable.

Every mode passes on only `http`/`https` URLs, so a URL can never reach `file://` or a custom-scheme handler. Notification title and body are truncated to 256 and 1024 bytes.

### 10.5 Agent RPCs

```proto
service Agent {
  rpc OpenUrl(mairu.platform.OpenUrlRequest) returns (mairu.platform.OpenUrlResponse);
  rpc Notify(mairu.platform.NotifyRequest) returns (mairu.platform.NotifyResponse);
}
```

Both need only a trusted peer (§5.1), never authorization, and apply the URL and length rules of §10.4.

## 11. Headless Linux

The reference workflow is long-lived **tmux sessions on a remote host, reached over SSH**.

| Capability | GUI session | SSH + tmux | No session bus | No polkitd |
|---|---|---|---|---|
| Peer verification | ✓ | ✓ | ✓ | ✓ |
| ssh-agent presence | ✓ (if agent has an sk key) | ✓ (forwarded agent) | ✓ | ✓ |
| polkit prompt | GUI agent | `pkttyagent` in the pane (§8.4) | ✓ (system bus) | ✗ → `UNAVAILABLE` |
| Integrity: protected directory | ✓ (hardened) | ✓ (hardened) | ✓ (hardened) | ✓ (hardened) |
| Integrity: Secret Service | usually ✓ | usually ✗ | ✗ | — |
| Notifications, `auto` mode (§10.2) | ✓ | ✗ (no-op) | ✗ | — |
| Open URL, `auto` mode (§10.2) | ✓ | ✗ (URL printed) | ✗ | — |
| Notifications / open URL, `command` mode | as configured | as configured (e.g. forward to the local machine) | as configured | as configured |

**Fails closed:**
- A role that requires a prompt when no method can ask: no ssh-agent key and polkit unavailable, or no tty for `pkttyagent`.

**Degrades:**
- Notifications and open-url fall back to terminal output only. Users can point them at their own helper (§10.3).
- Secret Service. On hardened hosts the protected directory carries integrity alone. On unhardened headless hosts there is no store, so the policy is `UNAPPROVED` and only tightens.

**Admin guidance** (README):
- polkit's PAM stack (`/etc/pam.d/polkit-1`) can use `pam_fprintd` or `pam_u2f` on local machines.
- For SSH, the ssh-agent method is preferred, because a FIDO key on the local machine cannot be reached through PAM on the remote host.

## 12. macOS design (implemented separately)

This section is the brief for the macOS implementation. Items marked **Q** must be settled there and written back into this spec.

1. **Distribution and signing.**
   - Release binaries (`aarch64-apple-darwin`, `universal-apple-darwin`) become Developer ID–signed with hardened runtime (`-o runtime`), identifier `co.0w0.mairu`, and notarized. This changes the release workflow.
   - **Q:** Homebrew builds from source are ad-hoc signed and live in user-writable `/opt/homebrew`. Mirror §4: a `sudo mairu harden` that copies to root-owned `/usr/local/libexec/mairu/mairu`, signs it ad-hoc with `-o runtime`, and adds re-exec. The self-DR then pins the cdhash.
2. **Peer verification** (§3.2) on the existing Unix socket, in both directions. **Q:** confirm that `LOCAL_PEERTOKEN` on the *client's* connected socket yields the listener's token (the counterpart of Linux listen-time credentials); if not, the agent proves itself another way, such as XPC with a code-signing requirement.
3. **Process facts.**
   - `proc_pidinfo(PROC_PIDTBSDINFO)`: start time `pbi_start_tvsec/usec`, `pbi_ppid`, `e_tdev` for the tty
   - `getsid` for the session
   - `proc_pidpath` for the executable
   - Pid reuse defeated with the audit-token pid version
4. **Authorization.**
   - `LAContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason:)`, with the reason built from §8.8, run in the agent or helper.
   - Track lid/clamshell state (Touch ID unavailable) and fall back to password.
   - **Q:** whether to use a Secure Enclave key gated by `.userPresence` so the result is cryptographic rather than boolean. Optional, because the agent enforcing the result is itself protected.
   - Over SSH there is no UI, so the ssh-agent method (§8.7) applies unchanged.
5. **Integrity store.** **Q:** choose between:
   - (a) a Keychain generic-password item holding the digest, with an ACL restricted to mairu's code requirement, or
   - (b) a Secure Enclave P-256 key (`kSecAttrTokenIDSecureEnclave`) signing the digest, with the signature in `$HOME` and the latest digest also kept in the Keychain to prevent rollback.

   Option (b) needs `keychain-access-groups`, which likely means an app bundle and a provisioning profile, i.e. the helper. Report the result through `IntegrityStoreKind` `KEYCHAIN` / `SECURE_ENCLAVE`.
6. **Notifications.** `UNUserNotificationCenter` requires a bundle, so expect `Mairu Helper.app` (`co.0w0.mairu.platform-helper`) serving `PlatformHelper` with mutual verification (§6.3). **Q:** launched by the agent (`open -a` / LaunchServices) or as a LaunchAgent with XPC.
7. **Open URL.** `NSWorkspace` or `/usr/bin/open`, in the user's GUI session.
8. **AI-agent ancestry.** The same rules, using `proc_pidinfo`.

## 13. BSD (design only)

- FreeBSD `LOCAL_PEERCRED` (`struct xucred`, `cr_groups[0]` is the effective gid, `cr_pid` on 13+), with the setgid marker as on Linux.
- Process facts from `kinfo_proc` via `sysctl`.
- polkit is in ports.
- `harden` would use `pw groupadd`.
- `crate::ppid` already handles `PROC_PDEATHSIG_CTL`.

## 14. Security considerations

| Threat | Mitigation |
|---|---|
| Rogue client process | Marker gid via `SO_PEERCRED` at `connect()` (§5.1) |
| Genuine binary run with arbitrary arguments | Authorization prompt shows truthful client-reported intent (§8.8) |
| `LD_PRELOAD` or ptrace into the genuine binary | `AT_SECURE`, non-dumpable, setgid dropped under ptrace (§3.1) |
| Marker leaking to children | Permanent drop before every exec; `hardening::command()` (§4.2) |
| Socket squatter or rogue agent stealing OAuth codes | Client checks the agent's listen-time marker (§5.2); hardened clients replace unverified agents (§5.3) |
| Pid reuse | `SO_PEERPIDFD`/pidfd, start times in every identity, liveness re-checks (§5.1, §8.2) |
| AI agent sharing the user's terminal session | Ancestry + env-name signals; `ai_agents` prompt/deny (§8.6). Guardrail only. |
| Editing the policy to relax it | Integrity records; tighten-only when unapproved; lockdown on tamper (§9.4) |
| Rolling back the policy | Protected directory keeps only the latest digest (§9.4) |
| Password capture in tmux/tty | Documented; ssh-agent FIDO preferred (§8.4, §8.7) |
| Abuse of the forwarded ssh-agent | Touch required; challenge bound to peer + request; single use; 60 s (§8.7) |
| Fake polkit, D-Bus or `pkttyagent` | System bus path pinned; authority uid 0; fixed `/usr/bin/pkttyagent` with ownership check (§6.4, §8.4) |
| Rogue platform helper or rogue helper caller | Mutual verification with pid pinning; fail closed (§6.3) |
| User in the marker group | Detected → `Misconfigured`; `harden` refuses (§4.2, §4.4) |
| Hardlinked old hardened binaries | `fs.protected_hardlinks` warning; atomic replace (§3.1, §4.4) |
| Environment injection into a hardened agent (`HOME`, `XDG_*`, `DBUS_*`) | Integrity keyed by uid; system bus pinned. `servers.d` is unprotected (future work, §16). |
| Credentials after delivery to the user's command | Out of scope (§2.2) |
| Spoofed, redirected or suppressed notifications and URL opening | Not relied on for security; unprotected client settings by design. Helpers run with the marker dropped and receive only `http`/`https` URLs. (§10) |

Logging: authorization decisions go to the agent log at `info` (peer pid, session identity, server, rolespec, method, result, AI signals), never with credentials or signatures.

## 15. Operations

- **Kernel**: Linux ≥ 5.3 (pidfd) is required for hardened mode; ≥ 6.5 (`SO_PEERPIDFD`) is recommended. polkit was developed against 127.
- **Upgrade**: re-run `sudo mairu harden`, or let the package manager upgrade it. Running agents keep the old image until restarted; the existing version-divergence warning tells the user to run `mairu kill-agent`.
- **Uninstall**: `sudo mairu harden --uninstall [--purge]`, then optionally `groupdel mairu`.
- **Diagnostics**: `mairu doctor` (`GetAgentStatus`, `GetPolicy`, plus local checks) shows:
  - client and agent hardening, paths and versions
  - the caller as the agent sees it
  - capabilities and their notes
  - effective methods: polkit reachable and agent present, `SSH_AUTH_SOCK` reachable and registered keys present
  - policy integrity per store
  - grant and lease counts
  - warnings: protected hardlinks, marker membership, missing `SO_PEERPIDFD`, Secret Service unavailable, stale `SSH_AUTH_SOCK`, no tty

## 16. Scope

**In scope (Linux):** §4–§11 and the `mairu doctor`, `mairu lock`, `mairu policy`, `mairu harden` and `mairu platform-helper` commands.

**Out of scope, and future work:**
- macOS implementation (§12)
- BSD (§13)
- Tokens wrapped by TPM or Secure Enclave and unwrapped only for use, plus a zeroizing global allocator (`zeroizing-alloc`) so HTTP client buffers are wiped too
- Integrity for `servers.d` and `.mairu.json` trust records
- Agent-initiated login with browser opening
- AUR and Homebrew packaging changes (separate repositories)
- Linux hosts without polkitd: prompts are `UNAVAILABLE` there, so prompting roles fail closed, while ssh-agent and deny rules still work

## 17. Deliverables

Delivered as a `gh stack`, one PR per layer.

| Layer | Files |
|---|---|
| `hardening/spec` | `docs/specs/agent-hardening.md` |
| `hardening/marker-gid` | `src/hardening.rs`, `src/main.rs`, `src/agent.rs` (connect), `src/cmd/agent.rs` (listen, spawn), `src/cmd/exec.rs` (executor drop), `Cargo.toml` (`nix` features `user`, `socket`) |
| `hardening/peer-verification` | `src/platform/{mod,fallback}.rs`, `src/platform/linux/{mod,procfs,peer}.rs`, `proto/mairu_platform.proto`, `proto/mairu.proto` (`GetAgentStatus`, `AuthorizationError`), `build.rs`, `src/proto.rs`, `src/agent.rs`, `src/cmd/agent.rs` (`PeerStream`, replacement), `src/cmd/kill_agent.rs`, `src/cmd/doctor.rs`, `src/main.rs` |
| `hardening/install` | `src/cmd/harden.rs`, `src/hardening.rs` (re-exec, validation, suggestion), `pkg/debian/postinst`, `pkg/sysusers.d/mairu.conf`, `pkg/tmpfiles.d/mairu.conf` |
| `hardening/polkit` | `src/authorization.rs`, `src/platform/linux/polkit.rs`, `pkg/polkit/co.0w0.mairu.policy`, `proto/mairu.proto` (`ClientContext`, `RevokeAuthorizations`), `src/cmd/{exec,credential_process,lock}.rs`, `src/ecs_server.rs`, `Cargo.toml` (`zbus`, `zbus_polkit`, deb asset) |
| `hardening/headless` | `src/polkit_tty_agent.rs`, client retry paths, `src/cmd/doctor.rs` |
| `hardening/ai-agents` | `src/authorization.rs` (signals), `src/platform/linux/procfs.rs` (ancestry), client `env_names` |
| `hardening/policy` | `src/policy.rs`, `src/platform/linux/integrity.rs`, `proto/mairu.proto` (`GetPolicy`, `ApprovePolicy`), `src/cmd/policy.rs`, `Cargo.toml` (Secret Service crate) |
| `hardening/ssh-agent` | `src/ssh_agent_presence.rs`, `proto/mairu.proto` (challenge messages), client relay, `Cargo.toml` (`ssh-key`, `ssh-encoding`) |
| `hardening/notify` | `src/convenience.rs` (mode resolution, helper commands, rate limits), `src/config.rs` (`UserConfig.open_url`, `UserConfig.notify`), `src/platform/linux/{notify,open_url}.rs`, `proto/mairu.proto` (`OpenUrl`, `Notify`, `PingAgentResponse.policy_integrity`), `src/agent.rs`, `src/cmd/{login,exec}.rs` (`--no-browser`, event emission) |
| `hardening/platform-helper` | `src/platform/remote.rs`, `src/cmd/platform_helper.rs` |

Every layer also updates `README.md` and `CHANGELOG.md` (`[not yet released]`) for its feature, and this section's Current Status.

## Current Status

Spec drafted; awaiting review before implementation. Implementors MUST keep this section updated as they work.

### Checklist

Common:
- [ ] `mairu.platform` proto and `Platform` trait
- [ ] Agent RPCs: `GetAgentStatus`, `GetPolicy`, `ApprovePolicy`, `RevokeAuthorizations`; `ClientContext`; `AuthorizationError`
- [ ] `Authorizer`: rule selection, grants, leases, singleflight, evaluation order
- [ ] AI-agent signals
- [ ] Policy schema, tighten-only merge, integrity states, lockdown
- [ ] ssh-agent presence method
- [ ] `mairu doctor`, `mairu lock`, `mairu policy show|approve`

Linux:
- [ ] Marker gid confinement (`src/hardening.rs`)
- [ ] Peer verification, both directions; unverified-agent replacement
- [ ] `mairu harden` and re-exec; debian postinst; sysusers/tmpfiles snippets
- [ ] polkit backend and policy file; system bus and authority checks
- [ ] `pkttyagent` fallback
- [ ] Protected-directory and Secret Service integrity stores
- [ ] Notifications and open-url: backends, client-chosen modes (`auto|local|agent|command|none`), agent `OpenUrl`/`Notify` RPCs
- [ ] Platform helper with mutual verification
- [ ] Manual end-to-end verification: GUI session, SSH + tmux, headless

macOS (separate implementation, §12):
- [ ] Settle the Q items in §12 and write them back here
- [ ] Code-signature peer verification
- [ ] LocalAuthentication backend
- [ ] Integrity store
- [ ] Helper app with mutual verification
- [ ] Signing and notarization in the release workflow

BSD:
- [ ] Design only (§13)

Future:
- [ ] TPM/Secure Enclave token wrapping and zeroizing allocator
- [ ] `servers.d` and trust-record integrity
- [ ] AUR and Homebrew packaging updates

### Updates

- 2026-10-23: Spec drafted (Linux implementation plan, macOS brief).
- 2026-10-23: Notifications and URL opening moved to client-side emission with client-chosen modes (§10).
