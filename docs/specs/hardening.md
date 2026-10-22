# Agent hardening

Mutual verification between `mairu` clients and `mairu agent`, the hardened installation that anchors it, and the threat model shared by the related specs.

Related specs:

- [policy.md](policy.md): when the agent asks the human, how answers are remembered, and the Cedar policy that decides it.
- [platform-helper.md](platform-helper.md): the platform abstraction, the `mairu.platform` protocol, the optional out-of-process platform helper, and the platform backends (polkit, integrity stores, notifications, opening URLs).

## 1. Overview

`mairu agent` holds credential-server sessions in memory and vends AWS credentials to whoever connects to its Unix socket. Today that is any process running as the user. Nothing checks who the client is, nothing lets a client check who the agent is, and nothing asks the human before credentials leave the agent.

Together with the related specs, this work adds three things:

1. **Mutual verification** between `mairu` (clients) and `mairu agent`, anchored in a platform mechanism that same-user code cannot forge. Clients only talk to a genuine agent, and the agent only serves genuine clients. Covered here.
2. **Platform authorization.** The agent asks the human, through a platform facility, before vending credentials, and remembers the answer per terminal session for a short time. When to ask is decided by a [Cedar](https://www.cedarpolicy.com/) policy, in which a human check is just another condition, as MFA is in AWS IAM. The user's policy is integrity-protected. Covered in [policy.md](policy.md).
3. **A common platform protocol** (`mairu.platform`, protobuf) and a matching Rust trait, covering authorization prompts, integrity records, notifications and opening URLs, so the agent core stays platform-independent and an out-of-process helper can serve the same contract. Notifications and opening URLs carry no security weight, and each client chooses how they are delivered. Covered in [platform-helper.md](platform-helper.md).

Linux is implemented first, with WSL2 as a first-class variant (§8). macOS is designed in these specs and implemented separately against them. BSD is design-only.

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
- open the user's ptys (`/dev/pts/N` belongs to the user) and race the foreground program for keystrokes
- drive the user's tmux server through its socket: key bindings that log and forward every key, `send-keys`, and `pipe-pane -I` to inject input

### 2.2 Out of scope

Root, kernel compromise, physical access, and malicious credential servers or IdPs.

Escalation to root through the user's own `sudo` is also out of scope. If the user types the sudo password where same-user code can capture it ([platform-helper §6.1](platform-helper.md)), that code can become root. mairu cannot defend against that, and its guarantees hold only on hosts where sudo is not used that way, or is backed by FIDO. §2.4 covers this and the other routes to root.

Credentials *after delivery* are also out of scope. Once `mairu exec` hands credentials to the user's command, same-user code that can inspect that command (its environment, its memory, or the ECS bearer token in its environment) can take them. This design protects the agent's ability to mint credentials for arbitrary roles and its session tokens. It does not protect credentials already given to an unprotected process.

### 2.3 What is a boundary and what is a guardrail

- **Boundary**:
  - The platform authorization step (polkit, macOS LocalAuthentication, or the ssh-agent FIDO touch).
  - The mutual verification that makes the prompt's contents truthful: a genuine client reports what it will actually do with the credentials.
  - Integrity of the policy that decides when to prompt.
- **Guardrails**, best-effort and never relied on alone:
  - AI-agent detection ([policy §5](policy.md))
  - `disallow_roles` in `config.json`
  - the `.mairu.json` trust prompt

### 2.4 Trust chain and the weakest link

On a hardened Linux host every anchor is root-owned:
- the setgid binary
- the polkit action file
- the integrity records in `/var/lib/mairu`, including the approval anchor that says which keys may approve policy changes ([policy §9.7](policy.md))

Root can replace any of these, and can also read the agent's memory directly. **Every guarantee in these specs is therefore bounded by how hard it is for same-user code to become root.**

Ways a same-user attacker reaches root:

| Path | How |
|---|---|
| `sudo`, `su` | PAM, usually the user's password, which is capturable at a tty ([platform-helper §6.1](platform-helper.md)). Also `NOPASSWD` rules and cached sudo timestamps. |
| polkit administrator actions | `auth_admin` actions such as `pkexec` and systemd units; PAM again |
| Root-equivalent group memberships | `docker`, `lxd`, `incus-admin`, `disk` |
| WSL2 interop | `wsl.exe -u root` (§8) |

The effective strength of a deployment is the **weakest** of:
1. becoming root
2. approving a policy change (`approval_methods`, [policy §9.5](policy.md), anchored in the protected record)
3. the presence methods that a role's `permit` policies accept (`context.presence.method`)

Registering a FIDO or Windows Hello key strengthens 2 and 3. It does nothing for 1. A password that passes `sudo` also passes polkit `auth_self` ([platform-helper §6.1](platform-helper.md)), so on a host where that password can be captured, key-based methods only add a guardrail.

Recommendations (README; `mairu doctor` warns where it can detect the condition, §12):
- Back `sudo` and the `polkit-1` PAM stack with FIDO: `pam_u2f` locally, `pam_ssh_agent_auth` with an `sk-` key over SSH, `pam_wsl_hello` on WSL2. Avoid `NOPASSWD` and root-equivalent groups for the user.
- Once keys are registered, keep `approval_methods` key-only (the default, [policy §9.5](policy.md)), and require a key-based `context.presence.method` in permits for sensitive roles.
- On WSL2, disable interop for strong guarantees (§8).

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

Both sides also require the hardened-runtime flag and the absence of `com.apple.security.get-task-allow`. The agent keeps `PT_DENY_ATTACH`. Use the audit token's pid version (`audit_token_to_pidversion`) wherever a pid is recorded. Details, and the questions still open, are in §9.

## 4. Hardened installation (Linux)

### 4.1 Layout

| Path | Owner | Mode | Purpose |
|---|---|---|---|
| `/usr/local/libexec/mairu/mairu` | `root:mairu` | `2755` | Hardened binary installed by `mairu harden` |
| `/usr/bin/mairu` | `root:mairu` | `2755` | Hardened binary installed by distro packages |
| `/usr/local/libexec/mairu/.harden-manifest` | `root:root` | `0644` | Files written by `mairu harden`, for `--uninstall` |
| `/usr/share/polkit-1/actions/co.0w0.mairu.policy` | `root:root` | `0644` | polkit actions ([platform-helper §6.1](platform-helper.md)) |
| `/var/lib/mairu` | `root:mairu` | `2770` | Protected state root. Users cannot traverse it, but the marker gid can. |
| `/var/lib/mairu/users` | `root:mairu` | `2770` | |
| `/var/lib/mairu/users/<uid>` | `<uid>:mairu` | `0700` | Per-user integrity records ([policy §9.7](policy.md)). Created by the agent with the marker gid held. |

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

`mairu harden --reset-policy-record --user <name>` deletes that user's `/var/lib/mairu/users/<uid>/policy.record`, the recovery path for lost approval keys ([policy §9.9](policy.md)).

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
3. Read `/proc/<pid>/stat` (§6) for `start_time`, then confirm the pidfd still refers to a live process (`pidfd_send_signal(pidfd, 0)`) so the values read belong to it.
4. Compute trust:

   | Agent state | Peer gid | `PeerTrust` |
   |---|---|---|
   | Hardened | `mairu` | `Verified` |
   | Hardened | anything else | `Rejected` |
   | Unhardened or Misconfigured | any | `Unverifiable` |

Each handler calls `require_trusted(&request)`. `Rejected` peers get `PERMISSION_DENIED` with `AuthorizationError{reason: UNVERIFIED_PEER}` ([policy §10.1](policy.md)) on every RPC except `PingAgent` and `GetAgentStatus`, which stay open so unverified binaries can diagnose themselves. `Unverifiable` peers are served as they are today.

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

## 6. Process facts (Linux)

`src/platform/linux/procfs.rs` parses `/proc/<pid>/stat` by splitting at the **last** `)` (comm may contain spaces and parentheses), giving:

- field 4 `ppid`
- 5 `pgrp`
- 6 `session`
- 7 `tty_nr`
- 22 `starttime` (clock ticks since boot)

It also reads `/proc/<pid>/comm`, `/proc/<pid>/exe` (readlink; may fail), and `/proc/<pid>/cmdline` (argv split on NUL, and only used for display and AI matching). Every read is followed by a pidfd or start-time liveness check so the values cannot belong to a recycled pid.

## 7. Agent status and compatibility

### 7.1 `GetAgentStatus`

```proto
service Agent {
  // ... existing RPCs ...
  rpc GetAgentStatus(GetAgentStatusRequest) returns (GetAgentStatusResponse);
}

enum HardeningState {
  HARDENING_STATE_UNSPECIFIED = 0;
  HARDENING_STATE_UNHARDENED = 1;
  HARDENING_STATE_HARDENED = 2;
  HARDENING_STATE_MISCONFIGURED = 3;
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
```

`GetAgentStatus` and `PingAgent` stay open to unverified peers so that unverified binaries can diagnose themselves (§5.1). `PolicyIntegrity` is defined in [policy §10](policy.md) and `mairu.platform.Capabilities` in [platform-helper §3](platform-helper.md). Every other RPC refuses a `Rejected` peer with `AuthorizationError{reason: REASON_UNVERIFIED_PEER}` ([policy §10](policy.md)).

### 7.2 Compatibility

- New fields are optional. An old client talking to a new agent sends no `ClientContext`, and the agent then treats intent as unknown: no lease, and `command` is shown as "(unknown)".
- An old agent ignores unknown fields.
- Versions already diverge noisily (the existing `PingAgent` warning). Hardened deployments run one binary, so mixed versions are transitional.

## 8. WSL2

WSL2 runs a real Linux kernel in a lightweight VM, so everything in these specs applies inside a distribution unchanged. Two things differ: Windows interop, and the authenticators available on the Windows side. WSL1 translates system calls instead of running a Linux kernel, and is not supported for hardening. On WSL1, `doctor` reports `HARDENING_STATE_MISCONFIGURED`.

### 8.1 Detection (agent)

- **WSL2**: `/proc/sys/kernel/osrelease` contains `microsoft-standard-WSL2`, and `/run/WSL` exists.
- **Interop enabled**: `/proc/sys/fs/binfmt_misc/WSLInterop` (or `WSLInterop-late`) exists, and its first line is `enabled`.

These facts are agent-determined and feed `context.wsl_interop` ([policy §9.2](policy.md)), `GetAgentStatus` capability notes and `doctor`.

### 8.2 Interop makes root reachable

With interop enabled, any process in the distribution can run Windows programs as the Windows user, including `wsl.exe`. `wsl.exe -u root` opens a root shell in the distribution without authentication. This is documented from the Windows side; **Q-W1** confirms it from inside a session.

So with interop on, same-user Linux code can become root and bypass the marker group, the protected directory and the agent's memory protection (§2.4). mairu still runs hardened in this mode, reports `context.wsl_interop = true`, and `harden` and `doctor` warn.

Windows-side code running as the same Windows user can do this with or without interop. Like root, it is outside the threat model: on WSL2 the Windows account sits at the top of the trust chain.

### 8.3 Profiles

| | Integrated (interop on, the WSL default) | Isolated (interop off) |
|---|---|---|
| Root reachable by same-user Linux code | Yes, through `wsl.exe -u root` | No; as native Linux |
| Strength | A guardrail against over-eager tools such as AI agents, and against accidents. Not a boundary against malicious code. | As native Linux (§2.4) |
| Presence methods | `windows-hello` ([policy §6.3](policy.md)). `ssh-agent` through a relay of the Windows OpenSSH agent (npiperelay + socat, or `wsl2-ssh-agent`). `platform` through `pkttyagent`. | `ssh-agent`, by SSHing into the distribution from Windows with `ssh -A`. This is the headless reference workflow ([platform-helper §9](platform-helper.md)). `platform` through `pkttyagent`. |
| `open_url` in `auto` mode | The Windows default browser: `wslview` when installed, otherwise `explorer.exe <url>` | URL printed, or `command` mode |
| `notify` in `auto` mode | None. Use `command` mode with a Windows toast helper. | None |
| Secret Service | Usually absent | Usually absent |

To disable interop, write `/etc/wsl.conf` and then restart the distribution from Windows (`wsl.exe --terminate <distro>`). Turning it back on requires root inside the distribution, or Windows-side access.

```ini
[interop]
enabled = false
appendWindowsPath = false
```

### 8.4 Integration points

- **`open_url` and `notify`**: [platform-helper §10](platform-helper.md).
- **`doctor`** reports:
  - the WSL version, interop state and profile in effect
  - whether the Windows Hello helper is reachable and its key enrolled
  - whether a relayed Windows OpenSSH agent is reachable
- **`harden`** on WSL2 with interop enabled proceeds, but prints the root-reachability warning and how to disable interop.
- **Policy.** `context.wsl_interop` lets a policy refuse sensitive roles while interop is on:

  ```cedar
  @id("no-prod-with-interop")
  forbid (principal, action, resource in Mairu::Account::"999999999999")
  when { context has wsl_interop && context.wsl_interop };
  ```

- **`sudo`.** `pam_wsl_hello` (WSL-Hello-sudo) backs `sudo` with Windows Hello, which addresses the `sudo` row of §2.4. It cannot close the interop row.

### 8.5 Open questions (need a WSL2 host)

- **Q-W1**: `wsl.exe -u root` started from inside a WSL2 session obtains root without authentication.
- **Q-W2**: the padding of KeyCredential signatures, PSS or PKCS #1 v1.5. Microsoft's documentation contradicts itself; pin it with a test vector.
- **Q-W3**: whether Windows OpenSSH's FIDO support (`webauthn.dll`) can use Windows Hello itself as the authenticator on current builds. Reports vary by build. If it can, the isolated profile gets Windows Hello through ssh-agent forwarding with no helper at all.
- **Q-W4**: whether a channel that doesn't use interop is practical for Windows Hello in the isolated profile. For example, a Hyper-V socket (`AF_VSOCK`) to a Windows-side service; registering one needs Windows administrator rights.
- **Q-W5**: how WSLg should influence `auto` modes beyond [platform-helper §10](platform-helper.md).

## 9. macOS hardening (implemented separately)

This section and [platform-helper §11](platform-helper.md) are the brief for the macOS implementation. Items marked **Q** must be settled there and written back into these specs.

1. **Distribution and signing.**
   - Release binaries (`aarch64-apple-darwin`, `universal-apple-darwin`) become Developer ID–signed with hardened runtime (`-o runtime`), identifier `co.0w0.mairu`, and notarized. This changes the release workflow.
   - **Q:** Homebrew builds from source are ad-hoc signed and live in user-writable `/opt/homebrew`. Mirror §4: a `sudo mairu harden` that copies to root-owned `/usr/local/libexec/mairu/mairu`, signs it ad-hoc with `-o runtime`, and adds re-exec. The self-DR then pins the cdhash.
2. **Peer verification** (§3.2) on the existing Unix socket, in both directions. **Q:** confirm that `LOCAL_PEERTOKEN` on the *client's* connected socket yields the listener's token (the counterpart of Linux listen-time credentials); if not, the agent proves itself another way, such as XPC with a code-signing requirement.
3. **Process facts** (the counterpart of §6):
   - `proc_pidinfo(PROC_PIDTBSDINFO)`: start time `pbi_start_tvsec/usec`, `pbi_ppid`, `e_tdev` for the tty
   - `getsid` for the session
   - `proc_pidpath` for the executable
   - Pid reuse defeated with the audit-token pid version
4. **Trust chain.** On macOS the top of the trust chain (§2.4) is the administrator account: `sudo`, and authorization rights in `/etc/authorization`.

## 10. BSD (design only)

- FreeBSD `LOCAL_PEERCRED` (`struct xucred`, `cr_groups[0]` is the effective gid, `cr_pid` on 13+), with the setgid marker as on Linux.
- Process facts from `kinfo_proc` via `sysctl`.
- polkit is in ports.
- `harden` would use `pw groupadd`.
- `crate::ppid` already handles `PROC_PDEATHSIG_CTL`.

## 11. Security considerations

| Threat | Mitigation |
|---|---|
| Rogue client process | Marker gid via `SO_PEERCRED` at `connect()` (§5.1) |
| Genuine binary run with arbitrary arguments | Authorization prompt shows truthful client-reported intent ([policy §7](policy.md)) |
| `LD_PRELOAD` or ptrace into the genuine binary | `AT_SECURE`, non-dumpable, setgid dropped under ptrace (§3.1) |
| Marker leaking to children | Permanent drop before every exec; `hardening::command()` (§4.2) |
| Socket squatter or rogue agent stealing OAuth codes | Client checks the agent's listen-time marker (§5.2); hardened clients replace unverified agents (§5.3) |
| Pid reuse | `SO_PEERPIDFD`/pidfd, start times in every identity, liveness re-checks (§5.1, §6) |
| Root reached through `sudo`/polkit passwords, `NOPASSWD`, root-equivalent groups | Out of scope, but it bounds everything (§2.4); `doctor` warns (§12) |
| Root reached through WSL2 interop (`wsl.exe -u root`) | Isolated profile, or `context.wsl_interop` forbids; `doctor` and `harden` warn (§8) |
| User in the marker group | Detected → `Misconfigured`; `harden` refuses (§4.2, §4.4) |
| Hardlinked old hardened binaries | `fs.protected_hardlinks` warning; atomic replace (§3.1, §4.4) |
| Environment injection into a hardened agent (`HOME`, `XDG_*`, `DBUS_*`) | Integrity keyed by uid ([policy §9.1](policy.md)); system bus pinned ([platform-helper §5](platform-helper.md)). `servers.d` is unprotected (future work, §13). |
| Credentials after delivery to the user's command | Out of scope (§2.2) |

Authorization-related threats are in [policy §11](policy.md), and helper- and backend-related ones in [platform-helper §12](platform-helper.md).

## 12. Operations

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
  - root reachability (§2.4):
    - `sudo -n true` succeeding, meaning `NOPASSWD` or a cached timestamp; run through `hardening::command()`
    - membership in `docker`, `lxd`, `incus-admin` or `disk`
    - WSL2 interop (§8)
    - `"platform"` in an anchored `approval_methods` while keys are registered

## 13. Scope

**In scope (Linux):** §3–§8, plus the `mairu harden` and `mairu doctor` commands. The WSL2 parts can be built on Linux; verifying §8.5 needs a Windows host with WSL2.

**Out of scope, and future work:**
- macOS implementation (§9)
- WSL1 hardening (§8)
- BSD (§10)
- Tokens wrapped by TPM or Secure Enclave and unwrapped only for use, plus a zeroizing global allocator (`zeroizing-alloc`) so HTTP client buffers are wiped too
- Integrity for `servers.d` and `.mairu.json` trust records
- AUR and Homebrew packaging changes (separate repositories)

## 14. Deliverables and stack

The three specs are delivered together as one `gh stack`, one PR per layer, in this order. Each layer updates `README.md`, `CHANGELOG.md` (`[not yet released]`) and the Current Status of every spec it implements.

| Layer | Specs | Files |
|---|---|---|
| `hardening/spec` | all | `docs/specs/{hardening,policy,platform-helper}.md` |
| `hardening/marker-gid` | hardening | `src/hardening.rs`, `src/main.rs`, `src/agent.rs` (connect), `src/cmd/agent.rs` (listen, spawn), `src/cmd/exec.rs` (executor drop), `Cargo.toml` (`nix` features `user`, `socket`) |
| `hardening/peer-verification` | hardening, platform-helper | `src/platform/{mod,fallback}.rs`, `src/platform/linux/{mod,procfs,peer}.rs`, `proto/mairu_platform.proto`, `proto/mairu.proto` (`GetAgentStatus`, `AuthorizationError`), `build.rs`, `src/proto.rs`, `src/agent.rs`, `src/cmd/agent.rs` (`PeerStream`, replacement), `src/cmd/kill_agent.rs`, `src/cmd/doctor.rs`, `src/main.rs` |
| `hardening/install` | hardening | `src/cmd/harden.rs` (including `--reset-policy-record`), `src/hardening.rs` (re-exec, validation, suggestion), `src/cmd/doctor.rs` (root-reachability warnings), `pkg/debian/postinst`, `pkg/sysusers.d/mairu.conf`, `pkg/tmpfiles.d/mairu.conf` |
| `hardening/authorization` | policy, platform-helper | `src/authorization.rs`, `src/policy/{mod.rs,mairu.cedarschema,builtin/*.cedar}`, `src/platform/linux/polkit.rs`, `pkg/polkit/co.0w0.mairu.policy`, `proto/mairu.proto` (`ClientContext`, `RevokeAuthorizations`), `src/cmd/{exec,credential_process,lock}.rs`, `src/ecs_server.rs`, `Cargo.toml` (`cedar-policy`, `zbus`, `zbus_polkit`, deb asset) |
| `hardening/headless` | platform-helper | `src/polkit_tty_agent.rs`, client retry paths, `src/cmd/doctor.rs` |
| `hardening/ai-agents` | policy | `src/authorization.rs` (signals), `src/platform/linux/procfs.rs` (ancestry), client `env_names` |
| `hardening/policy` | policy, platform-helper | `src/policy/{files,integrity_state,settings}.rs`, `src/platform/linux/integrity.rs`, `proto/mairu.proto` (`GetPolicy`, `ApprovePolicy`), `src/cmd/policy.rs`, `Cargo.toml` (Secret Service crate) |
| `hardening/ssh-agent` | policy | `src/ssh_agent_presence.rs`, `proto/mairu.proto` (challenge messages), client relay, `Cargo.toml` (`ssh-key`, `ssh-encoding`) |
| `hardening/wsl` | hardening, policy, platform-helper | `src/platform/linux/wsl.rs` (detection, `wsl_interop`, Windows-side `open_url`), `src/windows_hello.rs`, `windows-hello-helper/`, `src/cmd/policy.rs` (`enroll-windows-hello`), `proto/mairu.proto` (`windows_hello_signature`), `.github/workflows/release.yml`, README WSL2 guide |
| `hardening/notify` | platform-helper | `src/convenience.rs`, `src/config.rs` (`UserConfig.open_url`, `UserConfig.notify`), `src/platform/linux/{notify,open_url}.rs`, `proto/mairu.proto` (`OpenUrl`, `Notify`, `PingAgentResponse.policy_integrity`), `src/agent.rs`, `src/cmd/{login,exec}.rs` |
| `hardening/platform-helper` | platform-helper | `src/platform/remote.rs`, `src/cmd/platform_helper.rs` |

## Current Status

Spec drafted; awaiting review before implementation. Implementors MUST keep this section updated as they work.

### Checklist

Linux:
- [ ] Marker gid confinement (`src/hardening.rs`)
- [ ] Peer verification, both directions; unverified-agent replacement
- [ ] `GetAgentStatus` and `mairu doctor`
- [ ] `mairu harden` and re-exec; debian postinst; sysusers/tmpfiles snippets
- [ ] Root-reachability warnings in `doctor`; `harden --reset-policy-record`
- [ ] Manual end-to-end verification across all three specs: GUI session, SSH + tmux, headless

WSL2 (§8):
- [ ] Detection and `context.wsl_interop`
- [ ] Settle Q-W1 and Q-W4 on a WSL2 host

macOS (separate implementation, §9):
- [ ] Settle the Q items in §9 and write them back here
- [ ] Code-signature peer verification
- [ ] Signing and notarization in the release workflow

BSD:
- [ ] Design only (§10)

Future:
- [ ] TPM/Secure Enclave token wrapping and zeroizing allocator
- [ ] `servers.d` and trust-record integrity
- [ ] AUR and Homebrew packaging updates

### Updates

- 2026-10-23: Drafted as part of a single combined spec, `docs/specs/agent-hardening.md`.
- 2026-10-23: Corrected the tty password-capture vectors and stated `sudo` escalation as out of scope.
- 2026-10-23: Added the trust chain and weakest-link analysis (§2.4) and the WSL2 profiles (§8).
- 2026-10-23: Split into hardening, policy and platform-helper specs.
