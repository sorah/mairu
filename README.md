# Mairu

Mairu is a AWS credentials manager to securely grant AWS access to command-line tools and scripts __providing a right fine-grained IAM role access to scripts and commands, per-project.__

Mairu can retrieve credentials from __AWS SSO (AWS IAM Identity Center),__ or a credential vending server implements the Mairu API.

## Key features

- __Grant credentials explicitly via `mairu exec` command__ - instead of implicit global configuration or AWS profiles
- __In-memory credentials storage__ - No credentials left on disk
- __AWS SSO support__ (and you can bring your own server)
- __Automatic role switching__ - per-workspace configuration `.mairu.json` instructs a correct IAM role to assume

## Installation

* __Cargo:__ `cargo install --locked mairu` <sup>[[crate](https://crates.io/crates/mairu)]</sup>
* __Mise:__ `mise use -g github:sorah/mairu`
* __Aqua:__ sorah/mairu <sup>[[source](https://github.com/aquaproj/aqua-registry/tree/main/pkgs/sorah/mairu)]</sup>
* __Homebrew Tap:__ `brew install sorah/sorah/mairu` <sup>[[tap](https://github.com/sorah/homebrew-sorah)]</sup>
* __Arch Linux AUR:__ [mairu](https://aur.archlinux.org/packages/mairu), [mairu-bin](https://aur.archlinux.org/packages/mairu-bin)
* __Binary:__ Binaries for Linux and macOS are available at https://github.com/sorah/mairu/releases
  * `mairu-{x86_64,aarch64}-unknown-linux-musl.tar.gz` for Linux, `mairu-{x86_64,aarch64}-apple-darwin.tar.gz` for macOS
  * Keep every file of the archive next to `mairu`, as it may ship helpers.
  * Each `mairu` binary carries a GitHub artifact attestation. Verify a download with `gh attestation verify mairu --repo sorah/mairu`.

On Linux, harden the installation afterwards with `sudo mairu harden`; see [Hardening](#hardening).

## Get started

Mairu can be used like the following cases. In any case, Mairu automatically retrieves a AWS credential for specified role and prompts user to login when server token is expired or doesn't exist yet.

### 1. Configure Mairu for your AWS SSO instance

```
$ mairu setup-sso contoso --region ${aws_sso_region} --start-url https://my-aws-sso-domain.awsapps.com/start
```

### 2. Use as a executor

```
$ mairu exec --server=contoso 123456789999/AmazingAppDevelopment rails server
```

or, utilize Mairu's `auto` role feature like as follows:

```
$ echo '{"role": "123456789999/AmazingAppDevelopment", "server": "https://my-aws-sso-domain.awsapps.com/start"}' > my-project/.mairu.json
$ cd my-project
$ mairu exec auto rails server
```

### 3. Use as a credential process provider

```ini
# ~/.aws/config
[profile mairu_amazing_app]
credential_process = mairu credential-process contoso 123456789999/AmazingAppDevelopment
```

then

```
$ AWS_PROFILE=mairu_amazing_app rails server
```

## Configuration

Mairu reads `~/.config/mairu/servers.d/*.json` for a credential server information:

### AWS IAM Identity Center (AWS SSO)

To quickly generate:

```
$ mairu setup-sso ${choose_server_id} --region ${aws_sso_region} --start-url https://...awsapps.com/start
```

Or create by hand:

```jsonc
{
    "url": "https://...awsapps.com/start",
    "id": "server_id", // Optional, default to {url}
    "aws_sso": {
      "region": "us-east-1"
    }
}
```

### Mairu Assume Role Credentials API

```jsonc
{
    "url": "https://cred-server.example.com/", // Trailing slash is important https://docs.rs/url/latest/url/struct.Url.html#method.join
    "id": "my-credential-server", // Optional, default to {url}

    "oauth": {
        "client_id": "...",
        "client_secret": "...", // Optional

        "token_endpoint": "...", // Optional if token_endpoint is at ${url}/oauth/token
        "scope": [], // Optional, default to ["profile"]

        // Either device_grant or code_grant is required.
        // Even if configuration is empty, an empty object (e.g. "code_grant": {}) must be present to denote a support of grant type.
        "device_grant": {
            "device_authorization_endpoint": "...", // Omit if it is at ${url}/oauth/device
        },
        "code_grant": {
            "authorization_endpoint": "...", // Omit if it is at ${url}/oauth/authorize
            "local_port": 16624, // Optional. default to ephemeral port.
            "use_localhost": false, // Optional, default to false (http://127.0.0.1). Use http://localhost for redirect_uri. Has to be true for some issuers, i.e. Microsoft (public client).
        },
        "default_grant_type": "code_grant", // Optional
    }
}
```

### How to choose a Server ID

It is recommended to use the same `id` for your entire organisation. Personal preferences can be stored in other location, so it is safe to distribute the servers.d file with MDM or something else.

To learn how to prepare your credential server, continue reading at [Credential Server](#credential-server) section.

### Personal configuration

Mairu reads `~/.config/mairu/config.json` for personal preferences, separately from `servers.d`.

#### Disallowing roles

List roles in `disallow_roles` to make Mairu refuse to vend credentials for them (via `mairu exec` and `mairu credential-process`). `server` is a server ID or URL, and `role` must match exactly as shown in `mairu list-roles`.

```jsonc
{
    "disallow_roles": [
        {"server": "contoso", "role": "123456789999/AdministratorAccess"}
    ]
}
```

This is a local safety net against accidental use, not an access control; permissions are still governed by your credential server.

`harden_home` and `harden_suggestion` are described under [Hardening](#hardening).

### Local port for callback URL

Mairu uses ephemeral port number for OAuth 2.0 callback URLs. Otherwise, you can specify `--local-port` (or `.oauth.local_port`, `.aws_sso.local_port`) to use fixed port number.

## Usage in detail

### `auto` role

Mairu treats `auto` role as a special mode. It reads closest `.mairu.json` file <!-- or `MAIRU_ROLE` environment variable --> as a JSON object as follows to determine a role to assume:

```jsonc
{
    "server": "server id or url to use", // Equivalent to --server cli argument
    "role": "role to assume",
    "mode": "preferred credential provider method", // optional
}
```

If it is read by a filesystem, Mairu prompts user to trust that file for the first time. And prompt appears again if the file content has been changed.

Trust is shared across git worktrees; a `.mairu.json` in a linked worktree is trusted when the equivalent path in the repository's main checkout has been trusted with the same content. Set `MAIRU_NO_WORKTREE_TRUST=1` to prompt separately for each worktree.

We recommend use `auto` role by default. This allows using per-project AWS role seamlessly, securely and concurrently! It would also be convenient to have `alias ae="mairu exec auto "` in your shell profile.

### Role chaining

You can chain an additional `sts:AssumeRole` call after obtaining credentials from the credential server. This is useful when your SSO role needs to assume a different IAM role (e.g. cross-account access).

```
$ mairu exec --server=contoso --assume-role=arn:aws:iam::123456789012:role/TargetRole 999999999999/SSORole rails server
```

The following options are available for both `mairu exec` and `mairu credential-process`:

- `--assume-role` — ARN of the role to assume using the first-hop credentials
- `--assume-role-session-name` — Override the role session name (default: derived from the first-hop caller identity, falling back to `$USER`, then `"mairu"`)
- `--assume-role-duration-seconds` — Override session duration in seconds
- `--assume-role-external-id` — External ID for the AssumeRole call

This can also be configured in `.mairu.json` via the `assume_role` field:

```jsonc
{
    // ... other fields
    "assume_role": { // optional, see "Role chaining" section
        "role_arn": "arn:aws:iam::123456789012:role/TargetRole",
        "external_id": "...", // optional
        "role_session_name": "...", // optional
        "duration_seconds": 3600 // optional
    }
}
```

### Reauthentication

If your session with a credential server expired, Mairu prompts you to reauthenticate yourself. For existing processes under `mairu exec`, you'll see a warning message including a command line to start reauthentication flow. 

### Credential provider modes

`mairu exec` supports the following methods to provide credentials to AWS SDK. Choose your best way to pass obtained credentials to your app or tools you love:

- `ecs` (default): Run ephemeral server to emulate [container provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html). AWS_CONTAINER_CREDENTIALS_FULL_URI and AWS_CONTAINER_AUTHORIZATION_TOKEN environment variable will be exposed and supports automatic renewal.
- `static`: Expose traditional AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN environment variables ([static credentials](https://docs.aws.amazon.com/sdkref/latest/guide/feature-static-credentials.html)). This method doesn't support automatic renewal, so you have to restart `mairu exec` when credentials have expired.

<!-- TODO: - `docker`: Similar to `ecs`, but launch a proxy container on Docker to connect Mairu agent from Docker containers. See [Docker support](#docker-support) for details. AWS_CONTAINER_CREDENTIALS_FULL_URI and AWS_CONTAINER_AUTHORIZATION_TOKEN environment will be exposed and supports automatic renewal. -->

Your preferred method can be specified in `--mode`:

```
$ mairu exec --mode=static auto rails server
```

Alternatively, you can use Mairu `mairu credential-process` command for [process credential provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html).

<!--

### Docker support

TBD

-->

### Agent process

Mairu automatically launches agent process in background. This is similar to ssh-agent and gpg-agent. Mairu Agent retains all access tokens for credential server, and caches AWS credentials for re-use on memory.

It listens on `$XDG_RUNTIME_DIR/mairu/mairu-agent.sock` (or `~/.local/state/mairu/run/mairu-agent.sock`) by default. `MAIRU_AGENT_SOCK` overrides the path.

Debug builds (`cargo build`) use a separate `dev` profile, so a development build never touches your installed agent: the agent listens on `mairu-dev-agent.sock` and keeps state in `~/.local/state/mairu-dev`, while configuration in `~/.config/mairu` is shared. `MAIRU_PROFILE=dev` or `MAIRU_PROFILE=default` overrides the build's default.

The agent runs platform services (desktop prompts, notifications and the like) in a child process, `mairu platform-helper`, which holds no tokens. The two check each other, the helper exits with the agent, and the agent restarts a helper that died within 30 seconds; until then those services fail closed.

`mairu doctor` shows how the client and the agent see each other, the state of the platform helper and of authorization, and warns about setups that weaken them.

### Browser and notifications

`mairu login` (and the login inside `mairu exec`) opens the authorize URL in your browser, and clients post a desktop notification when a `mairu exec` needs a login (once per server per 10 minutes), when a request from an AI agent is refused (once per role per minute), and when the policy is in lockdown (once per agent). The URL and messages are printed on the terminal either way.

Each client chooses how, separately for `open_url` and `notify`:

| Mode | Behavior |
|---|---|
| `auto` (default) | `open_url`: `$BROWSER` when set, otherwise `agent`. `notify`: `agent`. |
| `agent` | The agent's platform helper opens the URL through the desktop portal (or `xdg-open`) and posts through `org.freedesktop.Notifications`, on the desktop session of the requesting client. Over SSH without a display, nothing happens. On WSL2 with interop, URLs open in the Windows default browser (see [WSL2](#wsl2)). |
| `command` | Runs your own program. |
| `none` | Disabled. |

`--no-browser` on `mairu login` and `mairu exec`, then `MAIRU_OPEN_URL` / `MAIRU_NOTIFY`, then `config.json`, choose the mode:

```jsonc
{
    "open_url": {"mode": "command", "command": ["my-open-url"]},
    "notify": {"mode": "none"}
}
```

`MAIRU_OPEN_URL_COMMAND` / `MAIRU_NOTIFY_COMMAND` hold a shell command line and imply `command` mode. A program receives the URL as its last argument, or a notification's title and body as its last two, with `MAIRU_NOTIFY_URGENCY` (`low`, `normal`, `critical`) and `MAIRU_NOTIFY_EVENT` (`login-required`, `ai-agent-denied`, `policy-lockdown`) set. Only `http` and `https` URLs are ever opened. Programs run without the `mairu` group and are not waited on for more than 5 seconds.

```sh
# A notify-send wrapper
export MAIRU_NOTIFY_COMMAND='notify-send --app-name=mairu --urgency="$MAIRU_NOTIFY_URGENCY"'

# tmux over SSH: show notifications in the status line
export MAIRU_NOTIFY_COMMAND='tmux display-message -d 10000'

# tmux over SSH: open URLs on your laptop, which listens with
#   socat UNIX-LISTEN:$HOME/.open-url.sock,fork EXEC:'xargs -n1 open'
# and connects with `ssh -R /home/you/.open-url.sock:$HOME/.open-url.sock host`
export MAIRU_OPEN_URL_COMMAND='~/bin/open-url-remote'
```

```sh
#!/bin/sh
# ~/bin/open-url-remote
printf '%s\n' "$1" | socat - "UNIX-CONNECT:$HOME/.open-url.sock"
```

`mairu doctor` shows the mode of each and whether the agent can deliver to your session.

## Hardening

On Linux, `mairu harden` lets the agent tell genuine mairu clients apart from other programs running as you. It installs a root-owned copy of mairu, setgid to a dedicated `mairu` group, and every mairu command then runs through that copy. Root is needed once per host, and again for upgrades.

### First install

Run `harden` from a copy of mairu you trust, as `sudo` runs it as root:

```sh
gh attestation verify mairu --repo sorah/mairu   # a release binary, from its archive
sudo ./mairu harden
```

The Debian package from the releases page is hardened on install, and needs no `harden`.

`harden` creates the `mairu` system group (it must have no members), installs `/usr/local/libexec/mairu/mairu` as `root:mairu 2755` with `cap_ipc_lock`, along with the helpers shipped next to it, creates `/var/lib/mairu`, which only hardened mairu can open, and installs the polkit actions at `/usr/share/polkit-1/actions/co.0w0.mairu.policy`. It is safe to run again. The next mairu command replaces an agent started before hardening; `mairu kill-agent` does it right away.

Other installations (mise, cargo, aqua, tarballs) keep working: they run the hardened copy instead of themselves, and say so when its version differs. `MAIRU_NO_HARDENED_REEXEC=1` turns this off, for development; debug builds never do it unless `MAIRU_PROFILE=default` is set. `mairu doctor` shows which mairu ran and which hardened copies exist.

### Authorization

A hardened agent asks a human before it hands out credentials, through polkit: the first `mairu exec` or `credential-process` for a role in a terminal shows a polkit authentication dialog, and the terminal prints what is being approved:

```
:: mairu :: Authorization may be required: 123456789012/Admin on contoso
:: mairu ::   command: terraform apply
:: mairu ::   cwd:     /home/u/src/infra
:: mairu ::   from:    /dev/pts/3 (zsh, tmux pane)
:: mairu :: Approve in the system dialog if one appears.
```

The approval is remembered in memory only, and only for that server and role:

- per terminal session (a terminal tab, an SSH login, a tmux pane), for 5 minutes since its last use and 12 hours at most;
- per running `mairu exec`, for as long as it runs, until it goes an hour without asking for credentials. Its background refresh never prompts.

Callers without a terminal, such as an IDE running `credential-process`, are remembered per parent process. A new terminal asks again, and so does every request after the agent restarts.

`mairu lock` makes the agent forget every approval; `--session` forgets only those of the current terminal session, and `--running` also those of running `mairu exec`, which then ask again on their next refresh.

An unhardened agent never asks. `mairu doctor` shows the remembered approvals and whether polkit can be used.

Before vending credentials, a hardened agent also asks AWS STS who they belong to (`sts:GetCallerIdentity` at `sts.amazonaws.com`, once per credential set, cached with them). Credentials whose account differs from the one the role name declares (`123456789012/Admin`, or a role ARN) are refused:

```
Error: refused at use-credentials: refused by policy (policies: builtin-caller-account-mismatch): credentials belong to 999999999999 (arn:aws:sts::999999999999:assumed-role/Admin/alice), not to the account the role name declares (123456789012)
```

If STS cannot be reached, a hardened agent vends nothing. Roles outside the `aws` partition, and networks that reach STS only through a VPC endpoint, cannot be served by a hardened agent for now.

### AI coding tools

AI coding agents run commands in your terminal session, as you. A remembered approval would let them ride on yours, so a hardened agent labels requests that come from such a tool `ai-agent` and asks for every new one; a running `mairu exec` still keeps its approval while it runs. Your own commands in the same terminal keep their approval as above.

A request is labelled when any of these match:

- a process among its ancestors (up to 64, while they run as you) whose name, executable, or first two arguments is one of `claude`, `codex`, `gemini`, `cursor-agent`, `aider`, `opencode`, `goose`, `amp`, `crush`, `qwen` or `copilot`;
- an environment variable set by such a tool, such as `AI_AGENT`, `CLAUDECODE`, `GEMINI_CLI` or `CODEX_SANDBOX`; mairu sends the agent only the names of its environment variables, never their values;
- a mark you put on the terminal session before starting a tool that detection would miss:

```console
$ mairu lock --tool ai-agent
:: mairu :: Marked this terminal session (/dev/pts/7) as: ai-agent
$ my-agent
```

The mark covers every command started from that terminal, including those a tool runs without a terminal, until the session ends. `mairu unlock --tool ai-agent` removes it, and always asks for approval, since the marked tool could run it too. `mairu doctor` shows the labels of the current terminal and its marks.

Labels are a guardrail, not a security boundary: a renamed binary, a double fork or `systemd-run --user` escapes detection, and any program can claim to be a tool.

### Your own policy

The agent decides with [Cedar](https://www.cedarpolicy.com/) policies, with IAM-like semantics: the default is deny, and a `forbid` wins over any `permit`. Write your own in `~/.config/mairu/policy.cedar`; the agent reads the file itself before every decision.

```cedar
// Never hand production to AI agents, on any server.
@id("no-ai-prod")
forbid (principal, action, resource in Mairu::Account::"999999999999")
when { context.tools.contains("ai-agent") };

// Credentials whose real account is production need a fresh human check, whatever the role is called.
@id("prod-by-real-account")
forbid (principal, action == Mairu::Action::"UseCredentials", resource in Mairu::Account::"999999999999")
unless { context.presence.verified && context.presence.scope == "request" };
```

Any program running as you can edit this file, so until you approve it the agent applies only its `forbid` policies, on top of the built-in policies. A `forbid` can only take permissions away, so it takes effect as soon as you save it, on hardened and unhardened agents alike; on an unhardened agent that is how you deny a role. A file that does not parse is ignored as a whole, and a `forbid` that fails validation is dropped; `mairu policy show` lists both.

`mairu policy approve` puts the whole file in force, `permit` policies and settings included. It prints both files, every server config in `servers.d` and an approval digest, asks `Proceed to authorize this policy? [y/N]` on the terminal (or takes `--confirm <approval digest>` instead), and only then asks for approval through polkit. The agent records a digest of the files and of each server config where same-user code cannot write it: `/var/lib/mairu/users/<uid>` on a hardened host, and a Secret Service item (GNOME Keyring, KeePassXC) as a weaker copy. An unhardened agent approves through the Secret Service item alone; without one its policy stays unapproved.

- Editing either file after approval means **lockdown** until you approve again: every request needs a fresh approval, AI agents are refused, and the file's `forbid` policies still apply. Every mairu command prints a warning meanwhile, and `mairu doctor` shows each store's status.
- A server whose config changed since approval is refused until approved again, and a server added later gets the built-in policies for its roles. The digest is of the config your session logged in with, so log in again after approving a server change.
- The next approval asks through the `approval_methods` recorded by the last one, never through what the files say now.
- Only one approval runs at a time, and never while a credential prompt is pending: a request that would prompt during an approval is refused with "a policy approval is pending from /dev/pts/N".
- If you can no longer approve, root removes the record with `sudo mairu harden --reset-policy-record --user <name>`; the next approval then asks through polkit again.

- `mairu policy init [--force]` writes templates: the hardened built-in policies with comments, and a minimal `authorization.json`.
- `mairu policy check` validates both files locally, lists every policy, and flags each `permit` that can apply without a human check or depends on a tool label.
- `mairu policy show` prints what the agent has in force, the policy state, each integrity store's status, each server's state, and why anything was ignored.
- `mairu policy approve [--confirm DIGEST]` approves the files and server configs.
- `mairu policy explain <server> <role> [--tool LABEL] [--exec CMD] [--cwd PATH] [--assume-role ARN] [--age SECS] [--idle SECS]` prints what the policy decides with no check, under a lease, under a session grant, and after a fresh check.
- `mairu policy schema` prints the schema, for `cedar validate --schema` and similar tools.

A request has `Mairu::User` as principal, `Mairu::Action::"AssumeRole"` (before fetching) or `"UseCredentials"` (once the credentials' real identity is known) as action, and `Mairu::Role::"<server>:<role>"` as resource, which is `in` its `Mairu::Server` and the `Mairu::Account` it names. Not all of `context` is equally trustworthy:

| Attributes | Determined by | Use them to |
|---|---|---|
| `presence`, `hardened`, `session`, `tty`, `caller`, `wsl_interop` | the agent | grant |
| `intent`, `exec_command`, `exec_command_line`, `cwd`, `chained_role_arn` | whoever runs mairu | narrow a `permit` that also requires `context.presence.verified`, or `forbid` |
| `tools`, `tool_matches` | names any program can produce or avoid | restrict, or grant knowingly |

Callers without a terminal, such as IDEs running `credential-process`, are asked about once an hour under the built-in policies. An approved policy can relax that for them:

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

Settings that are not policies live in `~/.config/mairu/authorization.json`. Unknown fields are rejected, and until the file is approved only what tightens applies:

```json
{
  "version": 1,
  "tool_detection": {
    "ai-agent": {"process_names": ["my-agent"], "env_names": ["MY_AGENT_ACTIVE"]},
    "ci": {"env_names": ["CI", "GITHUB_ACTIONS"]}
  },
  "grant_retention_secs": 3600
}
```

- `tool_detection` adds labels, or names to the built-in `ai-agent` label, for `context.tools`.
- `grant_retention_secs` bounds how long an approval is kept at all; the default is 43200, which is also the maximum until the file is approved.
- `methods` (how to ask, in order), `approval_methods` (who may approve the next change), `ssh_agent_keys` (see [SSH agent](#ssh-agent)), `sts` (the region and endpoint of `sts:GetCallerIdentity`, also per server) and `network` (a `proxy` for every outbound connection of the agent, and PEM `extra_roots` trusted beside the system roots) apply once the file is approved.

### Tmux over SSH

Without a desktop session, as over SSH or in tmux, polkit has no authentication agent to show a dialog. mairu then runs polkit's own text agent, `/usr/bin/pkttyagent`, for itself on its terminal, and polkit asks for your login password right there:

```
:: mairu :: Authorization required: 123456789012/Admin on contoso
:: mairu ::   command: terraform apply
:: mairu ::   cwd:     /home/u/src/infra
:: mairu ::   from:    /dev/pts/3 (zsh, tmux pane)
:: mairu :: Enter your password below.
==== AUTHENTICATING FOR co.0w0.mairu.assume-role ====
Authentication is required to provide AWS credentials to a mairu command
Authenticating as: u
Password:
```

- Each tmux pane is its own terminal session: an approval covers one pane, survives detaching and reattaching from a new SSH connection, and a new pane asks again.
- `pkttyagent` is used only from `/usr/bin/pkttyagent`, root-owned and not writable by others, never through `PATH`.
- A command without a terminal, such as a cron job or an AI tool's shell command, cannot be asked, and is refused when it needs approval.
- `mairu doctor` shows the terminal, SSH, polkit and `pkttyagent` state, and warns when a prompt could not be shown.

Typing a password into a terminal has the same exposure as `sudo` in that terminal: echo is off, so capturing the pane's output does not reveal it, but programs running as you can capture keystrokes by reading the pty, through tmux key bindings, by printing a fake prompt first, or with ptrace when `kernel.yama.ptrace_scope` is 0. polkit asks for the same password as `sudo`, so where you type the sudo password into tmux, such programs can already become root. Prefer a PAM setup a captured password cannot satisfy (see [Root](#root)), or approve with a key through your SSH agent instead.

### SSH agent

Register a public key in `authorization.json`, and mairu approves requests by a signature from your SSH agent at `$SSH_AUTH_SOCK`, usually forwarded with `ssh -A` from your laptop. A signature over a one-time challenge cannot be replayed, unlike a password typed into a pane.

```json
{
  "version": 1,
  "ssh_agent_keys": [
    {"key": "sk-ssh-ed25519@openssh.com AAAA... me@laptop"},
    {"key": "sk-ecdsa-sha2-nistp256@openssh.com AAAA... spare", "require_user_verification": true},
    {"key": "ecdsa-sha2-nistp256 AAAA... secretive@mac"}
  ]
}
```

```
:: mairu :: Authorization required: 123456789012/Admin on contoso
:: mairu ::   command: terraform apply
:: mairu ::   cwd:     /home/u/src/infra
:: mairu ::   from:    /dev/pts/3 (zsh, tmux pane)
:: mairu :: Approve the signature on your SSH agent (me@laptop) to authorize 123456789012/Admin on contoso
```

- Any key type an SSH agent signs with is accepted: `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `ssh-rsa` (signed as `rsa-sha2-512`), and the FIDO `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`.
- **The lock on a key belongs to your SSH agent, not to mairu**: a FIDO touch, an `ssh-add -c` confirmation, Touch ID in an agent such as Secretive, or nothing at all. mairu checks the only lock a signature shows, the user-present flag of `sk-` keys, and with `require_user_verification` also the user-verified flag (a PIN or biometric on the key). A key held unlocked proves only that your agent is reachable, so choose the key and configure its agent accordingly.
- With keys registered, `methods` defaults to `["ssh-agent", "platform"]` and `approval_methods` to `["ssh-agent"]`. When the agent is unreachable or holds none of the keys, or refuses to sign, the next method asks. A policy can require the method with `context.presence has method && context.presence.method == "ssh-agent"`.
- The same signature approves `mairu exec`, `mairu credential-process`, `mairu policy approve` and `mairu unlock --tool`. Signatures use the SSHSIG namespace `co.0w0.mairu.authorize`, so a signature made for git or anything else never counts.
- Registering the first key is a policy change: `mairu policy approve` asks through polkit once, and records the key as the approval anchor. From then on only a signature by an anchored key approves the next change. `mairu policy check` warns when `approval_methods` still allows `"platform"` while keys are registered.
- `mairu doctor` shows whether `$SSH_AUTH_SOCK` is reachable, which registered keys it holds, and warns about a stale socket. `mairu lock` also drops every outstanding challenge.

In a long-lived tmux session, `SSH_AUTH_SOCK` points at the socket of the SSH login that started it, which disappears when that login ends. Keep a stable symlink instead:

```sh
# ~/.ssh/rc: runs on every SSH login
if test "$SSH_AUTH_SOCK"; then ln -sf "$SSH_AUTH_SOCK" ~/.ssh/agent.sock; fi
```

```sh
# ~/.tmux.conf: do not copy SSH_AUTH_SOCK from the attaching client
set -g update-environment "DISPLAY KRB5CCNAME SSH_ASKPASS SSH_AGENT_PID SSH_CONNECTION WINDOWID XAUTHORITY"
# your shell's rc file, inside tmux
export SSH_AUTH_SOCK=~/.ssh/agent.sock
```

Programs running as you on that host can also reach the forwarded agent and ask it to sign; only the agent's own lock stands in their way. A program that times its request to coincide with yours can take one approval, but never a policy approval: `mairu policy approve` asks on the terminal first, and approval and credential checks are never pending together.

### Harden home

The hardened copy goes to `<harden home>/libexec/mairu/`, with `/usr/local` as the default harden home. To use another prefix where root-owned software lives, pass `--home <path>` to `harden`, or set `MAIRU_HARDEN_HOME` or `harden_home` in `~/.config/mairu/config.json`; mairu commands find the hardened copy through the same settings. `/usr/bin/mairu` from a package is used when no copy exists in the harden home.

### Upgrading

Upgrade through the hardened copy, which verifies the GitHub artifact attestation of the new binary and never runs it:

```sh
sudo /usr/local/libexec/mairu/mairu harden --from ~/Downloads/mairu
mairu kill-agent
```

The attestation is read from `mairu.sigstore.json` next to the file, as release archives ship it, or else fetched from GitHub. A release older than the hardened copy is refused unless `--allow-downgrade` is given. A build from source has no attestation; install it with `--unattested`.

### Reminders

Until a host is hardened, mairu suggests it at most once an hour on a terminal. Set `MAIRU_NO_HARDEN_SUGGESTION=1`, or configure it in `config.json`; `interval_secs: 0` shows it once per terminal session instead:

```jsonc
{"harden_suggestion": {"enabled": true, "interval_secs": 3600}}
```

### Uninstalling

`sudo mairu harden --uninstall` removes what `harden` installed in the harden home; `--purge` also removes `/var/lib/mairu`. The group stays; remove it with `sudo groupdel mairu`.

### Root

Root can replace the hardened copy and read the agent's memory, so hardening protects your credentials only as well as root is protected from programs running as you. `mairu doctor` warns when `sudo -n true` succeeds or you are in `docker`, `lxd`, `incus-admin` or `disk`.

- Avoid `NOPASSWD` sudo rules and root-equivalent groups for your user.
- Back `sudo` and polkit's `polkit-1` PAM stack (`/etc/pam.d/polkit-1`) with something a captured password cannot replay, such as `pam_u2f` locally, or `pam_ssh_agent_auth` with an approval-protected key over SSH. On a local machine, `pam_fprintd` or `pam_u2f` in `polkit-1` makes the prompt ask for a fingerprint or a security key instead of a password.

### Packaging

`cargo build --release --no-default-features --features platform-helper --bin mairu-platform-helper` builds the platform helper as a standalone `mairu-platform-helper` binary, without the client and agent, for packagers that ship it separately. On Linux the agent always runs `mairu platform-helper`.

Packages install `/usr/bin/mairu` as `root:mairu 2755` with `cap_ipc_lock` (setcap after chgrp, which clears file capabilities), create `/var/lib/mairu` and `/var/lib/mairu/users` as `root:mairu 2770`, and install [pkg/polkit/co.0w0.mairu.policy](./pkg/polkit/co.0w0.mairu.policy) into `/usr/share/polkit-1/actions/`. [pkg/debian/postinst](./pkg/debian/postinst) does this for the Debian package; [pkg/sysusers.d](./pkg/sysusers.d/mairu.conf) and [pkg/tmpfiles.d](./pkg/tmpfiles.d/mairu.conf) declare the group and directories for systemd distributions.

A package can ship the Windows Hello helper of the same release (from `mairu-windows-hello-<arch>-pc-windows-msvc.zip`, or built with `--features windows-hello-helper`) as `/usr/lib/mairu/mairu-windows-hello.exe`, mode 0755, and build `mairu` with `MAIRU_WINDOWS_HELLO_HELPER_SHA256` set to its SHA-256, so that the client runs it without further setup.

### WSL2

mairu hardens a WSL2 distribution as any Linux host, with one limit: with Windows interop on, which is the WSL default, any program running as you can become root through `wsl.exe -u root` without a prompt, and bypass mairu. `harden` and `doctor` say so on every WSL2 host.

| | Integrated (interop on) | Isolated (interop off) |
|---|---|---|
| Strength | A guardrail against over-eager tools such as AI agents, and against accidents | As native Linux against code inside the distribution |
| Opening URLs (`agent` mode) | The Windows default browser, through `rundll32.exe url.dll,FileProtocolHandler` | Printed |
| Approving | Windows Hello, your Windows OpenSSH agent through a relay, or `pkttyagent` | `ssh -A` from Windows into the distribution, or `pkttyagent` |

To switch to the isolated profile, add to `/etc/wsl.conf` and restart the distribution from Windows with `wsl.exe --terminate <distro>`:

```ini
[interop]
enabled = false
appendWindowsPath = false
```

Even then, the Windows account and every other distribution with interop on can become root in this one (`wsl.exe -d <distro> -u root`); they are outside what mairu protects against.

- `mairu doctor` shows the WSL version, whether interop is on, the profile, whether `$SSH_AUTH_SOCK` reaches an SSH agent, and the Windows Hello helper and key.
- `context.wsl_interop` is present only on WSL2, and is true while interop is on. Refuse sensitive accounts with it:

  ```cedar
  @id("no-prod-with-interop")
  forbid (principal, action, resource in Mairu::Account::"999999999999")
  when { context has wsl_interop && context.wsl_interop };
  ```

- To approve with your Windows OpenSSH agent in the integrated profile, relay it into the distribution, with [npiperelay](https://github.com/jstarks/npiperelay) and `socat`, or with [wsl2-ssh-agent](https://github.com/mame/wsl2-ssh-agent), and register its key as `ssh_agent_keys` (see [SSH agent](#ssh-agent)). A Windows agent that asks for Windows Hello before each signature works too; mairu sees an ordinary signature.
- In the integrated profile, Windows Hello can approve requests and policy changes; see [Windows Hello](#windows-hello).
- WSLg provides no notification daemon. For Windows toasts, use `command` mode with a helper such as [wsl-notify-send](https://github.com/stuartleeks/wsl-notify-send):

  ```sh
  #!/bin/sh
  # ~/bin/mairu-toast: the title and body come as the last two arguments
  exec wsl-notify-send.exe --category "$1" "$2"
  ```

  ```sh
  export MAIRU_NOTIFY_COMMAND=~/bin/mairu-toast
  ```

- [WSL-Hello-sudo](https://github.com/nullpo-head/WSL-Hello-sudo) (`pam_wsl_hello`) backs `sudo` with Windows Hello, which closes the `sudo` path to root (see [Root](#root)) but not the interop one.
- WSL1 is not supported: `harden` refuses it, and a hardened copy there runs as misconfigured.

#### Windows Hello

With interop on, a hardened agent can approve requests by a signature from a Windows Hello key: the PIN, fingerprint or face you use for Windows. The key is created by Windows Hello on your TPM, and every signature asks for the gesture. `mairu-windows-hello.exe` signs the agent's challenge on the Windows side, and the agent verifies the signature against the public key registered in `authorization.json`; nothing the helper says counts on its own.

Linux release archives ship `mairu-windows-hello.exe` next to `mairu`, and the Debian package installs it as `/usr/lib/mairu/mairu-windows-hello.exe`; `mairu harden` copies it next to the hardened copy. These builds pin the helper's SHA-256, and run it only while it matches.

1. Create the key and print its entry:

   ```sh
   mairu policy enroll-windows-hello
   ```

2. Add the entry to `windows_hello_keys` in `~/.config/mairu/authorization.json`:

   ```jsonc
   {
     "version": 1,
     // Default: the key-based methods with registered keys, then "platform".
     "methods": ["windows-hello", "platform"],
     "windows_hello_keys": [
       {"name": "desktop", "public_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."}
     ]
   }
   ```

3. Approve it with `mairu policy approve`. The first registration is approved through polkit; from then on, only Windows Hello approves the next policy change.

When a request needs a fresh check, mairu prints the request and `Approve in the Windows Hello dialog …`, and Windows shows the dialog. Cancelling it, or letting it time out, denies the request; no other method asks instead. `context.presence.method` is `"windows-hello"` for a request Windows Hello approved, so a policy can require it, as with [the SSH agent](#ssh-agent).

Builds from source (`cargo install`, AUR `mairu`) ship no helper. Download `mairu-windows-hello-<arch>-pc-windows-msvc.zip` of the same release, point `windows_hello_helper` in `~/.config/mairu/config.json` at the `.exe`, and pin its SHA-256 in `authorization.json` before enrolling, approved like any other setting:

```jsonc
// ~/.config/mairu/config.json
{"windows_hello_helper": "/mnt/c/Users/me/AppData/Local/mairu/mairu-windows-hello.exe"}
```

```jsonc
// ~/.config/mairu/authorization.json
{"version": 1, "windows_hello_helper_sha256": "<sha256sum of the .exe>"}
```

A hardened mairu refuses to run a helper that matches no pin, because a replaced helper could have your Windows Hello gesture sign something else, such as a policy approval. It cannot forge a signature.

## Credential Server API

If you don't have the AWS SSO instance, you need to run your own credential vending server to serve AWS credentials for your Mairu users. You may use a known compatible implementations, or implement your own.

### Known implementations

- https://github.com/sorah/himari2amc
- https://github.com/sorah/himeko

### API Spec

- [HTTP_API_SPEC.md](./HTTP_API_SPEC.md)

## Comparison with other products and solutions

### vs. AWS IAM Identity Center (AWS SSO)

https://aws.amazon.com/iam/identity-center/

- Mairu can automatically switch AWS role to use by reading `.mairu.json` configuration file in a working directory, similar to `.{language}-version` files.
- AWS SSO stores a token on a filesystem. Mairu stores on memory and doesn't persist.
- AWS SSO has to setup a `~/.aws/config` profile for every new role encountered. Mairu can reuse the single configuration (per credential server) for multiple roles and accounts.
- As Mairu retrieves all credentials from a credential server where implements compatible API, you can spin your own implementation to authenticate users and authorize AWS IAM roles with your own identity provider and authorization rules.

### vs. aws-vault

https://github.com/99designs/aws-vault

- Mairu can automatically switch AWS role to use by reading `.mairu.json` configuration file in a working directory, similar to `.{language}-version` files.
- As same as aws-vault, Mairu acts as a executor and a credential_process credential provider.
- Mairu doesn't support secret backends as it stores temporary credentials only on memory. OTOH, Mairu doesn't support permanent credentials at all, even with MFA.
- Mairu can retrieve AWS credentials from a external server with compatible API. You can spin your own implementation to authenticate and provide a credential for an authorised AWS role.
- There's no concept of master AWS credentials or support of AWS MFA devices. Mairu expects a credential server and its authorization server to perform required authentication and authorization including 2FA enforcement.

### vs. Weep

https://github.com/Netflix/weep

- Mairu is inspired by Netflix's ConsoleMe and Weep. Mairu works similarly to Weep, and ConsoleMe is like a credential server in Mairu. Whlist Weep expects a single server implementation ConsoleMe, Mairu works implementation-agnostic. You can write your own implementation, and Mairu can be configured to use multiple servers concurrently.

### vs. AssumeRoleWithWebIdentity

Q. Why Mairu doesn't use OIDC then call sts:AssumeRoleWithWebIdentity directly when retrieving AWS credentials?

A. As this tool aims to allow providing seamless experience for utilizing multiple AWS accounts and roles, an authenticated user is expected to have multiple roles assigned. In that case, it is difficult to allow sts:AssumeRoleWithWebIdentity in AssumeRolePolicy using sub claim because an ID token is likely issued based on user, not a role, and group.

## Security

### Reporting security issues

See [SECURITY.md](./SECURITY.md).

### Possible threats

- Mairu protects accidentially exposing credentials to tools unintentionally, but does not protect for malicious scripts that aware of Mairu; using Mairu CLI directly or interacting with Mairu agent directly.
   - Similarly to ssh-agent and gpg-agent, this means that Mairu doesn't provide well protection for agent process. Don't run on untrusted machines such like shared machines.


## License

Apache License 2.0

Copyright 2023 Sorah Fukumori.

> Licensed under the Apache License, Version 2.0 (the "License");
> you may not use this file except in compliance with the License.
> You may obtain a copy of the License at
> 
> http://www.apache.org/licenses/LICENSE-2.0
> 
> Unless required by applicable law or agreed to in writing, software
> distributed under the License is distributed on an "AS IS" BASIS,
> WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
> See the License for the specific language governing permissions and
> limitations under the License.
