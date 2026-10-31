## [not yet released]

### Enhancements

- Release binaries are built with link-time optimization and stripped, shrinking them by about 40%.
- Release archives carry a GitHub artifact attestation of `mairu` as `mairu.sigstore.json`; verify with `gh attestation verify mairu --repo sorah/mairu`. Debian packages are attested too.
- When mairu is installed setgid to a dedicated `mairu` group, the agent and its clients verify each other through that group. The agent serves only verified clients, apart from diagnostics; a client sends nothing to an agent it cannot verify, and replaces it with a verified one. A hardened agent also ignores proxies, `AWS_*` variables and `~/.aws/config`.
- New `mairu doctor` command shows how the client and the agent see each other.
- New `mairu harden` command (Linux, as root) installs a hardened copy at `/usr/local/libexec/mairu/mairu`, creates the `mairu` group and `/var/lib/mairu`, and removes them again with `--uninstall [--purge]`. `--home`, `MAIRU_HARDEN_HOME` or `harden_home` in `config.json` choose another prefix. `harden --from FILE` upgrades the hardened copy after verifying the GitHub artifact attestation of `FILE`.
- Other installations (mise, cargo, aqua, tarballs) run the hardened copy when one exists, and warn when its version differs. `MAIRU_NO_HARDENED_REEXEC=1` opts out. Without a hardened copy, mairu suggests `harden` at most once an hour on a terminal (`MAIRU_NO_HARDEN_SUGGESTION=1` or `harden_suggestion` in `config.json`).
- The Debian package installs `/usr/bin/mairu` setgid to the `mairu` group and creates `/var/lib/mairu`. `pkg/sysusers.d` and `pkg/tmpfiles.d` carry the same for other packagers.
- `mairu doctor` lists hardened copies and their versions, and warns when `sudo -n true` succeeds or the user is in `docker`, `lxd`, `incus-admin` or `disk`.
- A hardened agent asks for approval through polkit before vending credentials for a role, once per terminal session (5 minutes idle, 12 hours at most) and once per running `mairu exec`, whose background refresh never prompts. The decision is a built-in [Cedar](https://www.cedarpolicy.com/) policy; an unhardened agent never asks. Approvals are kept in memory only.
- Before vending credentials, a hardened agent asks `sts:GetCallerIdentity` at `sts.amazonaws.com` who they belong to, once per credential set, and refuses credentials whose account differs from the one the role name declares. If STS cannot be reached, nothing is vended.
- New `mairu lock` command makes the agent forget approvals: all of them, those of the current terminal session (`--session`), or also those of running `mairu exec` (`--running`).
- `mairu harden` and the Debian package install the polkit actions `co.0w0.mairu.*` at `/usr/share/polkit-1/actions/co.0w0.mairu.policy`. The Debian package recommends `polkitd`.
- Without a desktop session, as in tmux over SSH, mairu registers polkit's text agent `/usr/bin/pkttyagent` for itself on its terminal, so the approval prompt asks for your password in the pane that made the request. Commands without a terminal are refused with guidance. `mairu doctor` gains a headless section (terminal, SSH, polkit, `pkttyagent`).
- A hardened agent labels requests from AI coding tools (`claude`, `codex`, `gemini` and others among the caller's ancestors, or environment variables such as `CLAUDECODE`) as `ai-agent`, and asks for approval for every new one instead of reusing the terminal's approval; a running `mairu exec` keeps its approval. `mairu lock --tool ai-agent` marks the current terminal session for tools that detection misses, and `mairu unlock --tool ai-agent` removes the mark after asking. `mairu doctor` and refusals show the labels.
- The agent reads your own Cedar policy from `~/.config/mairu/policy.cedar`, and settings from `~/.config/mairu/authorization.json`. Until a policy can be approved, only its `forbid` policies apply, at once and on unhardened agents too, along with settings that tighten (`tool_detection` labels, a shorter `grant_retention_secs`). New `mairu policy` command: `init` writes templates, `check` validates the files and flags risky permits, `show` prints what the agent has in force, `explain` shows what it would decide for a request, and `schema` prints the Cedar schema. `mairu doctor` shows the policy state.
- New `mairu policy approve` puts `policy.cedar` and `authorization.json` in force in full, `permit` policies included, after a `[y/N]` question on the terminal (or `--confirm <approval digest>`) and an approval through polkit. The approval is recorded under `/var/lib/mairu/users/<uid>` on hardened hosts and in Secret Service, together with a digest of each server config. Editing the files afterwards puts the agent in lockdown (a fresh approval for every request, AI agents refused) until the next approval; a changed server is refused until approved again. Approved settings choose the STS region and endpoint of the identity check, and a proxy and extra TLS roots for the agent's connections to credential servers and AWS. `mairu policy show` and `mairu doctor` show the stores and server states, and `sudo mairu harden --reset-policy-record --user <name>` removes a record.
- A hardened agent can approve requests by a signature from your SSH agent at `$SSH_AUTH_SOCK`, including one forwarded with `ssh -A`: register public keys as `ssh_agent_keys` in `authorization.json` and approve the file once. Each challenge is single use and bound to the requesting process and request; FIDO `sk-` keys must assert user presence, and optionally user verification. A stale or unreachable socket falls back to polkit. Once registered keys are approved, the next policy change needs a signature by one of them. `mairu doctor` shows whether `SSH_AUTH_SOCK` is reachable and which registered keys it holds.
- `mairu login` opens the authorize URL in your browser, and clients post desktop notifications when a `mairu exec` needs a login, when an AI agent's request is refused, and when the policy is in lockdown. Each client picks `auto`, `agent` (the agent's helper, through the desktop portal or `xdg-open` and `org.freedesktop.Notifications` on the client's session), `command` (your own program) or `none`, through `--no-browser`, `MAIRU_OPEN_URL`/`MAIRU_NOTIFY` (`*_COMMAND`), or `open_url`/`notify` in `config.json`. `auto` honors `$BROWSER`, and over SSH without a display nothing is shown. `mairu doctor` shows the modes and what the agent can deliver.
- On WSL2, the agent tells the integrated profile (Windows interop on, where any program running as you can become root through `wsl.exe -u root`) from the isolated one. `mairu harden` warns and shows how to turn interop off, `mairu doctor` shows the WSL version, interop, profile and SSH agent, and policies can refuse roles while interop is on with `context.wsl_interop`. With interop on, `agent` mode opens URLs in the Windows default browser. WSL1 cannot be hardened.
- The agent runs platform services in a child process, `mairu platform-helper`, that holds no tokens. The agent and the helper verify each other, the helper exits with the agent, and a helper that died is restarted within 30 seconds; meanwhile those services fail closed. `mairu doctor` shows the helper's state and capabilities.

### Miscellaneous

- macOS binaries are now published per architecture as `mairu-x86_64-apple-darwin.tar.gz` and `mairu-aarch64-apple-darwin.tar.gz`. The universal binary `mairu-universal-apple-darwin.tar.gz` is no longer published.
- Debug builds use a separate `dev` profile (`mairu-dev-agent.sock`, `~/.local/state/mairu-dev`), so a development build no longer talks to the installed agent. `MAIRU_PROFILE` overrides it.
- New `platform-helper` Cargo feature builds a standalone `mairu-platform-helper` binary without the client and agent: `cargo build --no-default-features --features platform-helper --bin mairu-platform-helper`.
- The client and agent are behind a new default `cli` Cargo feature. `native-tls` and `rustls` imply it, so existing build commands such as `--no-default-features --features rustls` still build the full CLI.

## 0.12.0

### Enhancements

- auto: Trust of `.mairu.json` is now shared across git worktrees. A configuration file in a linked worktree is trusted when the equivalent path in the repository's main checkout has been trusted with the same content. Set `MAIRU_NO_WORKTREE_TRUST=1` to opt out. [#54](https://github.com/sorah/mairu/pull/54)
- `--version` now includes the git commit and dirty state. [#55](https://github.com/sorah/mairu/pull/55)
- New personal configuration file `~/.config/mairu/config.json` gains `disallow_roles` to refuse vending credentials for listed roles via `mairu exec` and `mairu credential-process`. [#56](https://github.com/sorah/mairu/pull/56)
- list-sessions: gains `--output json` option. [#57](https://github.com/sorah/mairu/pull/57)

### Bug fixes

- rustls build (`--features rustls`, used for Linux binaries and Debian packages on GitHub Releases): no longer trusts the `webpki-roots` set compiled into the binary in addition to the system CA store, so CA distrust such as the [eMudhra intermediate compromise](https://emudhra.we-have-a-problem.com/) follows OS CA updates. [#59](https://github.com/sorah/mairu/pull/59)
- rustls-webpki rolled to 0.103.16, which rejects certificate paths through the compromised eMudhra intermediates. [#59](https://github.com/sorah/mairu/pull/59)

### Miscellaneous

- `mise.toml` added for development tools. [#58](https://github.com/sorah/mairu/pull/58)
- Rolled Rust dependencies flagged by Dependabot. [#47](https://github.com/sorah/mairu/pull/47), [#48](https://github.com/sorah/mairu/pull/48), [#49](https://github.com/sorah/mairu/pull/49), [#51](https://github.com/sorah/mairu/pull/51)

## 0.11.0

### Enhancements

- exec: gains `--assume-role` option to call `sts:AssumeRole` using vended credentials from remote server. This allows to use the first-hop credential as a jump role for a final IAM role. [#44](https://github.com/sorah/mairu/pull/44), [#42](https://github.com/sorah/mairu/pull/42)

### Bug fixes

- aws-sso: was always re-registering OAuth 2.0 dynamic client when logging in. Now consent prompt is only shown at the first login. [#43](https://github.com/sorah/mairu/pull/43)
- aws-sso: was failing on a machine using a hostname with non-ASCII characters. [#45](https://github.com/sorah/mairu/pull/45)

## 0.10.0

### Enhancements

- exec: Recognises `$MAIRU_SERVER` environment variable in addition to `--server` CLI argument  [#38](https://github.com/sorah/mairu/pull/38)

### Miscellaneous

- Rust edition upgraded to 2024 [#34](https://github.com/sorah/mairu/pull/34)
- Rolled Rust dependencies to latest versions (16 Dec 2025) [#35](https://github.com/sorah/mairu/pull/35)
- `daemonize` crate used for daemonizing agent process was replaced with `daemonix` due to [RUSTSEC-2025-0069](https://rustsec.org/advisories/RUSTSEC-2025-0069) [#37](https://github.com/sorah/mairu/pull/37)
- https://crates.io/crates/mairu now published via GitHub Actions and Trusted Publishing [#40](https://github.com/sorah/mairu/pull/40)

## 0.9.0

### Enhancements

- kill-agent: New subcommand `mairu kill-agent` stops the running agent process. This is useful when upgrading mairu. [#31](https://github.com/sorah/mairu/pull/31)
- oauth_code: OAuth 2.0 callback page gained a dark mode and enabled when a browser configured to prefer dark mode. [#32](https://github.com/sorah/mairu/pull/32)

### Miscellaneous

- readme: Installation methods are reorganized.
- Rolled Rust dependencies to latest versions (21 Aug 2025) [#33](https://github.com/sorah/mairu/pull/33)


## 0.8.0

- login: during OAuth 2.0 Authorization Code flow, mairu now shows localhost URL that redirects to an actual authorize url. This allows to show shorter URLs, which ease opening URLs by avoiding line wrapping.

## 0.7.0

- redirect_uri endpoint returns fancier HTML page during OAuth 2.0 Authorization Code flow.
- New subcomand `mairu list-roles` lists possible `role` parameter for a server. Corresponding HTTP API is added to the spec.
- `mairu` command now suggets user to restart agent when a connected agent reports different version.

## 0.6.0

- New subcomand `mairu show` dumps informations about 'auto' role.

## 0.5.1

- debian: Debian package was missing `setcap` call on post installation, which results into mlockall failure on `mairu agent`.

## 0.5.0

- `mairu login` uses `$MAIRU_LOCAL_PORT` environment variable for a port number when listening to callback. Takes precedence over a server configuration.

## 0.4.0

- Support OAuth 2.0 Authorization Code Grant without client secret; It's safe because we always use PKCE, and expects your authorization server to enforce PKCE.
- `.oauth.code_grant` server configuration gains `use_localhost` flag, which forces redirect_uri to be `http://localhost:.../oauth2callback` instead of `http://127.0.0.1:.../oauth2callback`. This is required for some authorization servers, e.g. Microsoft + Mairu as a public client.
- `mairu list-sessions` command now indicates sessions with an OAuth refresh token.
- `mairu list-sessions` command now shows expiry in a local time by default. It also gains `--utc` to revert to the previous behaviour which shows expiry in UTC.

## 0.3.1

- AWS SSO: fix failure on device code flow. This requires re-registration of OAuth 2.0 dynamic client (which is performed automatically).

## 0.3.0

- agent: Ensure runtime_dir (to create a socket) is only writable by owner (0700) https://github.com/sorah/mairu/pull/19

### Breaking changes

- Agent socket location is changed to state_dir `~/.local/state/mairu/run` on platforms without XDG_RUNTIME_DIR (e.g. macOS)

## 0.2.0

- Fix crash on macOS https://github.com/sorah/mairu/pull/14
- Support generic OAuth 2.0 Device Authorization Grant (RFC 8628)  https://github.com/sorah/mairu/pull/15
- Support generic token refresh using refresh_token grant type https://github.com/sorah/mairu/pull/16
- AWS SSO: Support OAuth 2.0 Authorization Code Grant  https://github.com/sorah/mairu/pull/17  https://github.com/sorah/mairu/pull/18

## 0.1.0

- Initial release
