## 0.7.0

- redirect_uri endpoint returns fancier HTML page during OAuth 2.0 Authorization Code flow.
- New subcomand `mairu list-roles` lists possible `role` parameter for a server. Corresponding HTTP API is added to the spec.


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
