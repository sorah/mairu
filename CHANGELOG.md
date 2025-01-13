## 0.4.0

- Support OAuth 2.0 Authorization Code Grant without client secret; It's safe because we always use PKCE, and expects your authorization server to enforce PKCE.

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
