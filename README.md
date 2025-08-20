# Mairu

Mairu is a tool to securely grant AWS credentials to command-line tools and scripts, with allowing __seamless use of multiple AWS roles and accounts__ concurrently. Mairu can retrieve credentials from __AWS SSO (AWS IAM Identity Center),__ or a credential vending server implements the Mairu API.

By using as a executor, you can seamlessly switch between IAM roles per-project and give explicit intent to allow a command line to access your AWS resources. Plus, Mairu's __auto role selector__ allows reading a desired IAM role from `.mairu.json` under your working directory, so you as an admin don't have to tell detailed configuration such as IAM role ARN per project to your colleagues.

## Installation

* __Cargo:__ `cargo install --locked mairu`
* __Mise:__ `mise use -g ubi:sorah/mairu`
* __Homebrew Tap:__ `brew install sorah/sorah/mairu` <sup>[[tap](https://github.com/sorah/homebrew-sorah)]</sup>
* __Arch Linux AUR:__ [mairu](https://aur.archlinux.org/packages/mairu), [mairu-bin](https://aur.archlinux.org/packages/mairu-bin)
* __Binary:__ Binaries for Linux and macOS are available at https://github.com/sorah/mairu/releases

## Quick Introduction

Mairu can be used like the following cases. In any case, Mairu automatically retrieves a AWS credential for specified role and prompts user to login when server token is expired or doesn't exist yet.

### Configure AWS SSO

```
$ mairu setup-sso contoso --region ${aws_sso_region} --start-url https://my-aws-sso-domain.awsapps.com/start
```

### Use as a executor

```
$ mairu exec --server=contoso 123456789999/AmazingAppDevelopment rails server
```

or, utilize Mairu's `auto` role feature like as follows:

```
$ echo '{"role": "123456789999/AmazingAppDevelopment", "server": "https://my-aws-sso-domain.awsapps.com/start"}' > my-project/.mairu.json
$ cd my-project
$ mairu exec auto rails server
```

### Use as a credential process provider

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

You may specify `--local-port` (or `.aws_sso.local_port`) to fix Authorization Code grant callback port.

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
            "local_port": 16624, // Optional. Static port number to listen for oauth2 redirect_uri, otherwise ephemeral port is assigned and used.
            "use_localhost": false, // Optional, default to false. Use http://localhost for redirect_uri. Has to be true for some issuers, i.e. Microsoft (public client).
        },
        "default_grant_type": "code_grant", // Optional
    }
}
```

### How to choose a Server ID

It is recommended to use the same `id` for your entire organisation. Personal preferences can be stored in other location, so it is safe to distribute the servers.d file with MDM or something else.

To learn how to prepare your credential server, continue reading at [Credential Server](#credential-server) section.

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

We recommend use `auto` role by default. This allows using per-project AWS role seamlessly, securely and concurrently! It would also be convenient to have `alias ae="mairu exec auto "` in your shell profile.

### Reauthentication

If your session with a credential server expired, Mairu prompts you to reauthenticate yourself. For existing processes under `mairu exec`, you'll see a warning message including a command line to start reauthentication flow. 

### Credential provider modes

Mairu supports the following methods to provide credentials to AWS SDK. Choose your best way to pass obtained credentials to your app or tools you love:

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

It listens on `$XDG_RUNTIME_DIR/mairu-agent.sock` (or `~/.local/state/mairu/run/mairu-agent.sock`) by default.

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
