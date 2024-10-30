## Credential Server API

If you don't have the AWS SSO instance, you need to run your own credential vending server to serve AWS credentials for your Mairu users. You may use a known compatible implementations, or implement your own.

### Authentication

Mairu acts as a OAuth 2.0 public client and supports [device authorization grant](https://datatracker.ietf.org/doc/html/rfc8628) and [authorization code grant](https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.1) with [PKCE](https://datatracker.ietf.org/doc/html/rfc7636). Retrieved access token will be sent as a bearer token in `Authorization` header field ([RFC 6750 Section 2.1.](https://datatracker.ietf.org/doc/html/rfc6750#section-2.1)).

Therefore, a credential server must implement OAuth 2.0 endpoints for a one of supported grant types (at least):

- For authorization code grant
    - _Authentication server MUST support PKCE for auth code grant type_
    - authorization endpoint (default to `{url}/oauth/authorize`)
    - token endpoint (default to `{url}/oauth/token`)

<!-- TODO: For device authorization grant
    - device authorization endpoint (default to `{url}/oauth/device`)
    - token endpoint (default to `{url}/oauth/token`)
-->

### Assume Role Credentials API

##### Request

```
POST {url}/assume-role
Content-Type: application/json
Authorization: Bearer {access_token}
```

```json
{
  "Role": "{role to assume}"
}
```

- `Role` may be a role ARN or something else. Mairu pass-through a string given to a credential provider server, so it's up to a server implementation to decide what strings to accept.

##### Response

Compatible as https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html

```jsonc
{
    "Version": 1,
    "AccessKeyId": "an AWS access key",
    "SecretAccessKey": "your AWS secret access key",
    "SessionToken": "the AWS session token for temporary credentials", 
    "Expiration": "RFC3339 timestamp for when the credentials expire",

    // Mairu specific, optional
    "Mairu": {
        "NoCache": true // Optional default to false. When specified, Mairu doesn't cache this credential and always request to a server for every credential request.
    }
}
```

Mairu will prompt reauthentication for a response with `401 Unauthorized` HTTP status code.


