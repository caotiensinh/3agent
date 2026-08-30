# WorkSpace Four-Way Login

WorkSpace supports four login methods while keeping authorization and business data local:

1. local username/password;
2. Google OpenID Connect;
3. GitHub OAuth;
4. LINE Login OpenID Connect.

External providers are **identity only**. They do not grant access to WorkSpace data or AI capabilities.

## Trust boundary

```text
Browser
  |
  | local password
  +-------------------------------> WorkSpace Core
  |
  | Google / GitHub / LINE
  v
workspace-auth identity broker
  |
  | fixed provider endpoints only
  | transient provider tokens only
  v
Google / GitHub / LINE
  |
  | verified provider subject
  v
HMAC identity fingerprint
  |
  | one-time opaque ticket
  v
Browser -> WorkSpace Core
             |
             v
      local identity binding
             |
             v
        local WorkSpace RBAC
```

The identity broker must not have access to chat history, projects, uploads, artifacts, the confidential task database, model prompts, or WorkSpace AI tools.

## Provider permission policy

### Local

Local username/password remains the break-glass login and recovery path. Passwords remain scrypt-hashed in the local WorkSpace database.

### Google

Requested scopes are exactly:

```text
openid profile
```

WorkSpace does not request Gmail, Drive, Calendar, Contacts, Cloud or offline access. Email is deliberately not requested because the stable OpenID subject is sufficient for identity binding.

### GitHub

Requested scope is exactly:

```text
read:user
```

WorkSpace does not request `repo`, `workflow`, packages, organization administration, gist, notifications, project, delete-repo or email scopes. The broker rejects token responses containing permissions outside the identity-only allowlist.

### LINE

Requested scopes are exactly:

```text
openid profile
```

WorkSpace does not request email, LINE Messaging API, contacts, status-message mutation or other LINE Platform capabilities. LINE ID tokens are verified with the LINE v2.1 verify endpoint and the original nonce.

## First external login

External identities never auto-create or auto-authorize a WorkSpace account.

On first successful provider verification:

```text
provider identity
   -> pending
   -> visible to WorkSpace administrator
   -> administrator binds it to an existing enabled local user
   -> approved
```

The user signs in again with the same external provider after approval. Local role, enabled state, project ownership and all data authorization continue to come from the bound WorkSpace user.

Rejected identities remain rejected until an administrator explicitly changes the binding state.

## Data minimization

The broker does not persist provider access tokens, refresh tokens or ID tokens. They exist only in process memory during the callback verification flow and are discarded after deriving the identity assertion.

The confidential WorkSpace database stores:

- provider name;
- HMAC-derived 64-hex external identity fingerprint;
- display label;
- approval state;
- bound local WorkSpace user ID;
- timestamps.

It does not store the provider's raw subject identifier, OAuth access token, refresh token, ID token or provider password.

The browser-facing WorkSpace API never returns the external identity fingerprint.

## Identity broker configuration

The broker has a separate environment from WorkSpace Core.

```text
WORKSPACE_IDENTITY_PUBLIC_BASE_URL=https://auth.example.jp
WORKSPACE_IDENTITY_ALLOWED_RETURN_ORIGINS=http://192.168.11.112:8787,https://workspace.example.jp
WORKSPACE_IDENTITY_KEY=<32+ character secret>
WORKSPACE_EXTERNAL_AUTH_REDEEM_KEY=<32+ character shared redemption secret>

WORKSPACE_GOOGLE_CLIENT_ID=...
WORKSPACE_GOOGLE_CLIENT_SECRET=...

WORKSPACE_GITHUB_CLIENT_ID=...
WORKSPACE_GITHUB_CLIENT_SECRET=...

WORKSPACE_LINE_CHANNEL_ID=...
WORKSPACE_LINE_CHANNEL_SECRET=...
```

Only providers with both required client ID and secret are enabled by the broker.

Registered callback URLs are:

```text
https://auth.example.jp/auth/callback/google
https://auth.example.jp/auth/callback/github
https://auth.example.jp/auth/callback/line
```

`WORKSPACE_IDENTITY_PUBLIC_BASE_URL` must use HTTPS.

## WorkSpace Core configuration

Core receives no provider client secret.

```text
WORKSPACE_EXTERNAL_AUTH_BROKER_URL=https://auth.example.jp
WORKSPACE_EXTERNAL_AUTH_PROVIDERS=google,github,line
WORKSPACE_EXTERNAL_AUTH_REDEEM_URL=http://127.0.0.1:8791/redeem
WORKSPACE_EXTERNAL_AUTH_REDEEM_KEY=<same redemption secret>
```

The only Core -> broker operation is redemption of a one-time opaque login ticket over loopback. Core cannot ask the broker to make arbitrary Internet requests.

## PKCE / CSRF / replay controls

- OAuth state values are cryptographically random and single-use.
- PKCE S256 is used for Google, GitHub and LINE authorization-code flows.
- LINE also uses a nonce and verifies it with the LINE ID-token verification endpoint.
- Pending OAuth states expire after five minutes.
- WorkSpace redemption tickets expire after one minute and are consumed once.
- Provider callbacks contain no WorkSpace business data.
- Redemption is loopback-only and additionally requires a 32+ character shared redemption key.

## Operational limitation

External login is hidden unless explicitly configured. Local login continues to work if the identity broker or Internet is unavailable.

A valid HTTPS hostname is required for the provider callback base. The WorkSpace UI itself may remain on an operator-approved LAN origin because the broker validates its exact return origin before redirecting the browser back.
