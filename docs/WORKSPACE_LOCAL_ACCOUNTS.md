# WorkSpace Local Accounts and RBAC

## Scope

WorkSpace web chat uses local accounts stored in the existing local SQLite database. The account layer adds no Internet authority and does not change the Core/Public/Egress trust-zone separation in `AGENTS.md`.

## Password and session boundary

- Passwords are never stored in plaintext.
- Password verification uses Python `hashlib.scrypt` with a per-user random salt.
- Browser session secrets are random; only their SHA-256 digest is stored in SQLite.
- Sessions are bound to the originating client IP and expire after 12 hours.
- Disabled users are rejected immediately even if an older cookie exists.
- Password changes and administrative password resets revoke that user's sessions.
- Five consecutive failed password attempts produce a five-minute local lock.

## Bootstrap administrator

The first administrator is created only when the local user table is empty.

```text
WORKSPACE_ADMIN_USERNAME        default: admin
WORKSPACE_ADMIN_PASSWORD        preferred bootstrap password
WORKSPACE_ADMIN_DISPLAY_NAME    default: WorkSpace Administrator
WORKSPACE_ADMIN_DEPARTMENT      optional
WORKSPACE_ADMIN_TITLE           default: Administrator
```

For upgrade compatibility, when `WORKSPACE_ADMIN_PASSWORD` is not set, the existing `THREE_AGENT_WEB_ACCESS_TOKEN` is used as the first administrator password. Only the derived scrypt hash and salt are stored. Once at least one local account exists, WorkSpace restart does not require the bootstrap password to remain in an environment variable; the persisted account database becomes authoritative.

## Roles

- `user`: chat, account-scoped history, account-scoped uploads, own jobs/artifacts, and own password change.
- `admin`: all `user` rights plus local user creation, role changes, enable/disable, profile updates and password reset through the admin API.

The server refuses to disable or demote the last enabled administrator.

## Ownership

New web conversations and uploads are owned by a stable local account identity (`workspace-user:<user_id>`), not by UI state and not by a user-supplied conversation ID. Every conversation and upload reference is validated against the authenticated account on the server.

Job status, recent-job listings, and artifact downloads are also checked against that exact account identity. Being authenticated is not sufficient to read another user's job or artifact.

Legacy v5 conversation history was IP-scoped. On successful login, only the bootstrap administrator may migrate legacy history from that same client IP into the administrator account. The migration changes ownership metadata only and preserves message content.

Legacy uploads are not auto-claimed because ownership cannot be safely inferred after multi-user accounts are enabled.

## API surface

Authenticated account endpoints:

```text
POST /api/login
GET  /api/session
POST /api/logout
POST /api/account/password
```

Administrator-only endpoints:

```text
GET  /api/users
POST /api/users
POST /api/users/<user_id>
```

No endpoint exposes password hashes, salts, session hashes, browser cookies, filesystem paths, or raw credentials.
