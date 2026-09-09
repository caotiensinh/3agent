# Identity Account-State Diagnostic Lane

## Goal

Collect bounded evidence about the current local account state without contacting Active Directory, Entra ID, LDAP, SSO, or any remote identity provider.

## Safety contract

Allowed:
- current local account state exposed by the operating system
- local enabled/password-state metadata where available
- bounded structured evidence

Forbidden:
- password, token, cookie, credential-store, or secret reads
- authentication attempts
- Active Directory / Entra ID / LDAP queries
- remote lockout checks
- account enable/disable/unlock/password changes
- claiming directory health or credential validity from local account state

## Semantics

`local account enabled != directory account healthy`

`local account present != remote authentication valid`

`local account state unavailable != account disabled`

## Convergence rule

This lane MUST NOT modify shared runtime wiring files. Shared registration, authority and `identity.account_state` binding are owned by the convergence lane after collector tests are green.
