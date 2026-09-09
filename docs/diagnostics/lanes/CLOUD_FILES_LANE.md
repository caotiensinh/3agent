# Cloud Files Diagnostic Lane

## Goal

Build a bounded, local-first evidence collector for cloud-file client state without remote account access or public-network probing.

## Safety contract

Allowed:
- local sync-client process/service metadata
- local client configuration presence without reading secrets
- local sync-root metadata that does not enumerate user file contents
- bounded structured evidence

Forbidden:
- cloud API calls
- reading access tokens, cookies, credentials, or user file contents
- forcing sync
- modifying sync roots or account bindings
- claiming provider outage from local client state
- claiming authentication failure without direct local evidence

## Convergence rule

This lane MUST NOT modify shared runtime wiring files. Shared registration, authority, and capability bindings are owned by the convergence lane after collector tests are green.
