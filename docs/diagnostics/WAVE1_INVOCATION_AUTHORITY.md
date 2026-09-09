# Wave-1 Local Evidence Invocation Authority

## Scope

This slice promotes exactly five already-implemented Wave-1 local evidence collectors across the canonical capability invocation boundary:

- `cloud_files.client_state.snapshot`
- `mail_exchange.client_state.snapshot`
- `voip.client_state.snapshot`
- `identity.account_state.snapshot`
- `backup.local_state.snapshot`

The change grants no abstract diagnostic route capability. The collectors remain unbound from broad tags such as `cloud.sync`, `mail.account`, `voip.registration`, `identity.account_state`, and `backup.status`.

## Authority boundary

Each tool remains `network_access=none`, `effect=read`, and `requires_admin=false` in runtime metadata. Invocation additionally requires all of the following:

1. exact current runtime registry and descriptor fingerprints;
2. explicit membership in the task's immutable `allowed_tools`;
3. the source-reviewed Wave-1 handler allowlist;
4. the exact local resource kind and resource reference declared by the collector implementation;
5. read effect only;
6. bounded timeout input only.

The caller cannot supply `platform_name`, command, path, module, executable, shell, argv, callable, or another handler selector. Platform selection remains local runtime observation inside the collector rather than caller-controlled authority.

## Exact resources

| Tool | Resource kind | Resource reference |
| --- | --- | --- |
| `cloud_files.client_state.snapshot` | `cloud_files_client_state` | `local:cloud-files:client-state` |
| `mail_exchange.client_state.snapshot` | `mail_exchange_client_state` | `local:mail-exchange:client-state` |
| `voip.client_state.snapshot` | `voip_client_state` | `local:voip:client-state` |
| `identity.account_state.snapshot` | `identity_account_state` | `local:identity:account-state` |
| `backup.local_state.snapshot` | `backup_local_state` | `local:backup:state` |

## Evidence semantics

Successful invocation means only that the bounded local collector executed under canonical authority. It does not prove remote provider health, authentication success, mailbox state, SIP/PBX registration, directory health, backup freshness, restore viability, root cause, or remediation success.

## Explicitly unchanged

- no network egress;
- no credential access;
- no mailbox or backup payload reads;
- no call/media actions;
- no account mutation;
- no backup job start or restore;
- no remediation;
- no broad route capability binding;
- no automatic action authority.
