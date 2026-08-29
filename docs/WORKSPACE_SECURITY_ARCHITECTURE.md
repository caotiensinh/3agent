# WorkSpace Security Architecture

## Product security invariant

WorkSpace is a local-first AI runtime for internal enterprise work. The default rule is:

> Confidential data is processed locally and the runtime that can read it has no public egress capability and no broker access.

Cloud LLM APIs, telemetry, autonomous GitHub synchronization and arbitrary web requests are not runtime dependencies.

## Trust zones

### Zone A — Confidential Core

Contains tasks, uploaded/internal files, evidence, reports, caches and model prompts. Runs as `workspace-core`. It can access only local Ollama inference endpoints and is deliberately not in the egress IPC group.

### Zone B — Public Research

Runs as `workspace-public` with a separate database and artifact root. It exists only for questions that are already safe to disclose publicly. It cannot read the confidential store and has no direct network access. Search goes through the broker.

### Zone C — Egress Broker

Runs as `workspace-egress`. It has local DNS plus public HTTPS only and no permission to read either WorkSpace data root. It accepts requests only from the public-research UID and only for the research capability.

## Default deny matrix

| Capability | Core | Public Research | Egress Broker |
| --- | --- | --- | --- |
| Read confidential data | YES | NO | NO |
| Read public research data | NO by default | YES | NO |
| Local Ollama | YES | YES | NO |
| Broker IPC | NO | YES | server side |
| Direct LAN/Internet | NO | NO | HTTPS only |
| DNS | NO | NO | local resolver only |
| Shell execution gateway | policy-controlled | NO | NO |
| GitHub runtime push | NO | NO | NO |

## Constraint-first security

PicoLM's engineering method is applied to security too:

```text
remove capability > filter capability
avoid data movement > inspect data movement
reuse validated state > recompute blindly
mechanical constraint > prompt request
```

The strongest leak prevention is not a better prompt or larger DLP model; it is removing the route by which confidential bytes could leave.

## Internet exception policy

Public research is an exception and must satisfy all conditions: public-zone task, research capability, deterministic DLP, allowlisted search endpoint, GET-only fixed API, no body/caller headers/cookies/credentials, bounded redirects, globally routable destinations, search-derived one-time result URLs, bounded responses and hashed/minimal audit metadata.

## OS enforcement

`scripts/install_workspace_secure_boundary.sh` creates separate UIDs and an nftables owner-based policy:

- `workspace-core`: localhost Ollama ports, then reject;
- `workspace-public`: localhost Ollama ports, then reject;
- `workspace-egress`: local resolver + TCP/443, private/special ranges rejected, then reject.

Systemd hardening removes unnecessary capabilities and makes both data roots inaccessible to the egress service.

## File/prompt injection rule

Files and web pages are untrusted data. Their content cannot authorize network access, shell execution, credential access, policy changes, skill installation or persistent memory changes. Deterministic policy outranks model/file instructions.

## Deployment rule

For enterprise deployment, pin repository/installers to a reviewed exact commit SHA and verify it before execution. A moving `main` branch is not a supply-chain trust anchor.

## Re-review triggers

Review is mandatory if user/group memberships, nftables rules, broker peer UID, search defaults, request methods/headers, egress destinations, data-root permissions, remote model support, telemetry/update behavior or automatic public/confidential transfers change.
