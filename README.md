# WorkSpace

**Local-first AI runtime for confidential internal business work.**

WorkSpace is the new product identity of the project previously called `3Agent`. The repository/module names remain temporarily compatible during migration, but the product is no longer defined by a fixed number of agents.

## Positioning

WorkSpace helps employees research, analyze, write, present, code, process local files and create daily work reports while keeping business data under enterprise control.

The default security posture is **confidential local mode**:

- LLM inference runs on local Ollama/GPU workers.
- task state, files, evidence, reports and caches stay local.
- cloud LLM APIs are not required or authorized by default.
- GitHub synchronization is an operator/deployment action, not an agent runtime capability.
- public Internet search is **disabled by default**.
- arbitrary HTTP GET/POST, cookies, Authorization headers and outbound request bodies are prohibited by the WorkSpace egress policy.
- high-assurance Linux deployment separates `workspace-core` from `workspace-egress` and blocks Core network egress with nftables.

No software can honestly promise zero information-leak risk under every compromise scenario. WorkSpace therefore uses defense in depth: remove network capability from the process that holds confidential data, minimize the data accepted by the egress broker, fail closed, and audit decisions without logging query plaintext.

## Architecture

```text
                  CONFIDENTIAL ZONE

 User / local files
        |
        v
 +-------------------+
 |   WorkSpace Core  |  workspace-core UID
 |-------------------|
 | Harness           |
 | Context Engine    |
 | Evidence Engine   |
 | Skill Router      |
 | Model Router      |
 | Artifact Engine   |
 +----+----------+---+
      |          |
      |          +------ local files / SQLite / artifacts
      |
      +----------------> localhost Ollama / GPU workers
      |
      +---- AF_UNIX ----+
                        v
                 +------------------+
                 | Egress Broker    |  workspace-egress UID
                 |------------------|
                 | default DENY     |
                 | research only    |
                 | DLP              |
                 | search allowlist |
                 | one-time fetch   |
                 +--------+---------+
                          |
                          v
                       Internet
```

In high-assurance mode nftables rejects every network packet owned by the `workspace-core` UID except loopback access to Ollama. The egress broker runs under a different UID and has no read permission to `/var/lib/workspace`.

## PicoLM-inspired engineering philosophy

WorkSpace adopts the constraint-first lessons of PicoLM without copying its inference engine:

1. **Do less work.** Do not invoke an LLM for deterministic validation, hashing, routing or policy enforcement.
2. **Keep only what is needed.** Context length is a ceiling, not a target. Load only relevant evidence and skills.
3. **Eliminate intermediate copies.** Agent handoffs are compact evidence contracts, not duplicated raw sources.
4. **Cache repeated deterministic work.** Parsed files, cleaned sources and stable prompt/evidence states should be reused by content hash.
5. **Precompute stable decisions.** Skill approvals, file hashes, routing metadata and static policy are computed once and reused.
6. **Constrain output mechanically.** Schema, citation, state, file and network validity are enforced by code rather than hopeful prompting.
7. **Use the smallest sufficient model/resource.** Keep single-GPU work on one RTX 5090 when it fits; escalate only when evidence justifies it.
8. **Measure before optimizing.** Quality, latency, tokens, VRAM, RAM, cache hits and rejected claims are benchmark evidence.

See `docs/WORKSPACE_DESIGN_PRINCIPLES.md`.

## Security profiles

### Confidential mode — default

Canonical config:

```text
config/workspace.secure.json
```

Important defaults:

```json
{
  "confidentiality_mode": "confidential",
  "test_mode_full_access": false,
  "internet_gateway": {
    "mode": "strict",
    "public_search_enabled": false,
    "direct_egress": false,
    "broker_socket": "/run/workspace/egress.sock"
  }
}
```

With this profile, internal work has no reason to send any text to the Internet gateway.

### Public-research exception

Public web research is an explicit administrative exception, not an agent right. If enabled by policy, the broker still permits only:

- agent ID `research`;
- allowlisted HTTPS search engines;
- allowlisted search parameter keys;
- queries passing DLP and length checks;
- exact result URLs learned from the search response;
- one-time/short-lived result fetches;
- bounded response sizes.

It never accepts arbitrary POST bodies.

## CLI migration

New commands:

```bash
workspace smoke
workspace task-list
workspace workflow-run --title "..." --request "..."
```

Temporary compatibility aliases remain:

```bash
three-agent
three-agent-chat
```

Configuration now prefers:

```bash
export WORKSPACE_CONFIG=config/workspace.secure.json
```

Legacy `THREE_AGENT_*` environment variables remain fallback aliases during migration.

## Recommended secure Ubuntu deployment

On a workstation where NVIDIA 590+ and local Ollama are already healthy, deploy the confidential runtime to `/opt/workspace` with:

```bash
curl -fsSL https://raw.githubusercontent.com/caotiensinh/3agent/main/scripts/setup_workspace_secure.sh | bash
```

For enterprise/reproducible rollout, pin `WORKSPACE_REPO_REF` to a reviewed exact commit SHA instead of relying on `main`. The bootstrap phase downloads code/dependencies before confidential runtime data exists; normal WorkSpace execution then runs through the separated Core/Egress boundary.

## High-assurance Linux boundary

If the project/venv is already installed, an administrator can install only the OS trust boundary:

```bash
sudo WORKSPACE_INSTALL_DIR=/opt/workspace \
  bash scripts/install_workspace_secure_boundary.sh
```

This creates:

- `workspace-core` system user — owns confidential runtime data;
- `workspace-egress` system user — runs only the constrained broker;
- `workspace-ipc` shared Unix-socket group;
- `/var/lib/workspace` mode `0700` for Core data;
- `/run/workspace/egress.sock` for narrow IPC;
- `workspace-egress.service` with systemd hardening;
- `workspace-network-lockdown.service` with nftables Core egress denial;
- `workspace-secure` operator wrapper.

Then use:

```bash
workspace-secure smoke
```

## Current capabilities

WorkSpace currently includes workflow capabilities for:

- research and evidence synthesis;
- presentation/report generation;
- daily work reporting;
- secure local file ingestion primitives;
- skill registry and progressive skill approval;
- local model routing and resource admission;
- dual RTX 5090 worker routing;
- deterministic evidence/citation validation.

The system is designed to grow by capabilities and skills rather than by adding a fixed number of named agents.

## Repository transition

The GitHub repository is still currently hosted as `caotiensinh/3agent` for compatibility. Product naming, CLI and architecture use **WorkSpace** from this release onward. Repository renaming can be done separately after deployment URLs/workflows are migrated deliberately.
