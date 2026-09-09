# Hermes-Agent Baseline Comparison and WorkSpace Secure Foundation

## Locked baselines

This comparison is deliberately SHA-locked so that future Hermes or WorkSpace changes do not silently move the target.

- Hermes-Agent: `NousResearch/hermes-agent@9d865810b66b15a811eb62e0095f8cb66f6c032d`
- WorkSpace/3agent before this tranche: `caotiensinh/3agent@e48e799120ee073c941e1925bedbfe24bcbe5183`

The rubric is an engineering decision aid, not an objective universal ranking. Scores must be backed by repository implementation or CI evidence. A higher score does not imply that every individual feature is broader.

## Rubric

| Category | Weight | Hermes | WorkSpace before | Evidence / interpretation |
|---|---:|---:|---:|---|
| Safety, permissions, governance | 15 | 11 | 15 | WorkSpace has task-bound capability narrowing/revocation and dedicated egress/security gates. Hermes has mature security work but prioritizes broad autonomous tooling. |
| Audit, evidence, observability | 10 | 7 | 10 | WorkSpace treats evidence receipts, benchmark artifacts and verification gates as first-class. |
| Deployment/update/release trust | 10 | 6 | 10 | WorkSpace authenticates installed Windows/Ubuntu updater paths, pins update attempts to immutable commits and stress-tests idempotence. |
| Tests, CI, reliability, rollback | 10 | 8 | 10 | WorkSpace runs multi-runtime harness, portable deployment, canonical, egress and non-destructive update gates. |
| Persistent memory/context lifecycle | 10 | 9 | 3 | Hermes has a production persistent-memory subsystem; WorkSpace lacked a general persistent memory store. |
| MCP/interoperability | 10 | 10 | 0 | Hermes has mature MCP client/server, remote transport and OAuth support; WorkSpace lacked a general MCP client. |
| Tools/skills extensibility | 10 | 10 | 8 | Hermes has broader general-purpose skill/tool ecosystem; WorkSpace has strong modular domain tools and admission controls. |
| Core orchestration | 8 | 8 | 7 | Both are capable; Hermes is broader as a general autonomous agent, WorkSpace is more constrained by design. |
| Delegation/subagents/concurrency | 7 | 7 | 5 | Hermes has broader general delegation; WorkSpace has concurrency/evaluation primitives but less general subagent UX. |
| Local/provider independence | 4 | 4 | 4 | Both support local-first operation; WorkSpace explicitly targets confidential local infrastructure. |
| Operator UX | 3 | 3 | 2 | Hermes currently exposes broader general-purpose user workflows. |
| Domain/adaptive intelligence | 3 | 1 | 3 | WorkSpace has dedicated network, security, monitoring, vulnerability and adaptive diagnostic modules. |
| **Total** | **100** | **84** | **77** | WorkSpace was not yet ahead overall because memory and MCP were material platform gaps. |

## Secure foundation tranche

This tranche closes the two highest-weight missing platform capabilities without weakening WorkSpace's security model.

### Secure persistent memory

`three_agent.secure_memory.SecureMemoryStore` provides:

- local SQLite persistence with WAL/busy timeout;
- deterministic IDs scoped by `namespace + key`;
- namespace-isolated reads;
- mutation approval required by default;
- optional exact-action approval policy;
- public/internal/confidential/restricted classification;
- provenance and per-record integrity hashes;
- TTL/expiry and explicit purge receipts;
- bounded retrieval by record count and encoded byte budget;
- hash-chained mutation receipts and audit-chain verification;
- structured records rather than raw prompt concatenation.

The receipt chain is explicitly documented as tamper-evident, not tamper-proof.

### Governed MCP

`three_agent.governed_mcp.GovernedMCPClient` provides:

- explicit server registration; unknown servers are denied;
- per-server tool allowlists;
- stdio support through the official MCP SDK;
- Streamable HTTP only after explicit `allow_remote=True`;
- HTTPS-only remote URLs plus hostname allowlist;
- subprocess environment minimization through an explicit env allowlist;
- timeout, call-count and output-size budgets;
- optional TaskContract capability-revocation callback;
- hash-chained per-call receipts;
- optional dependency `workspace-local-ai[mcp]` pinned to `mcp==2.0.0`.

Hermes remains broader in MCP OAuth/provider integrations. WorkSpace deliberately does not claim parity with that breadth in this tranche; its differentiator is that MCP capability is bounded and deny-by-default at the client boundary.

## Post-tranche provisional score

The score may only be promoted from provisional after exact-head CI passes.

| Category | Hermes | WorkSpace after |
|---|---:|---:|
| Safety, permissions, governance | 11 | 15 |
| Audit, evidence, observability | 7 | 10 |
| Deployment/update/release trust | 6 | 10 |
| Tests, CI, reliability, rollback | 8 | 10 |
| Persistent memory/context lifecycle | 9 | 10 |
| MCP/interoperability | 10 | 8 |
| Tools/skills extensibility | 10 | 8 |
| Core orchestration | 8 | 7 |
| Delegation/subagents/concurrency | 7 | 5 |
| Local/provider independence | 4 | 4 |
| Operator UX | 3 | 2 |
| Domain/adaptive intelligence | 1 | 3 |
| **Total** | **84** | **92 provisional** |

This is sufficient for a higher weighted engineering score but not for a claim that WorkSpace is broader than Hermes in every category. The next baseline tranches should target general governed delegation and operator-facing skill discovery/scheduling while preserving the existing authority model.
