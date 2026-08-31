# Adaptive Learning Phase 4C — checkpoint-verified safe retrieval

## Status

Phase 4C makes operator-approved adaptive knowledge reusable by runtime reasoning without turning learned text into authority.

Prerequisites remain authoritative:

- Phase 1 persistent-content validation;
- Phase 2 domain safety validation;
- Phase 3 immutable staged/promoted learning store;
- Phase 3.1 authenticated checkpoint and trusted-head witness;
- Phase 4A verified-experience admission;
- Phase 4B isolated local reflection and stage-only persistence.

## Core invariant

> Learned knowledge may influence reasoning. It may never grant runtime authority.

Retrieval cannot modify or create:

- TaskContract authority;
- capability or tool authority;
- model authority;
- execution budget;
- network/write scope;
- credentials;
- validator results;
- checkpoint/witness state;
- promotion state;
- Git/deployment authority.

## Trust flow

```text
trusted workflow/policy context
        |
        v
LearningRetrievalQuery
  domain + task sensitivity + hard limits
        |
        v
checkpoint + trusted-head witness verify
        |
        v
append-only ledger + immutable version verification
        |
        v
latest active snapshot per item
  approved / enterprise only
        |
        v
exact domain + sensitivity + execution-mode filters
        |
        v
deterministic local token ranking
        |
        v
hard max-items / max-bytes packing
        |
        v
checkpoint re-verification
        |
        v
capability-free LearningContext
        |
        v
UNTRUSTED user/reference data for local reasoning
        |
        STOP
```

The checkpoint is verified both before and after the snapshot read. A checkpoint sequence/hash/state change during retrieval fails closed rather than returning a mixed-state context.

## Retrieval eligibility

Only the active snapshot derived from the append-only learning ledger is considered.

Eligible levels:

- `approved`
- `enterprise`

Never eligible:

- `candidate`
- `validated`
- archived items
- inactive historical snapshots
- an active snapshot replaced by a later active version

Rollback is naturally respected because active state is derived from the latest authenticated ledger transition.

## Domain binding

Domain is trusted workflow/policy configuration and must be exactly one of:

- `network`
- `security`
- `analyst`
- `general`

The model and learned content do not select the domain. Phase 4C performs exact-domain matching only. Cross-domain reuse is not implemented.

## Sensitivity monotonicity

Retrieval requires:

```text
knowledge_sensitivity <= task_sensitivity
```

Examples:

- public -> confidential: allowed;
- confidential -> public: denied;
- restricted -> confidential: denied.

There is no redaction-based downgrade bypass and no model override.

## Network and security execution boundary

Network/security learned knowledge remains descriptive reference context only. Eligible execution modes are limited to the existing non-remediation modes:

- `analysis_only`
- `passive`
- `read_only`
- `offline`
- `synthetic`

The `LearningContext` packet contains no executable grant or capability field. The retrieval gateway exposes no stage, promote, archive, rollback, signing, key rotation, shell, network, Git, deployment, or credential API.

## Deterministic retrieval

Phase 4C adds no embedding model, vector database, external service, background daemon, or model-based ranker.

Ranking uses normalized local query tokens against:

- title, weighted highest;
- scope;
- bounded content.

Exact normalized phrase matches receive an additional deterministic score. Ties are ordered by stable `item_id` and `knowledge_sha256`. Same authenticated store state and same query therefore produce byte-identical ordering and payload.

A candidate with score zero is not returned.

## Hard output bounds

`LearningRetrievalQuery` carries trusted hard limits:

- max items: 1..8;
- max serialized context: 1 KiB..32 KiB;
- query text: <= 2048 characters.

Each learned content field is additionally bounded before packing. The packer binary-searches the largest content prefix that fits the complete serialized context limit; it never exceeds the requested byte budget.

## LearningContext

Runtime output is a strict capability-free packet containing only:

- schema version;
- query SHA-256 (not raw query);
- trusted domain;
- task sensitivity;
- item ID;
- knowledge SHA-256;
- active level;
- domain;
- kind;
- title;
- bounded content;
- scope;
- sensitivity;
- risk level;
- execution mode.

It deliberately excludes source task IDs, evidence paths/raw evidence, source experience provenance, actor/reviewer identities, validation receipts, checkpoint keys/MACs, credentials, capabilities, and promotion controls.

## Prompt-injection persistence boundary

Approval does not upgrade learned text into instructions.

`render_untrusted_learning_reference()` emits one JSON reference packet with explicit fixed metadata:

- `trust=untrusted_reference_data_only`
- `authority=none`

`append_learning_reference()` accepts only a user/task prompt plus a `LearningContext`. It has no system/developer prompt parameter. This makes the intended authority boundary explicit in the API.

Empty context is a byte-identical no-op.

## Research / Analyst integration

The initial runtime integration is intentionally narrow and reversible in `agents/research_compiled.py`.

Important ordering:

1. prompt compilation remains local;
2. research query planning occurs without learned context;
3. only model-generated, declassified public queries may reach InternetGateway;
4. Phase 4C retrieval occurs locally from the authenticated learning store;
5. if matching approved knowledge exists, it is attached only to the local synthesis objective as untrusted reference data;
6. the authoritative request passed to existing constraint/evidence validators remains byte-identical;
7. if retrieval is unavailable, fails verification, or returns no items, no learned context is used.

Learned content is intentionally excluded from search-query planning. This prevents approved internal knowledge from becoming public-search egress through a model-generated query.

## Telemetry

Retrieval telemetry is metadata-only:

- query SHA-256;
- domain;
- task sensitivity;
- verified checkpoint SHA-256;
- item count;
- item IDs;
- knowledge SHA-256 values.

Raw query text and learned content are not logged by the retrieval gateway. Research activity logs likewise record only count, item IDs, knowledge hashes, or a sanitized exception type when retrieval is blocked.

## Local-only implementation boundary

`adaptive_learning_retrieval.py` imports no network or process execution modules. It performs SQLite reads through the existing `AdaptiveLearningStore` and verification through `LearningCheckpointAuthority` only.

No public/LAN calls, shell, subprocess, model calls, Git operations, deployment operations, or learning-store mutations are needed for ranking or retrieval.

## Acceptance

Phase 4C tests cover:

1. approved retrieval;
2. enterprise retrieval;
3. candidate exclusion;
4. validated-only exclusion;
5. archive exclusion;
6. rollback active-snapshot correctness;
7. missing/stale checkpoint fail-closed behavior;
8. exact-domain isolation;
9. sensitivity monotonicity;
10. deterministic replay/order;
11. max-items/max-bytes bounds;
12. capability-free output fields;
13. prompt-injection-looking text remains untrusted reference data;
14. Network/Security modes remain non-remediation;
15. no network/process imports in retrieval;
16. no-match empty context and byte-identical prompt no-op;
17. metadata-only telemetry;
18. Research query planning cannot receive learned context.

The repository-wide harness continues to provide Phase 1-4B regression coverage.

## Non-goals

Phase 4C does not implement:

- automatic promotion;
- autonomous remediation;
- background reflection;
- model-weight training;
- embeddings/vector retrieval;
- public/LAN research from the learning subsystem;
- cross-domain learned-knowledge sharing;
- trusted-core mutation;
- shell/Git/deployment authority.
