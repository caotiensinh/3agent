# Adaptive Learning Phase 4G — bounded background reflection scheduler

## Status

Phase 4G adds the first **operator-enabled bounded scheduler tick** for adaptive Reflection. It does not add an always-on learner, daemon, automatic promotion, or autonomous remediation.

> Automation may select when to evaluate an already-authorized source. It may not create authority.

## Architecture

```text
explicit scheduler configuration (default OFF)
        |
        v
bounded run_once()
        |
        v
exact operator/policy task_id -> domain binding
        |
        v
TaskStore: DONE tasks only
        |
        v
registered workflow_manifest_json
        |
        v
Phase 4A DeterministicLearningAdmission
        |
        v
ReflectionReceiptStore preflight
        |
        +-- completed -> SKIPPED
        |
        +-- claimed -> RECOVERY_REQUIRED
        |
        `-- no receipt
                |
                v
registered research_handoff_json
 + artifact-root containment
 + exact admitted SHA-256 match
                |
                v
Phase 4B ReflectionCoordinator.reflect_and_stage()
                |
                +-- NO_LEARNING_VALUE
                |
                `-- LearningStagingGateway.stage()
                            |
                           STOP
```

## Default-off boundary

`AdaptiveLearningSchedulerConfig.enabled` defaults to `False`.

A disabled `run_once()` returns a metadata-only disabled receipt before source discovery, manifest access, evidence access, receipt-store access or model invocation. Phase 4G is not wired into normal `Orchestrator` startup and does not create a service, thread, timer or daemon loop.

Production operators may construct the scheduler explicitly through `AdaptiveLearningScheduler.from_local_runtime(...)` and invoke one tick when policy permits.

## Explicit domain policy

Phase 4G intentionally does **not** infer a learning domain from task title, request, artifact text or model output.

The current TaskContract uses broad task types such as `analysis`, which are not strong enough to distinguish `network`, `security`, `analyst` and `general` review requirements. Inferring a weaker domain from untrusted content could bypass Network/Security reviewer gates.

Therefore the Phase 4G scheduler requires an exact operator/policy-owned mapping:

```text
TASK-ID -> network | security | analyst | general
```

The mapping is validated before discovery. Duplicate, unknown or non-canonical domain bindings fail closed. `ReflectionDomainBinding` is still created by the trusted parent before the model is invoked, and the model result has no domain field.

A future phase may replace per-task configuration only after workflow domain becomes an authenticated deterministic contract field.

## Bounded discovery

The scheduler does not recursively scan the artifact filesystem.

`LocalLearningSourceProvider` queries the existing `TaskStore` SQLite database for:

- exact `DONE` tasks that are explicitly present in the configured domain map;
- their most recent registered `workflow_manifest_json` artifact;
- registered `research_handoff_json` artifacts for admitted evidence resolution.

Discovery has fixed configuration caps:

- maximum configured tasks: 128;
- maximum discovered rows per tick: 128;
- maximum processed items per tick: 32;
- maximum scheduling wall window: 3600 seconds.

The wall window prevents a tick from starting additional items after its deadline. Each already-started model call remains bounded by the existing Phase 4B isolated worker timeout; Phase 4G adds no second process runner or retry loop.

## Registered-path boundary

Artifact paths are accepted only when all of the following hold:

1. the path came from the existing `artifacts` table;
2. it resolves to a regular file;
3. the final path is not a symlink;
4. its resolved location remains under the configured `ArtifactManager.root`;
5. the artifact type is exactly the expected type.

Phase 4G never accepts a model-provided path, prompt-provided path or arbitrary filesystem root.

A registered path outside the artifact root fails closed.

## Manifest admission

The scheduler does not trust the artifact DB record as proof of success.

The registered manifest is passed to the existing Phase 4A `DeterministicLearningAdmission`, which rechecks:

- current task status is exactly `DONE`;
- complete TaskContract integrity;
- fresh ValidatorLedger state;
- exact `workflow-run/v1` schema and task identity;
- verified completion state;
- manifest verification equals the fresh ledger evaluation;
- content-addressed evidence references.

A task that changed state after scheduler discovery therefore still fails admission.

## Evidence resolution

Current production evidence validation records SHA-256 of the Research handoff and Research Agent records the corresponding `research_handoff_json` path in `TaskStore`.

Phase 4G uses only those registered handoff records. For each Phase 4A evidence hash it:

1. reads only a bounded registered handoff candidate under the artifact root;
2. enforces the existing Phase 4B per-item 32 KiB evidence bound;
3. recomputes `sha256:<digest>` from exact bytes;
4. returns bytes only when every admitted evidence hash has an exact match.

Missing, oversized, moved or tampered evidence fails with `SCHEDULER_EVIDENCE_NOT_RESOLVED` before model invocation.

The Phase 4B content broker then independently repeats exact-set and digest validation before building the model packet.

## No-repeat and crash behavior

Before reading evidence, Phase 4G checks the existing Phase 4B `ReflectionReceiptStore` for the exact `(admission_id, domain)` pair.

- `completed` -> `SKIPPED / REFLECTION_ALREADY_COMPLETED`; no evidence load and no model call.
- `claimed` -> `RECOVERY_REQUIRED / REFLECTION_CLAIM_RECOVERY_REQUIRED`; no silent replay.
- no receipt -> normal Phase 4B flow.

A concurrent race after preflight is still handled by the Phase 4B exclusive receipt claim and the same fail-closed reason codes.

`NO_LEARNING_VALUE` remains a successful completed Reflection result. It creates no staged knowledge.

## Per-source failure isolation

One source failure does not create an automatic retry and does not abort the rest of the bounded tick.

Scheduler outcomes contain only metadata:

- task ID;
- prebound domain;
- admission ID when available;
- candidate ID/SHA when a candidate was staged;
- result class;
- deterministic reason code.

They contain no raw evidence, prompt, model output, filesystem path, credential, token, session data or DB content.

## Authority boundary

Phase 4G introduces no method or object for:

- promotion or enterprise adoption;
- archive/rollback/key rotation;
- checkpoint operator mutation;
- shell execution;
- additional subprocess execution beyond the existing Phase 4B worker;
- public/LAN research;
- credentials;
- package installation;
- Git/deployment;
- network or Security remediation;
- trusted-core mutation.

A valid candidate still terminates at `LearningStagingGateway.stage()`.

Existing Phase 4E authenticated human/domain reviewer requirements remain authoritative for promotion.

## Secret data

`secret` Reflection remains unsupported and fails before evidence loading or model invocation. Phase 4G does not weaken the Phase 4B secret boundary.

## Non-goals

Phase 4G does not implement:

- an always-running background daemon;
- cron/systemd/Task Scheduler installation;
- automatic runtime enablement;
- automatic promotion/adoption;
- autonomous remediation;
- source-domain inference from natural language;
- generic artifact scanning;
- model-weight training/fine-tuning;
- vector DB/embedding retrieval;
- Internet/LAN learning egress;
- Git/deployment authority.
