# Adaptive Learning Phase 4B — Domain-Bound Isolated Reflection

Status: IMPLEMENTED CANDIDATE-PROPOSAL BOUNDARY / NO AUTO-PROMOTION

Phase 4B introduces WorkSpace's first model-assisted Reflection step. The model is deliberately placed **after** Phase 4A verified-source admission and **before** deterministic candidate validation and stage-only persistence.

> Model proposes. Evidence validates. Policy authorizes.

## Architecture

```text
Phase 4A VerifiedLearningSourceEnvelope
        |
        v
ReflectionDomainBinding
  operator / workflow / policy owned
        |
        v
TrustedReflectionContentBroker
  redact + bound + reject instruction risk
        |
        v
BoundedReflectionPacket
        |
        v
separate Python worker process
  fixed Ollama loopback only
  strict structured output
        |
        +--> NO_LEARNING_VALUE
        |
        `--> narrow ReflectionResult proposal
                    |
                    v
          deterministic parent rebuild
          ExperienceRecord + KnowledgeCandidate
                    |
                    v
          Phase 1 candidate.validate()
                    |
                    v
          Phase 2 domain validator
                    |
                    v
          LearningStagingGateway.stage()
                    |
                   STOP
```

The Reflection Worker cannot promote, archive, roll back, sign checkpoints, rotate keys, mutate active knowledge, call Git, deploy software, access TaskStore, or receive the learning database.

## Domain binding

The learning domain is selected **before** model invocation by a trusted authority type:

- `operator`
- `workflow`
- `policy`

Allowed domains remain:

- `network`
- `security`
- `analyst`
- `general`

`ReflectionDomainBinding` is deterministic and content-addressed. The model result schema deliberately contains no `domain` field. A model therefore cannot relabel Network work as `analyst` or `general` to evade Network/Security review requirements.

## Model-owned fields versus deterministic fields

The model can propose only:

- whether there is durable learning value;
- candidate kind;
- title;
- reusable content;
- bounded scope description;
- requested candidate action, which must equal the already-authorized action;
- execution mode;
- a short reusable-value rationale.

The model **does not provide**:

- candidate ID;
- experience ID;
- domain;
- sensitivity;
- risk level;
- ownership;
- task IDs;
- source outcome;
- source experience hashes;
- evidence hashes;
- checkpoint state;
- reviewer identity;
- runtime capability.

The parent coordinator builds those fields from the Phase 4A envelope and trusted domain binding.

## Stable identity and over-learning protection

For a given authoritative admission and bound domain, WorkSpace derives one stable candidate identity:

```text
admission_id + bound_domain
        |
        v
candidate:<sha256>
```

The identity does not depend on stochastic model wording. Re-running the same admission cannot manufacture a new candidate identity merely because the model phrases the lesson differently.

A metadata-only `ReflectionReceiptStore` also records `claimed` / `completed` state and recognizes `NO_LEARNING_VALUE`. A completed receipt blocks automatic reflection of the same admission/domain again.

The receipt store is intentionally **not** promotion authority and is not added as an uncheckpointed table in the learning SQLite database. If a receipt is deleted, the deterministic candidate identity and immutable Phase 3 store still prevent a second identity from being silently created for the same admission/domain pair.

A crashed `claimed` receipt fails closed with `REFLECTION_CLAIM_RECOVERY_REQUIRED`; WorkSpace does not silently rerun a possibly completed reflection after a crash.

## Trusted content broker

The model never receives raw conversation history or arbitrary artifact paths.

The broker:

1. rejects empty or oversized source summaries;
2. normalizes untrusted text using the existing WorkSpace handoff sanitizer;
3. rejects prompt/instruction-injection signals rather than persisting them into learning;
4. reuses `privacy.redact_sensitive_text()` for known tokens, email addresses, MAC addresses and private IPv4 addresses;
5. additionally redacts password/token/key assignments, JWT-like values, private-key blocks and common local absolute paths;
6. applies a hard UTF-8 byte cap and character cap before building the packet.

Phase 4B intentionally uses deterministic byte limits instead of adding a tokenizer dependency.

`secret` classification fails closed in this phase.

## Worker process boundary

`IsolatedReflectionRunner` launches:

```text
<current-python> -I -m three_agent.adaptive_learning_reflection_worker
```

with:

- `shell=False`;
- a temporary empty working directory;
- closed inherited file descriptors;
- a restricted environment allowlist;
- no inherited Git/AWS/checkpoint/PYTHONPATH credentials;
- one packet on stdin;
- one result on stdout.

The worker module imports no TaskStore, adaptive-learning store, checkpoint gateway, operator gateway, Git helper, deployment helper or shell helper.

This is a **process boundary**, not a claim that Python process isolation is a kernel sandbox against hostile trusted code. Production deployments that require protection against a compromised worker interpreter should additionally run the worker under a dedicated OS identity/container/sandbox. The model itself has no code-execution or tool-call interface in Phase 4B.

## Ollama transport rule

Reflection reuses the existing `OllamaClient`; it does not create a second generic HTTP client.

Before inference, the worker requires the configured endpoint to be:

- scheme `http`;
- an IP literal;
- a loopback address (`127.0.0.0/8` or `::1`);
- free of username/password, query, fragment and API path.

`localhost` is rejected because it requires name resolution. LAN addresses are rejected. `AdaptiveOllamaClient` is not used, so Reflection cannot silently escalate to a different deep model.

## Strict model output

The normal WorkSpace `OllamaClient.generate_json()` is intentionally tolerant of fenced JSON for general tasks. Phase 4B persistence is stricter.

The Reflection Worker uses the existing schema-constrained Ollama request transport, then requires the **raw model response itself** to be exactly one JSON object. Markdown fences, prefixes, suffixes, extra fields and tool-call shapes are rejected.

`NO_LEARNING_VALUE` is a first-class successful result and is preferred for one-off or non-durable observations.

## Candidate validation

A candidate proposal is rebuilt by the trusted parent as:

```text
Phase 4A evidence hashes
        -> EvidenceReference[]
        -> verified_success ExperienceRecord
        -> KnowledgeCandidate.from_experiences()
        -> KnowledgeCandidate.validate()
        -> AdaptiveLearningDomainValidator.validate()
```

This preserves exact domain/sensitivity/evidence lineage and applies Phase 2 Network/Security/Analyst defenses before persistence.

Examples blocked before staging include:

- active network scanning;
- load testing;
- packet injection;
- router/switch/firewall configuration mutation;
- automatic firewall blocking;
- account disabling/credential rotation;
- host quarantine/process killing;
- alert suppression.

For Network/Security, Reflection remains proposal/read-only-analysis oriented. Passing Phase 4B still grants no promotion or execution authority.

## Persistence boundary

The only persistence call in `ReflectionCoordinator` is:

```text
LearningStagingGateway.stage(candidate)
```

The coordinator has no `promote`, `archive`, `rollback` or `rotate_key` method.

Phase 3.1 checkpoint/witness protection therefore remains the only path for accepted learner-managed staging state.

## Failure behavior

Phase 4B fails closed for:

- non-admitted or non-verified-success sources;
- secret sources;
- invalid/stale domain binding;
- summary prompt-injection signals;
- summary/packet size overflow;
- non-loopback Ollama endpoint;
- worker timeout/failure;
- fenced or non-strict JSON;
- model-supplied authority fields;
- action mismatch;
- Phase 1 contract failure;
- Phase 2 domain safety failure;
- duplicate completed reflection;
- unresolved crash claim.

No failure path automatically promotes or mutates active knowledge.

## Current non-goals

Phase 4B does **not** add:

- automatic promotion;
- autonomous remediation;
- background reflection daemon;
- public/LAN research from Reflection;
- model-weight training;
- trusted-core source mutation;
- Git/deployment authority;
- checkpoint signing authority;
- authenticated human/domain reviewer identity.

The next phase must not start until Phase 4B exact-head tests/CI pass and the accepted Phase 4B commit is merged and verified on `main`.
