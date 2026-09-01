# WorkSpace Knowledge Base

This directory contains architecture knowledge and engineering doctrine for WorkSpace.

## Status

**Knowledge does not grant runtime authority.**

Documents in this directory describe principles, contracts, review criteria, and implementation boundaries. They do not enable network access, authorize shell execution, change security policy, or modify production infrastructure merely by existing.

The WorkSpace authority hierarchy in `AGENTS.md` remains controlling. Deterministic policy and operator-approved configuration always outrank learned knowledge, skills, model output, and external content.

## Adaptive learning package

- `SELF_IMPROVEMENT_DOCTRINE.md` — canonical WorkSpace interpretation of experience-driven learning, memory, procedural skills, validation, curation, rollback, and safe self-improvement.
- `NETWORK_SECURITY_ANALYST_LEARNING.md` — domain-specific application for Network Monitoring, Security Analysis, and general Analyst work, where evidence quality and false-positive control are critical.
- `NETWORK_SECURITY_INTELLIGENCE_V002.md` — operator-bounded public corpus acquisition, CTU-13 CC-BY flow admission, truth-separated streaming normalization, and deterministic advisory deep-flow security signals.
- `NETWORK_SECURITY_INTELLIGENCE_V003.md` — privacy-preserving typed entity references, additive event/entity persistence, strict structured auth/process enrichment, and exact-relationship multi-source incident graphs across DNS, flow, authentication, process and IDS evidence.
- `ADAPTIVE_LEARNING_PHASE1.md` — implemented deterministic contracts for evidence, experience, candidate provenance, contradictions, validation receipts, classification monotonicity and knowledge-level promotion.
- `ADAPTIVE_LEARNING_PHASE2.md` — implemented offline/synthetic Network/Security/Analyst evaluation corpus and metadata-only deterministic replay.
- `ADAPTIVE_LEARNING_PHASE3.md` — implemented local immutable version store, append-only hash-chained audit ledger, staged/active lifecycle, enterprise-baseline protection, archive, and exact-version rollback.
- `ADAPTIVE_LEARNING_PHASE3_1.md` — authenticated checkpoint journal plus independent trusted-head freshness witness, exact store-state binding, stale/full-rewrite/replay detection, key rotation, and a learner-facing `stage()`-only gateway.
- `ADAPTIVE_LEARNING_PHASE4A.md` — deterministic verified-experience admission from authoritative task contract, validator ledger and workflow manifest into a capability-free, metadata-only learning-source envelope.
- `ADAPTIVE_LEARNING_PHASE4B.md` — domain-bound, process-isolated local Reflection proposal path with bounded/redacted packets, strict raw JSON, loopback-only Ollama, deterministic candidate provenance, Phase 1/2 revalidation, persistent no-repeat receipts, and stage-only persistence.
- `ADAPTIVE_LEARNING_PHASE4C.md` — checkpoint-verified deterministic retrieval of active approved/enterprise knowledge as bounded capability-free untrusted reference data, with exact-domain and TaskContract-bound sensitivity controls.
- `ADAPTIVE_LEARNING_PHASE4D.md` — trusted production bootstrap that opens only an existing authenticated learning generation read-only and injects the Phase 4C gateway into the real Research Agent construction path.
- `ADAPTIVE_LEARNING_PHASE4E.md` — authenticated local operator promotion ceremony that binds a WorkSpace principal, explicit reviewer/domain entitlement, exact candidate/receipt lineage and exact checkpoint state to the existing checkpointed `LearningOperatorGateway`.
- `ADAPTIVE_LEARNING_PHASE4F.md` — explicit local operator bootstrap and read-only verification ceremony for a fresh authenticated learning generation, with private POSIX key creation, no overwrite/rebaseline/repair shortcut, and no automatic runtime enablement.
- `ADAPTIVE_LEARNING_PHASE4G.md` — default-off bounded `run_once()` Reflection scheduler using explicit task/domain policy, TaskStore-registered manifests/evidence, exact content hashes, Phase 4A admission, Phase 4B no-repeat receipts, and stage-only persistence.
- `ADAPTIVE_LEARNING_PHASE4H.md` — deterministic metadata-only reuse receipts and observational outcome aggregation, with anti-self-reinforcement deduplication, confounding controls, fresh validator truth and advisory-only curation signals.
- `ADAPTIVE_LEARNING_PHASE4I.md` — deterministic checkpoint-bound curation proposal compiler that turns Phase 4H observational signals into exact-SHA review artifacts with explicit human/domain reviewer requirements and zero mutation authority.

The current implementation has **no always-on or unbounded autonomous learner**. Phase 1 through Phase 3 establish deterministic contract, evaluation, persistence, audit, and rollback. Phase 3.1 adds authenticated persistence integrity/freshness. Phase 4A decides, without an LLM, which exact completed workflows are trustworthy enough to become Reflection input. Phase 4B permits one bounded local model proposal while keeping domain, provenance, sensitivity, ownership, identity, validation and persistence authority outside the model. Phase 4C makes separately approved knowledge reusable without granting authority. Phase 4D wires that read-only retrieval path into production only when an operator explicitly supplies an already-authenticated store/checkpoint/witness/key boundary. Phase 4E authenticates and explicitly authorizes the human promotion ceremony while preserving the existing checkpointed mutation path; it does not automate promotion or grant new runtime capability. Phase 4F closes the production initialization gap with an explicit fresh-only operator bootstrap and read-only verification path while preserving default-off retrieval and fail-closed integrity semantics. Phase 4G adds only an explicitly enabled, bounded scheduler tick that reuses Phase 4A/4B and terminates at staging or `NO_LEARNING_VALUE`; it does not start itself, infer weaker domains, promote knowledge, or remediate systems. Phase 4H records which exact approved knowledge versions were made available to a task and deterministically compares that reuse with later TaskStore/ValidatorLedger outcomes. Those metrics remain observational and advisory: they can recommend review or show support, but they cannot promote, archive, delete, rollback, or remediate anything. Phase 4I binds those signals to the exact currently active authenticated knowledge version and produces deterministic review-only curation proposals. It can request observe-more, keep-active review, or revise/archive review, but cannot apply any of those actions.

## Provenance

The adaptive-learning doctrine was derived from a design study of `NousResearch/hermes-agent`, especially its separation of persistent memory, procedural skills, background review, curation, provenance, and rollback.

Study snapshot: `NousResearch/hermes-agent@5cc1369fa298021f8c740de154ff8c37c30bdcc8`.

WorkSpace extraction baseline: `caotiensinh/3agent@9bdf43ed89c53951e7172923d1b58b7330a8c481`.

This package extracts architecture ideas and operating principles. It does not copy Hermes source code, prompts, or implementation text.

## Core rule

WorkSpace should improve primarily by improving **what it remembers, how it performs validated classes of work, and how it evaluates evidence** — not by allowing an unattended model to rewrite the trusted core.

```text
Experience
  -> Reflection
  -> Candidate knowledge
  -> Validation
  -> Approved memory / skill / playbook
  -> Reuse
  -> Measurement
  -> Curation / rollback
```

For Network and Security domains, autonomous learning is proposal-oriented by default. Learned material can improve diagnosis and analysis, but it cannot grant itself execution, network, credential, remediation, deployment, promotion, checkpoint-signing, witness-write, or Git authority.
