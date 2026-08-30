# WorkSpace Knowledge Base

This directory contains architecture knowledge and engineering doctrine for WorkSpace.

## Status

**Knowledge does not grant runtime authority.**

Documents in this directory describe principles, contracts, review criteria, and implementation boundaries. They do not enable network access, authorize shell execution, change security policy, or modify production infrastructure merely by existing.

The WorkSpace authority hierarchy in `AGENTS.md` remains controlling. Deterministic policy and operator-approved configuration always outrank learned knowledge, skills, model output, and external content.

## Adaptive learning package

- `SELF_IMPROVEMENT_DOCTRINE.md` — canonical WorkSpace interpretation of experience-driven learning, memory, procedural skills, validation, curation, rollback, and safe self-improvement.
- `NETWORK_SECURITY_ANALYST_LEARNING.md` — domain-specific application for Network Monitoring, Security Analysis, and general Analyst work, where evidence quality and false-positive control are critical.
- `ADAPTIVE_LEARNING_PHASE1.md` — implemented deterministic contracts for evidence, experience, candidate provenance, contradictions, validation receipts, classification monotonicity and knowledge-level promotion.
- `ADAPTIVE_LEARNING_PHASE2.md` — implemented offline/synthetic Network/Security/Analyst evaluation corpus and metadata-only deterministic replay.
- `ADAPTIVE_LEARNING_PHASE3.md` — implemented local immutable version store, append-only hash-chained audit ledger, staged/active lifecycle, enterprise-baseline protection, archive, and exact-version rollback.
- `ADAPTIVE_LEARNING_PHASE3_1.md` — authenticated checkpoint journal plus independent trusted-head freshness witness, exact store-state binding, stale/full-rewrite/replay detection, key rotation, and a learner-facing `stage()`-only gateway.

The current implementation still has **no background LLM learner**. Phase 1 through Phase 3 establish deterministic contract, evaluation, persistence, audit, and rollback. Phase 3.1 adds the authenticated external integrity/freshness boundary that must be deployed before unattended Reflection is permitted.

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
