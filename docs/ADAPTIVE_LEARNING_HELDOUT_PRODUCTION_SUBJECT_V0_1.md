# Held-out Lane 1 — Exact Production Skill Evaluation Subject v0.1

## Goal

Define the exact **current production skill** identity used by held-out evaluation.
This closes baseline-identity ambiguity without creating a second skill registry.

## Canonical inputs

`ProductionSkillEvaluationSubjectResolver` reuses `ApprovedSkillLoader.audit_registry()`
and then binds one enabled registry entry to the canonical LF-normalized `SKILL.md`
SHA-256.

For learned/materialized skills it also recognizes the existing canonical provenance
token:

`candidate:<candidate_id>:sha256:<64-hex>`

A caller may require an exact expected candidate SHA. A mismatch fails closed.

## Security invariants

- read-only projection only;
- canonical registry audit is mandatory;
- exact enabled production bytes are SHA-256 verified;
- authority flags must remain instruction-only with network, credential,
  persistent-self-modification and external-code access denied;
- ambiguous candidate provenance is rejected;
- no stage, promotion, rollback, materialization, tool, network, credential or
  runtime execution authority is introduced.

## Output

The metadata-only subject includes:

- production skill name;
- exact production skill SHA-256;
- deterministic registry-entry SHA-256;
- optional exact source candidate identity;
- deterministic `subject_sha256`.

This lane does **not** execute held-out cases or decide regression acceptance.
