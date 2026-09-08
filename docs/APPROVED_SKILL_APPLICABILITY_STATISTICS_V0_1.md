# Approved Skill Applicability Statistics V0.1

## Purpose

This document defines the M-06 vendor/version applicability statistics boundary for approved WorkSpace skills.

The implementation projects only reviewed applicability declarations already admitted by the canonical production skill loader. It does not claim that a task actually ran against a particular vendor, device family, firmware, operating-system release, protocol revision, or deployment version.

## Canonical sources

The projector reuses:

- `ApprovedSkillLoader` for registry, review, integrity, authority, path, reference, and content-safety validation;
- `ApprovedSkillCatalog.list_for_agent()` for audited production skill identity;
- `ApprovedSkillCatalog.list_references_for_agent()` for compact reviewed reference metadata;
- existing optional reference metadata fields `vendor_family` and `version`.

No second skill registry, reference parser, trust model, telemetry database, or promotion path is introduced.

## Schema

Schema identifier:

`workspace-approved-skill-applicability-statistics/v1`

One projection is bound to:

- exact approved skill name;
- exact production `SKILL.md` SHA-256;
- total reviewed reference count;
- vendor-scoped reference count;
- version-scoped reference count;
- fully vendor+version scoped reference count;
- unscoped reference count;
- deterministic `(vendor_family, version)` buckets with reference counts;
- deterministic projection SHA-256.

## Safety and privacy boundary

The projection is metadata-only.

It never includes:

- `SKILL.md` procedure text;
- reference body text;
- reference filesystem paths;
- provenance strings;
- prompts or model output;
- task IDs or user requests;
- credentials, tokens, or secrets;
- evidence bytes;
- executable commands.

The projector grants no filesystem write, network, credential, tool, shell, model, promotion, materialization, rollback, quarantine, or deletion authority.

## Fail-closed behavior

Projection fails when:

- the production registry or any enabled skill fails canonical audit;
- the requested skill is disabled, unapproved, or not allowed for the agent;
- reviewed reference bytes fail integrity or size validation;
- vendor/version metadata contains invalid control characters or exceeds bounds;
- aggregate counters disagree with deterministic applicability buckets;
- a projection contains duplicate or non-deterministically ordered buckets.

## Bounds

`project_many_for_agent()` requires an explicit set of names and accepts at most 16 distinct skills per projection request.

The operation does not turn M-06 into an unbounded registry-discovery surface.

## Interpretation

These statistics answer:

> What vendor/version applicability has been explicitly declared in the reviewed reference pack for this exact approved production skill version?

They do **not** answer:

> What vendor/version was actually observed in a live task, and how effective was this skill for that observed version?

Observed field applicability requires an independently trusted device/vendor/version observation bound to the task/evidence lifecycle. That remains part of the E-05 vendor/version drift work and must not be inferred from reviewed documentation metadata.

## M-06 acceptance

M-06 is considered satisfied for declared applicability statistics when tests prove:

1. deterministic vendor/version bucket counts;
2. exact production SHA binding;
3. agent scope and production integrity remain fail-closed;
4. tampered references cannot be projected;
5. projection payload contains no skill/reference content or provenance;
6. empty reference packs produce explicit zero coverage;
7. multi-skill projection remains bounded and deterministic;
8. malformed applicability metadata is rejected.
