# Workflow Studio Draft Library v1

## Goal

Turn Workflow Studio from a one-shot compiler into a persistent enterprise design workspace without widening execution authority.

## Authority boundary

Saving, opening, duplicating, archiving or restoring a workflow draft is a **design-only** operation.

Draft APIs never call workflow prepare/start/checkpoint execution, scheduler/event triggers, shell/process/network execution, deployment/remediation, or PCAP authority. Execution remains under the existing V4 admission and administrator-approval boundary.

## Persistence model

SQLite tables:

- `workspace_workflow_drafts`: current owner-scoped design state;
- `workspace_workflow_draft_versions`: immutable content revisions;
- `workspace_workflow_draft_audit`: metadata-only lifecycle/audit trail.

Every content revision has authenticated owner scope, authenticated actor id, revision number, canonical SHA-256 content fingerprint, origin (`workspace_ai`, `human`, `import`) and timestamp. Audit rows contain hashes and metadata, not raw workflow descriptions/contracts.

## Concurrency

Updates require both `expected_revision` and `expected_content_sha256`. A stale browser/tab receives a conflict and must reload before saving. WorkSpace does not silently apply last-write-wins. An idempotent save with identical canonical content does not create a new revision.

## Lifecycle

Drafts are archive/restore only in v1. There is no destructive delete endpoint. Duplication creates a new independent `draft_id` while retaining parent draft/revision lineage metadata.

## Owner isolation

All reads and mutations bind to the authenticated WorkSpace account owner key. A valid draft id owned by another account is returned as not found.

## UI

Workflow Studio adds My Workflows, search, active/archived/all views, Save new, Save revision, Duplicate, Archive/restore, and revision chips. Opening a saved draft reconstructs the diagram through the deterministic V4 renderer. It does not grant or trigger execution.

## Enterprise provenance

Open-source diagram/workflow projects are research references only. The clean-room policy and machine-readable source registry live under `docs/legal/`.
