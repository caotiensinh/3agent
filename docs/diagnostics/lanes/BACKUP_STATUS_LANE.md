# Backup Status Diagnostic Lane

## Goal

Collect bounded local evidence about backup-related services/timers without touching backup payloads, credentials, destinations, or restore operations.

## Safety contract

Allowed:
- local backup-related service/timer state
- bounded local component metadata
- evidence-only output

Forbidden:
- starting/stopping/restarting backup jobs
- reading backup payload contents
- contacting backup destinations or cloud APIs
- reading backup credentials/tokens
- restore attempts
- claiming backup success, freshness, restore viability, or remote destination health without direct evidence

## Semantics

`backup component active != backup succeeded`

`backup timer present != recent backup exists`

`local component unavailable != backup destination down`

## Convergence rule

This lane MUST NOT modify shared runtime wiring files. Shared registration, authority and `backup.status` binding are owned by the convergence lane after collector tests are green and semantic sufficiency is reviewed.
