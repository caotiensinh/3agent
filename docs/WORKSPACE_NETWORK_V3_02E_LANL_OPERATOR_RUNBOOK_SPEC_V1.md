# WorkSpace Network AI V3-02E — LANL Operator Runbook Contract v1

Status: **CONTRACT-FROZEN BEFORE RUNBOOK CONTENT**

## 1. Goal

Provide one safe, operator-facing runbook that turns the remaining LANL publisher-access blocker into an explicit, auditable manual procedure without granting WorkSpace any enrollment, browser automation, download, or secret-persistence authority.

## 2. Scope

The runbook may explain only:

1. how the operator opens the official LANL dataset page themselves;
2. that LANL currently requests an email address and intended-use description before download access;
3. the exact five expected publisher files: `auth.txt.gz`, `proc.txt.gz`, `flows.txt.gz`, `dns.txt.gz`, `redteam.txt.gz`;
4. how to run the already-reviewed local handoff command;
5. how to recognize `READY_FOR_LANL_EXECUTION_SPEC` versus `NOT_ENOUGH_REAL_SOURCE_EVIDENCE` or a hard failure;
6. what information must never be pasted into GitHub, shell history, environment variables, files, CI, chat logs, or command-line arguments;
7. what evidence may be retained after the handoff: only safe readiness/gate identifiers and the reviewed durable receipt.

The runbook does **not** authorize corpus acquisition or V3-03.

## 3. Trust boundary

Authorized:

- operator browser interaction with the official LANL page;
- operator-provided email/intended-use directly to LANL;
- trusted local interactive terminal;
- `PYTHONPATH=src python -m three_agent.network_lanl_operator_handoff`;
- no-echo `getpass` intake implemented in the reviewed module;
- safe readiness output only.

Forbidden:

- automated LANL form submission;
- mirror fallback;
- inventing or hard-coding LANL direct-download handles;
- putting raw handles in CLI arguments, environment variables, files, Git, issues, PR comments, CI, shell history, screenshots, logs, or chat;
- storing operator email or intended-use text in the repository;
- download, decompression, bounded derivation, adapter execution, or V3-03 authority.

## 4. Required runbook structure

The final runbook must contain:

1. **Prerequisites** — verified `main` checkpoint and trusted local terminal.
2. **Official publisher step** — LANL page only; operator manually supplies email and intended use.
3. **Expected source set** — exact five filenames and source families.
4. **Safe local handoff command** — exact reviewed module invocation with no raw-handle arguments.
5. **Prompt order** — auth, process, flow, DNS, redteam.
6. **Result interpretation** — READY, NOT_ENOUGH, FAIL_SECURITY/FAIL_PROVENANCE/FAIL_SCHEMA.
7. **Do-not-store checklist** — raw handles, email, intended use, cookies/tokens, screenshots containing handles.
8. **Safe evidence checklist** — readiness, gate IDs, reviewed receipt fingerprint only.
9. **Stop condition** — after READY, stop; execution remains blocked until a separate Goal/Spec/Harness/PASS-Fail contract is frozen.

## 5. PASS contract

All must be true:

- official publisher URL points only to `https://csr.lanl.gov/data/cyber1/`;
- exact five filenames are present;
- exact reviewed handoff command is present;
- no direct-download URL example exists;
- no placeholder token/credential/query URL exists;
- no suggestion to export handles to environment variables;
- no suggestion to pass handles through CLI arguments;
- no suggestion to save handles to JSON/text files;
- no suggestion to paste handles into GitHub, CI, chat, screenshots, or shell history;
- runbook states READY does not authorize download/execution;
- runbook states V3-03 remains blocked;
- runbook states Python RAM zeroization is not claimed;
- runbook aligns with the existing operator-handoff and publisher-access contracts.

## 6. FAIL contract

Zero-tolerance failures include:

- `LANL_RUNBOOK_MIRROR_OR_ALT_HOST`
- `LANL_RUNBOOK_DIRECT_HANDLE_EXAMPLE`
- `LANL_RUNBOOK_RAW_HANDLE_CLI`
- `LANL_RUNBOOK_RAW_HANDLE_ENV`
- `LANL_RUNBOOK_RAW_HANDLE_FILE`
- `LANL_RUNBOOK_RAW_HANDLE_LOG_OR_CHAT`
- `LANL_RUNBOOK_FORM_AUTOMATION`
- `LANL_RUNBOOK_DOWNLOAD_AUTHORITY`
- `LANL_RUNBOOK_READY_TREATED_AS_EXECUTION_AUTHORITY`
- `LANL_RUNBOOK_V3_03_EARLY_ADVANCE`

No `PASS_WITH_WARNING` exists.

## 7. Promotion gate

This documentation checkpoint may merge only when the exact head passes:

- a deterministic runbook contract test;
- `harness-ci`;
- `installer-ci`;
- `portable-deploy-ci`;
- `windows-deploy-ci`.

After merge, LANL real-source acceptance remains `NOT_ENOUGH_REAL_SOURCE_EVIDENCE` until the operator has real publisher-issued handles and the separate LANL execution contract is frozen.