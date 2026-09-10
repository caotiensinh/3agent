# WorkSpace Network AI V3-02E — LANL Operator Handoff Specification v1

Status: **CONTRACT-FROZEN BEFORE IMPLEMENTATION**

## 1. Goal

Provide a safe local operator handoff path for the five LANL publisher-issued access handles after the operator has completed LANL enrollment themselves.

The handoff must let the operator validate the handles without writing the raw handles, operator email, intended-use text, cookies, tokens, credentials, or form content to Git, durable files, CI artifacts, logs, shell history, or command-line arguments.

This checkpoint does **not** authorize LANL corpus acquisition or V3-03.

## 2. Prerequisite

Required main checkpoint:

`c9263e8e71b6b63f0cacb3d9471ac86e97507c13`

That checkpoint contains the reviewed offline LANL publisher-access validator and keeps the current no-handle state at:

`NOT_ENOUGH_REAL_SOURCE_EVIDENCE / LANL_ACCESS_HANDLE_MISSING`

## 3. Trust boundary

Authorized:

- one trusted local interactive operator terminal;
- local process memory for the lifetime of the handoff command;
- no-echo interactive prompts for the five publisher handles;
- the already-reviewed `network_lanl_publisher_access` validator;
- safe compact readiness output only.

Forbidden:

- automated LANL enrollment or form submission;
- network access of any kind;
- corpus download;
- URL discovery or redirect chasing;
- mirror fallback;
- raw handle CLI arguments;
- raw handle environment variables;
- raw handle JSON/text input files;
- raw handle stdout/stderr/logging;
- raw handle durable receipt/artifact;
- operator email/intended-use persistence;
- subprocess/shell/model authority;
- acquisition, decompression, bounded derivation, adapter execution, or V3-03 authority.

## 4. Required source set

The interactive handoff must request exactly these five source families in this order:

1. `auth` -> `auth.txt.gz`
2. `process` -> `proc.txt.gz`
3. `flow` -> `flows.txt.gz`
4. `dns` -> `dns.txt.gz`
5. `redteam` -> `redteam.txt.gz`

The handoff itself does not interpret the URLs. Validation authority remains in the reviewed LANL publisher-access validator.

## 5. Input contract

### 5.1 Interactive-only

Raw handles may enter the process only through an interactive TTY no-echo prompt.

The production command must fail closed before prompting when the terminal is not interactive.

### 5.2 No raw-handle CLI surface

The command may expose only non-secret options such as `--profile`.

The parser must not expose URL/handle/token/cookie/credential/email/purpose arguments.

### 5.3 No environment/file handle ingestion

The command must not read raw LANL handles from environment variables or an input JSON/text file.

### 5.4 Prompt behavior

Prompts may display only the source family and expected publisher filename.

The raw value must not be echoed.

If prompting is cancelled by EOF/interrupt before all five handles are collected, the command must return an insufficient-evidence result without validating or persisting a partial handle set.

## 6. Process-memory limitation

The implementation may hold Python strings containing the five handles only for the lifetime required to validate them.

It must delete its container references in a `finally` path after validation/cancellation.

Python immutable strings cannot be guaranteed to be physically zeroized. The product must not claim secure memory erasure. The security guarantee for this checkpoint is **no deliberate durable/log/CLI/environment persistence**, not physical RAM scrubbing.

## 7. Validation binding

After all five handles are collected, the handoff must call the existing reviewed function:

`network_lanl_publisher_access.evaluate_access_handles()`

The handoff must not duplicate or weaken publisher-host/path/family/security validation.

The only valid READY state remains:

`READY_FOR_LANL_EXECUTION_SPEC`

READY means only that the five access handles satisfy the publisher-access contract. READY does **not** authorize download or execution.

## 8. Output contract

Allowed stdout result:

- the safe durable receipt produced by the reviewed access validator, or
- a compact safe status object containing only readiness/gate identifiers on cancellation/failure.

Raw input handles must never appear in stdout or stderr.

No new durable schema containing handles is authorized.

## 9. Exit codes

- `0`: all five handles validated and result is `READY_FOR_LANL_EXECUTION_SPEC`;
- `2`: operator cancelled/incomplete input -> `NOT_ENOUGH_REAL_SOURCE_EVIDENCE`;
- `1`: hard security/provenance/schema failure.

## 10. Authority constraints

The module must have zero imports or calls granting:

- HTTP/network authority (`requests`, `urllib.request`, `socket`, `httpx`, `boto3`);
- subprocess/shell authority;
- browser/form automation;
- model/LLM authority;
- Git/GitHub mutation authority;
- corpus parsing/decompression authority.

The only URL parser/validation authority remains in the existing offline LANL access validator.

## 11. PASS contract

All must pass:

- exact five prompts, exact order;
- no-echo prompt implementation;
- non-TTY fail-closed before prompt;
- no raw-handle CLI/env/file input surface;
- exact reuse of reviewed access validator;
- valid five-handle set -> READY;
- partial/cancel -> NOT_ENOUGH;
- mirror -> FAIL_PROVENANCE;
- embedded credentials/query-fragment policy violations -> fail closed per reviewed validator;
- raw handle absent from stdout/stderr on success and every failure fixture;
- safe receipt contains only existing allowlisted fields;
- zero network/subprocess/model/browser/form/download authority;
- full existing regression CI passes.

## 12. FAIL contract

Zero-tolerance failures include:

- `LANL_HANDOFF_NON_INTERACTIVE_INPUT_ACCEPTED`
- `LANL_HANDOFF_RAW_HANDLE_IN_CLI`
- `LANL_HANDOFF_RAW_HANDLE_FROM_ENV`
- `LANL_HANDOFF_RAW_HANDLE_FROM_FILE`
- `LANL_HANDOFF_RAW_HANDLE_ECHOED`
- `LANL_HANDOFF_RAW_HANDLE_LOGGED`
- `LANL_HANDOFF_RAW_HANDLE_DURABLE`
- `LANL_HANDOFF_OPERATOR_FORM_CONTENT_PERSISTED`
- `LANL_HANDOFF_VALIDATOR_BYPASSED`
- `LANL_HANDOFF_NETWORK_AUTHORITY`
- `LANL_HANDOFF_SUBPROCESS_AUTHORITY`
- `LANL_HANDOFF_FORM_AUTOMATION_AUTHORITY`
- `LANL_HANDOFF_DOWNLOAD_AUTHORITY`
- `LANL_HANDOFF_READY_WITH_PARTIAL_SOURCE_SET`

No `PASS_WITH_WARNING` exists.

## 13. Fixture matrix

Required fixtures:

1. valid exact five publisher handles -> READY;
2. non-TTY -> FAIL_SECURITY before prompt;
3. EOF before first value -> NOT_ENOUGH;
4. EOF after partial values -> NOT_ENOUGH and no partial validation/persistence;
5. mirror handle -> FAIL_PROVENANCE;
6. embedded userinfo -> FAIL_SECURITY;
7. query/fragment -> FAIL_SECURITY;
8. wrong family filename -> FAIL_PROVENANCE;
9. success stdout capture contains no raw handle;
10. each failure stdout/stderr capture contains no raw handle;
11. parser has no raw-handle arguments;
12. AST authority audit;
13. prompt function is no-echo (`getpass`) rather than normal `input()`;
14. handoff references are released in a `finally` path;
15. targeted workflow itself has no network/acquisition step.

## 14. Promotion gate

The handoff checkpoint may merge only when one exact head passes:

- `lanl-operator-handoff-contract`
- `harness-ci`
- `installer-ci`
- `portable-deploy-ci`
- `windows-deploy-ci`

After merge, LANL real-source acceptance still remains blocked until the operator supplies real publisher-issued handles and a separate execution SPEC/HARNESS is frozen.
