# WorkSpace Harness H1 — Canonical Task + Acceptance Boundary v0.0.1

**Status:** implementation slice  
**Parent architecture:** `docs/WORKSPACE_COGNITIVE_HARNESS_V0_0_1.md`  
**Governance:** `docs/WORKSPACE_EXECUTION_GOVERNANCE_V0_0_1.md`

## Purpose

H1 adds a deterministic boundary between user intent and execution:

```text
user prompt
  -> existing PromptCompiler
  -> CanonicalTaskSpec
  -> existing TaskContract
  -> existing TaskCapabilityAuthority
  -> execution

AcceptanceContract
  -> evidence-backed CriterionResult
  -> AcceptanceEvaluator
  -> SUCCESS / PARTIAL / BLOCKED / IMPOSSIBLE / FAILED_SAFE / ABORTED
```

This slice does **not** create a new authority source, database, memory system, learning engine, or network path.

## Reuse decisions

H1 deliberately reuses:

- `prompt_compiler.py` for local deterministic prompt normalization and digest binding;
- `task_contract.py` as the authoritative execution contract;
- `capability_authority.py` as the deny-by-default capability projection;
- existing acceptance/evidence conventions instead of creating an autonomous model judge.

The Harness compiler cannot derive tools, write scope, network scope, model authority, or data authority from prompt text.

## Canonical task contract

`CanonicalTaskSpec` binds:

- task identity/type/sensitivity/risk;
- prompt compiler version;
- raw and compiled prompt digests;
- immutable TaskContract authority fingerprint;
- acceptance contract fingerprint.

`compiled_intent` is working-memory data only. It is excluded from canonical metadata/fingerprints so H1 does not create another persistent raw confidential prompt copy.

A task spec can re-check the current `TaskContract` authority fingerprint before execution. Any change fails closed.

## Acceptance contract

Each criterion declares:

- compact criterion ID;
- observable statement;
- deterministic verifier identifier where available;
- required/optional hard-gate role;
- progress weight.

Results use `PASS`, `FAIL`, `BLOCKED`, or `NOT_RUN`.

`PASS`, `FAIL`, and `BLOCKED` require evidence references. A required criterion without evidence can therefore never become a verified PASS.

Optional criteria contribute progress but can never compensate for a failed, blocked, missing, or unevaluated mandatory criterion.

## Deterministic terminal-state rules

- all mandatory criteria PASS -> `SUCCESS`;
- any mandatory criterion BLOCKED -> `BLOCKED`;
- otherwise incomplete/failed mandatory acceptance -> `PARTIAL`;
- `IMPOSSIBLE`, `FAILED_SAFE`, and `ABORTED` are explicit stop states and require evidence.

No caller may force `SUCCESS`.

## Progress

For the acceptance contract:

```text
completion_percent = verified_pass_weight / total_planned_weight * 100
remaining_percent  = 100 - completion_percent
```

Only evidence-backed PASS contributes verified weight.

This deliberately allows `SUCCESS` with less than 100% progress when only optional criteria remain; optional quality work cannot become a hidden hard gate. A release policy may separately require 100% when all planned optional work is release-mandatory.

## H1 security invariants

1. user prompt never grants authority;
2. TaskContract remains authoritative;
3. authority change after compilation fails closed;
4. canonical metadata contains prompt digests, not prompt text;
5. required PASS without evidence is impossible;
6. optional PASS cannot mask mandatory failure;
7. blocker/irreducible stop claims require evidence;
8. evaluator is deterministic and uses no LLM.

## Acceptance evidence

The H1 unit suite covers deterministic fingerprints, prompt non-persistence, prompt authority-escalation attempts, task-ID mismatch, evidence-required PASS, optional-vs-hard-gate behavior, blocked state, unknown/duplicate results, terminal stop evidence, authority rebinding detection, and acceptance contract fingerprint changes.
