# WorkSpace Engineering Doctrine — Reading and Authority Order

This index prevents research notes, implementation ideas, and normative project rules from being mixed together.

## Authority order

When two documents appear to conflict, use this order:

1. **Human-approved security/privacy/authority constraints and repository governance**
   - `SECURITY_POLICY.md`
   - `AGENTS.md`
   - `CLAUDE.md` when applicable
   - explicit task/user authority and applicable project specs
2. **Pico-first normative engineering philosophy**
   - `docs/PICO_FIRST_ENGINEERING_PHILOSOPHY.md`
3. **Project architecture and agent contracts**
   - `docs/ARCHITECTURE.md`
   - `docs/HARNESS.md`
   - agent-specific specifications
4. **Research evidence** — informative, not automatically normative
   - R1 original Efficient Reasoning doctrine
   - R3 fact-checked/corrected v2 layer
   - R2 expanded v2 engineering doctrine
   - R4 v3 implementation playbook
5. **Derived implementation decisions**
   - `docs/EFFICIENT_REASONING_V2_V3_IMPLEMENTATION.md`
   - `docs/INFERENCE_AND_SKILL_OPTIMIZATION_2026-08-29.md`
6. **Executable implementation order**
   - `docs/IMPLEMENTATION_CHECKLIST.md`

A checklist item may never override a higher-authority security or correctness requirement.

## Research reading order

### R1 — Original doctrine

Purpose: understand the original thesis and design intent.

Core idea carried forward:

```text
MINIMIZE → SELECT → CONSTRAIN → EXECUTE → VERIFY → ESCALATE ONLY IF REQUIRED
```

Treat historical/current-technology claims as research claims, not immutable truth.

### R3 — Fact-checked and corrected v2

Read immediately after R1. Its job is to correct attribution, stale capability claims, and missing modern techniques. Where R1 and R3 disagree on factual attribution or current capability, R3 is the preferred research evidence.

### R2 — Expanded v2 engineering doctrine

Use for architectural detail: deterministic control plane, context precision, structured outputs, routing/escalation, verification, caching, and security/trust-boundary consequences.

### R4 — Efficiency playbook v3

Use for execution order and benchmark gates. Its most important operational lesson is that optional infrastructure follows measurement; it does not precede it.

All archived source bytes and hashes are documented in `docs/research/README.md`.

## How an agent should use this hierarchy

For every engineering task:

```text
1. Read security/governance.
2. Apply Pico-first laws.
3. Read the relevant project contract.
4. Consult R1/R3/R2/R4 for rationale and candidate techniques.
5. Check IMPLEMENTATION_CHECKLIST for current sequence/status.
6. Implement only the current eligible item.
7. Add deterministic tests/evidence.
8. Update checklist status only after evidence exists.
```

## Status vocabulary

- `DONE` — implemented and covered by repository evidence/tests.
- `NEXT` — next eligible implementation item.
- `TODO` — planned but dependency/order says not yet.
- `PARTIAL` — meaningful foundation exists but acceptance criteria are not complete.
- `BENCHMARK-GATED` — instrumentation/benchmark must run before adoption/rejection.
- `DEFERRED` — explicitly not justified by current evidence.
- `REJECTED` — benchmark/security/correctness evidence says not to adopt; this can be a successful completion state for an optional technology.

## Change control

Research sources are append-only provenance. If a later study corrects R1–R4, archive it as a new research source and update this index/checklist explicitly. Do not silently rewrite old research evidence.
