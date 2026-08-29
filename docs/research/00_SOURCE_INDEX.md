# WorkSpace Efficient Reasoning Research — Source Index

Status: project research archive and implementation ordering record.

## Canonical reading order

1. `../WORKSPACE_EFFICIENT_REASONING_DOCTRINE_V1.md` — original WorkSpace doctrine already present in the repository.
2. `01_PICOLM_PHILOSOPHY.md` — the resource-minimalism doctrine WorkSpace adopts from PicoLM.
3. `02_WORKSPACE_EFFICIENT_REASONING_V2.md` — project-integrated v2 architecture doctrine.
4. `03_WORKSPACE_EFFICIENT_REASONING_V2_FACT_CHECKED.md` — corrections, caveats, and architectural additions from the fact-check pass.
5. `04_WORKSPACE_EFFICIENCY_PLAYBOOK_V3.md` — implementation ordering and measurable decision gates.
6. `../EFFICIENT_REASONING_V2_V3_IMPLEMENTATION.md` — implementation baseline already merged into WorkSpace.
7. `05_MASTER_IMPLEMENTATION_CHECKLIST.md` — authoritative execution checklist. Code work must proceed in checklist order unless an explicit security/production blocker requires reordering.

## Original research artifacts reviewed on 2026-08-29

The project integration is based on four research artifacts supplied/reviewed for WorkSpace:

- WorkSpace Efficient Reasoning Doctrine v1.0 — Agent-Ready Engineering Research Report.
- WorkSpace Efficient Reasoning Doctrine v2.0.
- WorkSpace Efficient Reasoning Doctrine v2.0 — Fact-Checked, Corrected, and Expanded.
- WorkSpace Efficiency Playbook v3.0.

The v1 project doctrine preserves the central rule: do less probabilistic work. Deterministic software should remove unnecessary decisions, context should be selected rather than dumped, model strength should escalate only when evidence requires it, important results should be externally verified, and security must remain outside the model.

The fact-check pass is authoritative when it conflicts with an older research claim. In particular, do not reintroduce the stale mini-swe-agent 65% figure, the PromptIntern ACL-Findings attribution, or the unverified BitNet #600 / Semantic Router #2971/#2965 citations as facts.

## Normative synthesis

The project-level doctrine is:

```text
PicoLM resource discipline
        ↓
MINIMIZE
        ↓
SELECT
        ↓
CONSTRAIN
        ↓
EXECUTE
        ↓
VERIFY
        ↓
ESCALATE ONLY WHEN REQUIRED
        ↓
MEASURE VERIFIED WORK / RESOURCE
```

The documents in this directory are not a mandate to install every referenced framework. They are design evidence. New runtime/cache/router/compression dependencies remain benchmark-gated.
