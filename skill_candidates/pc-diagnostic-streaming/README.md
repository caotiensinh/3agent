# PC Diagnostic Streaming Candidate

Status: **candidate / quarantine**. This package is designed for `skill_candidates/` and is not an approved WorkSpace skill until the repository admission gate reviews the exact commit and explicitly promotes the reviewed instruction into `skills/registry.json`.

## Goal
Provide a Windows/Linux PC diagnostic framework that behaves like an experienced support engineer: listen to imperfect customer descriptions, normalize them into technical observations, collect bounded evidence immediately, continuously update a differential diagnosis, adapt the next question/test, repair only when justified, and verify the original failure mode.

The workflow is streaming rather than questionnaire-first:

`user answer + logs/events + telemetry + tool result -> normalize -> correlate -> re-rank hypotheses -> next best action -> repeat`

## Design rules
- Preserve customer wording separately from technical interpretation.
- Treat customer causal claims as hypotheses, not facts.
- Ask 1-3 high-information questions rather than a long form.
- Never wait for all answers before analyzing available evidence.
- Prefer machine-readable evidence for facts the machine can provide.
- Use bounded micro-tools first; deep collection is fallback only.
- A single generic event such as Windows Kernel-Power 41 is evidence of an unclean restart, not a root cause by itself.
- Keep contradictions instead of silently overwriting them.
- Keep `unknown` when evidence is insufficient.
- Separate diagnosis from repair authority and apply the S0-S4 safety ladder.
- Verify the original symptom after any repair.

## Package
- `SKILL.md` — compact agent doctrine suitable for later admission review.
- `references/ADAPTIVE_DIAGNOSTIC_LOOP.md` — streaming controller.
- `references/USER_LANGUAGE_NORMALIZATION.md` — layperson-to-technical semantic layer.
- `references/SYMPTOM_TRIAGE.md` — symptom routing.
- `references/WINDOWS_PLAYBOOKS.md` / `LINUX_PLAYBOOKS.md` — OS evidence paths.
- `references/CAUSE_TAXONOMY.md` — normalized cause classes.
- `references/COMMAND_SAFETY.md` — S0-S4 action policy.
- `references/SOURCES.md` — source registry.
- `rules/*.yaml` — machine-readable adaptive, normalization, and scoring rules.
- `schemas/diagnostic_case.schema.json` — structured case state.
- `tools/manifest.yaml` — candidate micro-tool catalog and risk classes.
- `tools/windows/` / `tools/linux/` — read-only micro-tools plus explicit deep collectors.
- `examples/freeze-reboot.md` — worked reasoning example.

## Runtime loading doctrine
Load `SKILL.md` first. Load only the reference and micro-tool that matches the active symptom/subsystem. Do not preload the full corpus for every support interaction.

## Intended next admission step
Review the exact candidate commit for provenance, privacy, authority boundaries, deterministic validation, and size budget. Promotion should update or complement `skills/office-it-diagnostics` rather than bypassing its current fail-closed registry controls.
