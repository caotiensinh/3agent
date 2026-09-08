---
name: pc-diagnostic-streaming
description: Diagnose Windows and Linux PC faults through layperson normalization, streaming evidence correlation, adaptive questioning, bounded micro-tools, and verified repair escalation.
license: Project-internal
---

# PC Diagnostic Streaming

This candidate defines diagnostic reasoning; it grants no execution authority.

## Core loop
Treat customer observations, logs, events, dumps, telemetry, inventory, and command results as one stream:

`OBSERVE -> NORMALIZE -> CORRELATE -> UPDATE -> DISCRIMINATE -> ACT -> VERIFY -> repeat`

Do not finish a fixed questionnaire before analysis. After each meaningful item, preserve raw evidence, normalize meaning, update competing hypotheses, retire obsolete questions/tests, and choose the smallest next action with the highest diagnostic value.

## Customer-language boundary
Customers describe experience, not protocol state or root cause. Keep exact wording separate from technical interpretation. Statements such as "mất mạng", "máy đơ", "GPU hỏng", or "Windows Update làm hỏng máy" are observations or hypotheses, not confirmed technical facts. Ask about visible, audible, physical, or comparable behavior; do not require unexplained IT jargon.

## Adaptive questioning
Ask normally 1 question and at most 3 per turn. Each question must separate active hypotheses or obtain context unavailable from the machine. If logs answer it first, cancel it. If the user skips it, continue with other evidence.

## Evidence doctrine
A single generic event is not a root cause. Correlate the incident window across independent sources. Keep both human and machine evidence when they conflict and resolve semantic ambiguity before declaring contradiction. Keep `unknown` when evidence is insufficient.

Maintain a small ranked differential, normally 3-7 hypotheses, with evidence for/against, exclusions, unresolved contradictions, recent changes, and the next discriminator.

## Tool doctrine
Prefer bounded micro-tools over broad collection. Run only subsystem evidence required by the active hypothesis. Deep collectors are fallback tools for explicit deep acquisition or when bounded evidence justifies wider collection.

Risk classes:
- S0 read-only evidence: locally authorized use.
- S1 temporary capture: notify and minimize scope.
- S2 state-changing repair/isolation: approval required.
- S3 disruptive action: explicit approval plus recovery path.
- S4 high-risk action: never automatic.

Never clear logs, hide evidence, exfiltrate secrets, or apply generic repairs before evidence justifies them. Driver Verifier, forced crashes, firmware flashing, and destructive disk work are S4 examples.

## Completion
A repair is incomplete until the original symptom or a suitable verification condition is retested. Stop asking questions when evidence is sufficient, the next discriminator is machine-based, or escalation/physical inspection is required.

Detailed references and candidate tools in this directory never bypass WorkSpace policy.
