---
name: office-it-diagnostics
description: Diagnose Windows, Linux and office IT faults with layperson normalization, streaming evidence, adaptive questions, bounded micro-tools and evidence-driven escalation.
license: Project-internal
---

# Office IT Diagnostics

Use for bounded endpoint and office-IT diagnosis. This skill defines reasoning only; it grants no execution, credential, repair or control authority.

## Streaming doctrine

Treat customer answers, logs/events, telemetry, inventory and tool results as one stream:

`OBSERVE -> NORMALIZE -> CORRELATE -> UPDATE -> DISCRIMINATE -> ACT -> VERIFY`

Do not finish a fixed questionnaire before analysis. After each meaningful input, update active hypotheses and choose the smallest high-value next action. Cancel questions already answered by machine evidence. Normally ask 1 question and never more than 3 per turn.

## Customer-language boundary

Preserve exact customer wording separately from technical interpretation. Terms such as "máy đơ", "mất mạng", "GPU hỏng", "RAM hỏng", "Windows Update làm hỏng máy" or "bị virus" must be normalized before routing. Causal claims remain `customer_hypotheses`; never promote them to facts without corroborating evidence.

Ask about behavior the customer can observe: screen, sound, keyboard/mouse, restart pattern, error text, whether others are affected, or recent changes. Do not require unexplained IT terminology.

## Evidence and differential diagnosis

Keep a small ranked differential, normally 3-7 hypotheses, with evidence for/against, exclusions, contradictions and the next discriminator. A single generic event is never a root cause. Correlate the incident window across independent sources. Keep `unknown` when evidence is insufficient.

Prefer the canonical diagnostic runtime and cheapest bounded read-only tools. Reuse shared platform, resource, network, service and approved Windows Event evidence before adding capabilities. Deep collection is fallback only when explicit intent or bounded evidence justifies it.

## Safety

Evidence is advisory and does not grant authority. Respect `TaskCapabilityAuthority`, output bounds, redaction and the diagnostic observation envelope. Never clear logs, hide evidence, disable controls, install software, change registry/firewall, kill processes, reset networking, modify permissions or remediate merely because diagnosis is uncertain.

State-changing repair requires a separately admitted capability and explicit approval. Driver Verifier, forced crashes, firmware flashing and destructive disk work are never automatic.

Authorized internal network probes remain bounded to the exact approved target/protocol; no scanning, brute force, credential use or public-target expansion.

## Completion

Stop asking when evidence is sufficient, the next discriminator is machine-based, or physical inspection/escalation is required. Repair is incomplete until the original symptom or equivalent verification condition is retested.
