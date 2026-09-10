# WorkSpace Network AI — Independent Skill Architecture

## Goal

The Network Experience Engine must distill large public and local corpora into **separate reusable expert skills**, then combine their evidence-backed results through a later coordinator.

The first three mandatory specialist skills are:

1. **Intrusion Trace Hunting** — reconstruct attacker movement and compromise paths from multi-source evidence.
2. **Log-based Incident Diagnosis** — isolate operational/network/service root causes from symptoms and cascading failures.
3. **Host Log Forensics** — reconstruct post-compromise host activity from Windows/Linux event evidence.

They are deliberately independent. No specialist may silently adopt another specialist's conclusion.

## Why independent skills

A single general-purpose security prompt is too easy to bias and too hard to evaluate. Independent skills provide:

- separate training/evaluation corpora;
- separate evidence requirements;
- separate stop/unknown conditions;
- separate false-positive controls;
- independent confidence;
- clean regression testing;
- later ensemble/fusion without losing provenance.

## Common evidence doctrine

Every material conclusion must resolve to immutable evidence references. Specialists may infer hypotheses, but must label them as hypotheses. `confirmed` remains reserved for ground truth or operator-verified conclusions.

```text
OBSERVED EVIDENCE
      |
      +--> supporting
      +--> contradicting
      +--> discriminator
      `--> outcome
              |
              v
      SPECIALIST RESULT
```

Raw/normalized public logs remain temporary staging material. Durable material is case/pattern/skill knowledge plus provenance.

## Skill 1 — Intrusion Trace Hunting

Primary question:

> What evidence-supported path did an attacker take through accounts, hosts and network activity?

Core reasoning:

```text
initial suspicious identity/host
 -> authentication relationship
 -> process/script execution
 -> DNS/network activity
 -> credential/lateral movement
 -> persistence/privilege/defense evasion
 -> C2/exfiltration indicators
```

The skill must actively search for discontinuities and missing evidence. It must never fill timeline gaps merely because an ATT&CK sequence would be plausible.

High-value enterprise corpora:

- LANL comprehensive multi-source events;
- Splunk BOTS v2;
- CSE-CIC-IDS2018 for network-side attack discrimination.

MITRE ATT&CK is a behavior/data-source reference, not incident ground truth.

## Skill 2 — Log-based Incident Diagnosis

Primary question:

> Which failure best explains the observed cross-layer symptoms, and what evidence rules alternatives in or out?

Core reasoning:

```text
impact
 -> symptom timeline
 -> earliest abnormal evidence
 -> candidate causes
 -> supporting/contradicting evidence
 -> discriminator checks
 -> likely root cause
 -> confirmed cause only when verified
 -> verified remediation when available
```

This skill covers security-independent failures too: link degradation, DNS/DHCP problems, routing/VPN faults, service saturation, process crashes, container/service failures, RTSP instability, resource exhaustion and cascading errors.

Public system-log corpora such as Loghub-2.0 may be used only inside their license boundary. Local verified enterprise incidents are expected to become the highest-value long-term source for this skill.

## Skill 3 — Host Log Forensics

Primary question:

> What traces did an attacker leave on a host, and what sequence can be defensibly reconstructed from host logs?

Core evidence includes, when available:

- Windows Security;
- Sysmon;
- PowerShell;
- WMI;
- Scheduled Task;
- Service Control Manager;
- Windows Firewall;
- registry/file events;
- Linux auth/auditd/journal;
- process execution and network connection evidence.

The skill explicitly looks for:

- suspicious logons and privilege changes;
- process ancestry and script execution;
- persistence;
- credential access indicators;
- lateral movement;
- defense evasion;
- log clearing/tampering and resulting visibility gaps.

It is **log forensics**, not full disk/memory forensics. If a conclusion requires MFT, registry hive, browser, memory, disk image or other unavailable artifacts, the skill must request that evidence rather than pretend logs are sufficient.

## Public source strategy

### Enterprise-usable core

- LANL multi-source events: auth/process/DNS/flow/red-team ground truth.
- Splunk BOTS v2: CC0 incident evidence, full and attack-only variants.
- CSE-CIC-IDS2018: enterprise-scale network attack evidence.
- MITRE ATT&CK STIX: reviewed technique/behavior/data-source reference; not case ground truth.

### High-value but license-gated

- OTRF Security-Datasets: rich Windows/Sysmon/PowerShell/network attack scenarios. Current repository metadata has conflicting MIT/GPL signals, therefore WorkSpace keeps it `review_required` until clarified.
- Atomic-EVTX: extensive Windows EVTX/JSON attack simulations; no explicit repository license was found during review, therefore `review_required`.

### Research-only

- Loghub-2.0: system-log research/academic license; may improve parser/pattern research but cannot silently produce enterprise-approved skill material.
- MAWI / TON_IoT remain isolated according to the dataset registry.

## Distillation curriculum

Each skill follows the same learning stages but with different case filters and evaluation targets:

```text
PUBLIC/LOCAL EVIDENCE
      |
      v
INCIDENT SEGMENTATION
      |
      v
EXPERIENCE CASES
      |
      v
SKILL-SPECIFIC PATTERNS
      |
      v
CANDIDATE PROCEDURE
      |
      v
HELD-OUT INCIDENT EVALUATION
      |
      v
INDEPENDENT REVIEW + HASH
      |
      v
APPROVED SKILL
```

Training/distillation must maximize **case diversity**, not raw byte count. Repeated near-identical events cannot inflate independent-case support.

## Future coordinator

The coordinator is intentionally deferred until specialists have independent evaluation evidence.

Its eventual contract is:

```text
CURRENT INCIDENT EVIDENCE
        |
   +----+------------------+
   |                       |
   v                       v
Intrusion Hunter      Incident Diagnosis
   |                       |
   +-----------+-----------+
               |
               v
        Host Log Forensics
               |
               v
       RESULT FUSION LAYER
               |
               v
      Combined assessment
```

The real implementation should normally invoke only relevant specialists; the diagram shows composability, not a requirement to run all three every time.

The fusion layer must preserve per-skill:

- evidence IDs;
- findings;
- hypotheses;
- contradictory evidence;
- missing evidence;
- confidence;
- stop conditions;
- provenance.

It may rank or reconcile results, but may not convert an unconfirmed specialist hypothesis into a confirmed fact.

## Security boundary

These skills are analysis capabilities, not authority grants.

They must not automatically:

- execute shell/network commands;
- quarantine hosts;
- block accounts;
- modify firewall/router/switch configuration;
- delete evidence;
- collect unapproved packet captures;
- install tools;
- promote themselves into `skills/registry.json`.

Any future response action remains a separate deterministic/approved capability.

## Repository placement

`network_skills/*.json` are training/evaluation blueprints and are intentionally outside `skills/`.

Only after independent evaluation and review should a distilled compact procedure be transformed into an instruction-only `skills/<name>/SKILL.md`, reviewed, hashed and admitted through the existing `ApprovedSkillLoader` path.
