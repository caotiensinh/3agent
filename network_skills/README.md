# WorkSpace Network AI Skill Blueprints

This directory contains **independent candidate blueprints**, not approved runtime skills.

They exist so the Network Experience Engine can distill public and local evidence into separate long-lived capabilities before any orchestration layer combines them.

## Core skills

1. `intrusion-trace-hunting.json` — reconstruct intrusion traces across authentication, process, DNS, network, IDS and host evidence.
2. `log-incident-diagnosis.json` — diagnose operational/network/service incidents from multi-source logs and metrics.
3. `host-log-forensics.json` — perform read-only host forensic reconstruction from Windows/Linux logs after suspected compromise.

## Separation rule

Each skill must be trained/evaluated independently and must emit its own evidence-backed result. A future coordinator may combine those results, but cannot overwrite a skill's evidence, confidence, unknowns or stop conditions.

```text
current evidence
   |-- intrusion-trace-hunting
   |-- log-incident-diagnosis
   `-- host-log-forensics
             |
             v
      future coordinator
             |
             v
  combined diagnosis/report
```

## Promotion rule

Blueprint -> extracted cases -> repeated patterns -> candidate skill -> held-out evaluation -> independent security/content review -> compact `SKILL.md` -> SHA-256 registry admission.

Blueprints in this directory are deliberately outside `skills/`; `ApprovedSkillLoader` must never load them directly.

## Data doctrine

Public raw logs are temporary evidence. Durable outputs are compact experience cases, patterns, held-out evaluation cases, provenance, and reviewed skills. Research-only or license-ambiguous corpora may improve research/evaluation but cannot silently produce enterprise-approved skill material.
