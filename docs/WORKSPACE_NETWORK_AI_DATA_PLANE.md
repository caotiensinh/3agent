# WorkSpace Network AI Experience Data Plane

## Status

Design and control-plane contract for using public network/security/operations datasets as **temporary evidence** from which WorkSpace derives reusable diagnostic experience, evidence patterns and reviewed operational skills.

The purpose of this subsystem is **not** to build a permanent raw-log warehouse.

> Specialist implementation is governed by `docs/WORKSPACE_NETWORK_SPECIALIST_HARNESS_SPEC_V1.md` and the machine-readable `evaluation/network_specialist_harness_v1.json`. The required order is goal/spec/harness/pass-fail contract first, implementation second. No specialist or coordinator may claim PASS outside those gates.

## Primary objective

WorkSpace should learn how experienced network engineers reason:

```text
symptom
  -> collect evidence
  -> correlate events across layers/time
  -> form candidate causes
  -> eliminate alternatives
  -> identify the most likely/confirmed cause
  -> select a remediation only when it has a valid basis
  -> verify the outcome
```

Public datasets are source material for that process. The durable product is compact, evidence-backed operational knowledge.

### Durable outputs

1. **Experience Case** — one bounded incident/failure/security case with symptoms, evidence references, candidate causes, confirmed cause when supported, remediation when supported, outcome and provenance.
2. **Evidence Pattern** — a repeated diagnostic pattern supported by multiple independent cases, including discriminators and false-positive checks.
3. **Evaluation Case** — held-out evidence used to test whether WorkSpace reaches the right conclusion without seeing the answer.
4. **Candidate Skill** — a compact advisory procedure derived from reviewed evidence patterns. It is never automatically trusted or loaded.
5. **Provenance** — immutable hashes and lineage proving where each retained conclusion came from.

### Explicit non-goals

- permanent storage of public raw PCAP/log corpora;
- permanent storage of normalized event streams after experience extraction;
- asking an LLM to memorize billions of log lines;
- treating a dataset label as a complete operational procedure;
- inventing remediation that is absent from evidence or authoritative/verified operational knowledge;
- automatically promoting model-generated procedures into WorkSpace's approved skill registry.

## Core principle

```text
RAW LOGS ARE EVIDENCE, NOT KNOWLEDGE.
NORMALIZED EVENTS ARE WORKING MATERIAL, NOT THE PRODUCT.
EXPERIENCE + PATTERNS + REVIEWED SKILLS ARE THE PRODUCT.
```

This matches the WorkSpace design principle that context is working memory, not storage, and that deterministic constraints and compact handoffs should eliminate unnecessary data movement.

## End-to-end lifecycle

```text
PUBLIC DATASET
     |
     v
BOUNDED FETCH
     |
     v
RAW SCRATCH CACHE                 <- temporary
     |
     v
VERIFY SHA-256 / LICENSE / TYPE
     |
     v
NORMALIZED EVIDENCE STAGING       <- temporary
     |
     v
CORRELATE + SEGMENT INCIDENTS
     |
     v
EXPERIENCE CASES                  <- durable compact knowledge
     |
     +--------------------+
     |                    |
     v                    v
EVIDENCE PATTERNS      EVALUATION CASES
     |
     v
CANDIDATE SKILLS                  <- advisory, untrusted candidate
     |
     v
INDEPENDENT REVIEW / TEST / HASH
     |
     v
APPROVED WORKSPACE SKILL          <- existing skill trust path

After successful extraction:
RAW SCRATCH -> DELETE
NORMALIZED STAGING -> DELETE
```

The same architecture applies to enterprise-local telemetry, except confidential telemetry never enters the public fetch zone.

## Trust-zone design

```text
                          PUBLIC INTERNET
                                |
                         HTTPS GET/HEAD only
                                |
                    +-----------v-----------+
                    | Zone D1: FETCH        |
                    | workspace-dataset-fetch|
                    |                       |
                    | no Core access        |
                    | reviewed URL allowlist|
                    +-----------+-----------+
                                |
                                v
              /var/cache/workspace-datasets/incoming
                       RAW / TEMPORARY
                                |
                                v
                    +-----------+-----------+
                    | Zone D2: PROCESS      |
                    | workspace-dataset     |
                    |                       |
                    | NO Internet           |
                    | verify / normalize    |
                    | correlate / extract   |
                    +-----------+-----------+
                                |
                                v
             /var/cache/workspace-datasets/normalized
                    NORMALIZED / TEMPORARY
                                |
                                v
               EXPERIENCE CONTRACT VALIDATION
                                |
              +-----------------+-----------------+
              |                                   |
              v                                   v
 /var/lib/workspace-network-experience/approved   research-only store
       cases / patterns / eval / provenance
              |
              | read-only
              v
      +-------+--------+
      | WorkSpace Core |
      | NO Internet    |
      +-------+--------+
              |
              v
      evidence-first reasoning
```

`workspace-public` is not reused for dataset ingestion. Dataset acquisition has different parser, volume and lifecycle risks.

## Storage contract

```text
/var/cache/workspace-datasets/incoming/
    raw public objects
    ephemeral
    re-fetchable

/var/cache/workspace-datasets/normalized/
    normalized flow/event staging
    exists only until experience extraction completes

/var/lib/workspace-network-experience/approved/
    compact approved experience cases, evidence patterns and evaluation artifacts

/var/lib/workspace-network-experience/candidate-skills/
    advisory skill drafts awaiting independent review
    not visible to ApprovedSkillLoader

/var/lib/workspace-network-experience/provenance/
    immutable source/transform/output lineage

/var/lib/workspace-datasets/research/
    research-only material isolated from enterprise experience and skills
```

Default V1 budgets:

- raw scratch cache: 80 GiB;
- one acquisition job: at most 20 GiB;
- one job: at most 32 objects;
- full remote sync: denied;
- raw retention: `ephemeral`;
- normalized retention: `until_experience_extracted`;
- raw logs durable: `false`;
- normalized events durable: `false`;
- candidate skills auto-approve: `false`.

## Experience Case contract

A retained case is deliberately compact. It stores observations and references to evidence, never an arbitrary raw log dump.

Conceptual form:

```text
case_id
incident_class
symptoms[]

evidence[]
  evidence_id
  role: supporting | contradicting | discriminator | outcome
  observation
  source_ref
  source_sha256

candidate_causes[]
confirmed_cause | null
cause_basis: ground_truth | operator_verified | unknown

remediation[]
  action
  basis: observed_outcome | ground_truth | authoritative_reference | operator_verified
  evidence_ids[]

outcome | null
confidence
provenance_refs[]
```

### Cause rule

A model may propose candidate causes, but `confirmed_cause` may be stored only when the case has an accepted basis such as dataset ground truth or operator verification.

If the source does not support a confirmed cause:

```text
confirmed_cause = null
cause_basis = unknown
```

That is preferable to false certainty.

### Remediation rule

Logs often show what happened but do **not** show the correct fix. Therefore a remediation step may become durable only when its basis is one of:

- a successful observed outcome;
- ground truth provided with the case;
- an authoritative reviewed operational reference;
- operator verification from a real incident/test.

`model_inference`, unsupported guesswork or generic Internet advice is not an allowed remediation basis.

If no valid remediation evidence exists, the retained case has an empty remediation list.

## From cases to patterns

One incident is an anecdote. WorkSpace should not promote it directly into general knowledge.

A durable `EvidencePattern` requires multiple independent supporting cases.

Example:

```text
Pattern: physical Ethernet link degradation

Symptoms:
- packet loss increases
- RTSP reconnects increase

Evidence requirements:
- interface CRC/input error trend
- packet loss measurement
- scope of affected endpoints

Discriminators:
- errors rise on one local switch port
- WAN path remains healthy
- service process remains healthy

Likely causes:
- cable/connector degradation
- faulty PHY/switch port

False-positive checks:
- upstream congestion
- camera/server CPU saturation
- remote service outage
```

The pattern does not preserve millions of packets. It preserves the **relationship between useful evidence and diagnostic conclusions**.

## From patterns to skills

Dataset-derived procedures are created only as `SkillCandidate` objects.

A candidate contains:

```text
name
description
derived_pattern_ids[]
evidence_requirements[]
procedure_steps[]
stop_conditions[]
authority = advisory
auto_promotable = false
```

It cannot grant itself network, shell, credential or write authority.

Before it becomes an approved WorkSpace skill it must pass the existing WorkSpace skill path:

```text
candidate
   -> independent content/security review
   -> evaluation against held-out incidents
   -> compact instruction-only SKILL.md
   -> SHA-256 recorded in skill registry
   -> ApprovedSkillLoader validation
   -> usable by a task only when task authority also permits it
```

This is intentionally separate from dataset extraction. The current WorkSpace skill loader already treats skills as small reviewed procedures rather than storage and enforces hashes and authority restrictions.

**Candidate skill generation never edits `skills/registry.json` and never writes into an approved skill directory.** Promotion requires a separate explicit reviewed operation.

## Runtime reasoning: how the experience is used

The preferred runtime is **case-based/evidence-based reasoning**, not raw-log retrieval.

```text
LIVE NETWORK EVIDENCE
        |
        v
NORMALIZE CURRENT OBSERVATIONS
        |
        v
RETRIEVE SIMILAR EXPERIENCE CASES + PATTERNS
        |
        v
BUILD CANDIDATE CAUSES
        |
        v
COMPARE REQUIRED EVIDENCE / DISCRIMINATORS
        |
        +---- missing evidence ----> ask collector for bounded evidence
        |
        v
RANK CAUSES WITH EXPLICIT SUPPORT / CONTRADICTION
        |
        v
DIAGNOSIS + CONFIDENCE
        |
        v
RETRIEVE REVIEWED SKILL, IF ONE MATCHES
        |
        v
RECOMMEND VERIFIED ACTION + VERIFICATION STEP
```

Example final reasoning artifact:

```text
Observed:
- Gi1/0/12 CRC errors rose sharply
- packet loss affects only CAM-12 path
- RTSP reconnects rose at the same timestamps
- WAN RTT and loss remained normal

Candidate causes:
1. local physical link degradation   HIGH
2. camera overload                   LOW
3. WAN congestion                    REJECTED

Why:
- local interface error counter is a strong discriminator
- WAN evidence contradicts congestion hypothesis
- temporal correlation matches prior verified link-failure cases

Recommended next action:
- run the approved physical-link verification skill
- do not replace hardware automatically
```

The AI should always be able to expose **which evidence supported or contradicted a cause**.

## Public dataset selection strategy

WorkSpace should fetch only shards that add diagnostic information.

High-value examples:

- LANL: authentication/process/DNS/flow correlation -> multi-source incident chains;
- CSE-CIC-IDS2018: labeled flow/attack evidence -> discriminative attack patterns;
- BOTS v2: cross-source enterprise logs -> incident correlation reasoning.

Raw PCAP is fetched only when packet-level detail is required to validate a pattern/extractor. It is not a default retention target.

Research-only datasets remain isolated and cannot produce enterprise-approved patterns or skills under a research-only license state.

## Own-network learning

Public datasets provide broad experience. The highest-value operational experience eventually comes from the company's own verified incidents:

```text
switch/router syslog
SNMP/interface counters
NetFlow/IPFIX
DNS/DHCP
VPN
Windows/Linux events
camera/RTSP events
server/container events
latency/loss/jitter
operator incident notes
verified remediation outcome
```

For local incidents the ideal closed loop is:

```text
incident evidence
  -> diagnosis
  -> operator action
  -> verification
  -> outcome
  -> reviewed Experience Case
  -> repeated cases
  -> Evidence Pattern
  -> reviewed Skill
```

This allows WorkSpace to accumulate enterprise-specific operational experience without exporting confidential data.

## Admission and license lifecycle

```text
REQUEST
  |
  v
DATASET REGISTRY LOOKUP
  |
  +-- unknown ----------> DENY
  |
  v
LICENSE / STATUS GATE
  |
  +-- blocked ----------> DENY
  +-- review_required --> DENY
  +-- research_only ----> research purpose only
  |
  v
VARIANT / PURPOSE GATE
  |
  v
BYTE + OBJECT BUDGET
  |
  v
FETCH -> VERIFY -> TEMP NORMALIZE
  |
  v
EXPERIENCE EXTRACTION
  |
  v
EXPERIENCE CONTRACT VALIDATION
  |
  +-- unsupported cause/remediation --> retain as unknown, never fabricate
  |
  v
PROMOTE COMPACT EXPERIENCE / PATTERN / EVAL
  |
  v
DELETE RAW + NORMALIZED STAGING WHEN NO LONGER REQUIRED
```

`experience_extraction` is the primary enterprise acquisition purpose. `training` remains available only as a secondary bounded experiment path; it does not change the no-raw-retention rule.

## CLI V1

Primary use:

```bash
workspace-network-data plan cse-cic-ids2018 \
  --purpose experience_extraction \
  --variant processed-ml \
  --estimated-bytes 1073741824 \
  --objects 2
```

`experience_extraction` is also the CLI default purpose.

The command creates an immutable bounded plan and performs no network I/O.

## Security invariants

1. `workspace-core` has no Internet/LAN egress.
2. Internet-capable dataset fetch code cannot read confidential WorkSpace data.
3. Fetch and parse/extract use separate OS identities.
4. Raw public bytes are untrusted.
5. License state is deterministic policy, never LLM inference.
6. Whole-corpus sync is denied by default.
7. Raw and normalized logs are temporary staging material.
8. Durable causes/remediation require explicit evidence basis.
9. A single case cannot become a general evidence pattern.
10. Dataset-derived skills remain advisory candidates and cannot auto-promote.
11. Approved skills retain the existing WorkSpace hash/review/authority boundary.
12. Every durable experience artifact is traceable to source hashes and transformation provenance.
13. Specialist-visible evaluation input contains neither hidden ground truth nor case-class labels such as positive/negative/ambiguous.
14. Pass/fail thresholds are frozen before candidate implementation and cannot be relaxed merely to make an existing candidate pass.

## Implementation phases

### G0 / V1 — control plane, experience contract and specialist harness contract

Implemented on this branch:

- reviewed dataset registry;
- license/purpose/status admission;
- `experience_extraction` acquisition purpose;
- bounded scratch policy;
- explicit prohibition on durable raw/normalized log retention;
- stable policy/registry fingerprints;
- source provenance templates;
- `ExperienceCase`, `EvidencePattern` and `SkillCandidate` validation contracts;
- three independent specialist blueprints;
- frozen specialist harness spec and machine-readable pass/fail profile;
- prohibition on unsupported confirmed causes/remediation;
- prohibition on candidate-skill self-approval.

### G1 / V3 — corpus boundary and evidence extraction

The first code is harness infrastructure, not model training:

1. corpus manifest and hidden-ground-truth boundary;
2. bounded adapters for CIC/LANL/BOTS;
3. incident slicer and evidence-reference builder;
4. deterministic harness validator/scorer;
5. staging deletion and provenance receipt.

### G2 — specialist baseline

Build the smallest evidence-first specialist implementation for each blueprint, preferring procedure + deterministic retrieval before fine-tuning.

### G3 — held-out and hard-negative evaluation

Freeze holdout manifest before candidate execution and require all quality plus zero-tolerance security/evidence/license gates.

### G4 — approved skill promotion

Only independently reviewed G3 PASS candidates may become compact hashed skills under the existing WorkSpace skill trust path.

### G5 — multi-skill coordinator

Only after the required specialists reach G4. The coordinator must preserve disagreement, contradiction and uncertainty rather than manufacture consensus.

## Final design statement

The data plane exists to turn large external log collections into **small, auditable operational experience**.

The intended compression is conceptual:

```text
TERABYTES OF RE-FETCHABLE PUBLIC LOGS
                  |
                  v
       BOUNDED TEMPORARY EVIDENCE
                  |
                  v
       VERIFIED INCIDENT CASES
                  |
                  v
        REPEATED PATTERNS
                  |
                  v
       REVIEWED DIAGNOSTIC SKILLS
```

WorkSpace should remember **how evidence leads to a diagnosis**, not remember every packet that ever passed through a network.
