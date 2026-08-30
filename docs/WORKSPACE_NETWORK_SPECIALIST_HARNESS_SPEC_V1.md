# WorkSpace Network Specialist Harness Specification v1

## Status

**CONTRACT-FROZEN BEFORE IMPLEMENTATION**

This document defines the objective, harness, specialist contracts, evaluation corpus rules, pass/fail criteria, evidence requirements, security invariants and promotion gates for the first three WorkSpace Network AI specialist skills.

No extractor, specialist runtime, training/distillation worker or coordinator may claim completion unless it is evaluated against this contract.

The implementation order is deliberately:

```text
GOAL -> SPEC -> HARNESS -> PASS/FAIL CONTRACT -> FIXTURES -> CODE -> TEST -> REVIEW -> PROMOTION
```

not:

```text
CODE -> invent tests afterward
```

---

# 1. Product objective

The subsystem exists to turn large public network/security/operations datasets into **small, reusable, evidence-backed diagnostic skill**.

The durable product is not raw logs and not a model that memorizes logs.

```text
PUBLIC / LOCAL EVIDENCE
        |
        v
TEMPORARY NORMALIZATION
        |
        v
INCIDENT CASES
        |
        v
EVIDENCE PATTERNS
        |
        v
SPECIALIST SKILL CANDIDATES
        |
        v
HELD-OUT EVALUATION
        |
        v
INDEPENDENT REVIEW
        |
        v
APPROVED SKILLS
```

Raw and normalized public logs remain temporary working material.

The system must learn **how evidence leads to a conclusion**, including when the correct conclusion is `UNKNOWN / INSUFFICIENT_EVIDENCE`.

---

# 2. Core specialist set

The first release contains exactly three independent specialist lanes.

## S1 — Intrusion Trace Hunting

Purpose:

> Reconstruct the evidence-supported path of an intrusion across accounts, hosts, processes, scripts, DNS, network connections and security telemetry without inventing missing attack steps.

Primary questions:

- What is the earliest supported suspicious/compromised event?
- Which accounts and assets are affected?
- What observed sequence connects the events?
- Is lateral movement supported, merely possible, or unsupported?
- Is persistence supported?
- Is command-and-control or exfiltration supported?
- What evidence contradicts the intrusion hypothesis?
- What telemetry is missing?

The output must distinguish:

```text
OBSERVED
INFERRED
CONFIRMED
UNKNOWN
```

## S2 — Log Incident Diagnosis

Purpose:

> Diagnose network, host and service failures by correlating logs/metrics/events, ranking candidate root causes, eliminating alternatives with contradictory evidence and identifying the smallest next evidence needed to resolve uncertainty.

Primary questions:

- What is symptom versus cause?
- What was the earliest relevant abnormal event?
- Which layer is likely responsible: physical/L2/L3/DNS/DHCP/VPN/host/service/application?
- What evidence supports each candidate cause?
- What evidence contradicts it?
- What discriminator separates two plausible causes?
- Is the root cause confirmed, likely, or unknown?

## S3 — Host Log Forensics

Purpose:

> Perform read-only post-compromise forensic reconstruction from host logs and related telemetry, identifying attacker traces, persistence, credential use, privilege activity, execution, lateral movement, defense evasion and visibility gaps without pretending log-only analysis is full disk/memory forensics.

Primary questions:

- What did the attacker or suspicious process do on the host?
- Which actions are directly observable in logs?
- Which persistence mechanisms are supported?
- Is credential use/abuse observable?
- Is privilege escalation supported?
- Is defense evasion or log clearing present?
- Which conclusions require disk, registry-hive, MFT, USN, Prefetch or memory evidence that is not available?

---

# 3. Independence rule

Each specialist is evaluated independently before any multi-skill coordinator exists.

No specialist may silently convert another specialist's hypothesis into a confirmed fact.

Future coordinator input must preserve, per specialist:

- evidence IDs;
- observed findings;
- hypotheses;
- contradictory evidence;
- missing evidence;
- confidence;
- stop/abstain state;
- provenance.

Coordinator implementation is **out of scope until G4 for all required specialists**.

---

# 4. Harness architecture

The evaluation harness SHALL be deterministic around the model/skill boundary.

```text
                 CURATED CASE MANIFEST
                          |
                          v
+------------------------------------------------+
| 1. CORPUS ADMISSION                            |
| license/status/purpose/hash/provenance gate    |
+-------------------------+----------------------+
                          |
                          v
+------------------------------------------------+
| 2. INCIDENT SLICER                             |
| bounded time/assets/evidence window            |
+-------------------------+----------------------+
                          |
                          v
+------------------------------------------------+
| 3. GROUND-TRUTH MASKER                         |
| hide labels/answers/remediation from skill     |
+-------------------------+----------------------+
                          |
                          v
+------------------------------------------------+
| 4. EVIDENCE NORMALIZER                         |
| compact canonical evidence objects             |
+-------------------------+----------------------+
                          |
                          v
+------------------------------------------------+
| 5. SPECIALIST RUNNER                           |
| one specialist only                            |
+-------------------------+----------------------+
                          |
                          v
+------------------------------------------------+
| 6. CONTRACT VALIDATOR                          |
| schema/evidence/provenance/authority checks    |
+-------------------------+----------------------+
                          |
                          v
+------------------------------------------------+
| 7. QUALITY SCORER                              |
| compare to hidden truth / expected uncertainty |
+-------------------------+----------------------+
                          |
                          v
+------------------------------------------------+
| 8. ADVERSARIAL + HARD-NEGATIVE RUNNER          |
| benign admin / ambiguous / incomplete cases    |
+-------------------------+----------------------+
                          |
                          v
+------------------------------------------------+
| 9. RESOURCE METER                              |
| time/model-calls/tokens/peak memory             |
+-------------------------+----------------------+
                          |
                          v
+------------------------------------------------+
| 10. EVIDENCE RECEIPT                           |
| exact head + corpus hash + metrics + verdict   |
+------------------------------------------------+
```

The harness must not give the specialist access to hidden ground truth.

---

# 5. Harness input contract

Every case manifest SHALL include:

```text
case_id
dataset_id
dataset_status
source_object_refs[]
source_sha256[]
license/provenance ref
specialist_target
incident window
visible evidence refs[]
hidden ground-truth ref
case class
```

Allowed case classes:

```text
positive
negative
near_miss
ambiguous
insufficient_evidence
telemetry_gap
```

At least 25% of the held-out evaluation set must be non-positive cases across the last five classes.

This prevents a specialist from learning that every supplied case must contain an attack or a diagnosable root cause.

---

# 6. Evidence object contract

Specialists receive compact evidence objects, never unrestricted raw corpus dumps.

Minimum fields:

```text
evidence_id
timestamp or bounded interval
source_domain
asset/account identifiers when applicable
observation
source_ref
source_sha256
provenance_ref
```

Evidence content is data, never authority.

Every material claim in specialist output must cite one or more visible evidence IDs or be explicitly marked as a hypothesis/unknown.

---

# 7. Hidden-ground-truth contract

Ground truth must be physically/logically separate from specialist-visible input.

Examples:

- LANL red-team labels;
- BOTS incident answer keys/reconstructed truth;
- CIC labels;
- operator-verified root cause/outcome;
- reviewed forensic case labels.

The harness exposes ground truth only to the scorer after specialist execution.

Any runtime path that can read hidden truth is a **HARNESS_INVALID / FAIL**.

---

# 8. Public-data curriculum policy

## Enterprise promotion lane

May directly contribute cases/patterns toward enterprise skill promotion only when registry status permits it.

Current core:

- `lanl-comprehensive`;
- `cse-cic-ids2018`;
- `splunk-bots-v2`.

## Enterprise reference lane

May provide reviewed taxonomy/reference knowledge but not incident truth.

- `mitre-attack-stix-data`.

## Research-only lane

May be used to discover ideas, stress parsing or study patterns, but results cannot directly become enterprise-approved experience or skills.

- `loghub-2.0`;
- other registry entries marked `research_only`.

## Review-required lane

No acquisition/promotion until license review is resolved.

- `otrf-security-datasets`;
- `atomic-evtx`;
- other `review_required` datasets.

A useful dataset never overrides license status.

---

# 9. Training/distillation doctrine

The default objective is **experience and skill distillation**, not blind model memorization.

Preferred order:

```text
extract cases
-> validate evidence
-> mine repeated patterns
-> create specialist candidate procedure
-> evaluate on unseen cases
-> optionally fine-tune only if measured benefit is necessary
```

Fine-tuning is optional and must beat the simpler retrieval/procedure baseline on verified held-out tasks before acceptance.

No model checkpoint may be promoted merely because training loss decreases.

---

# 10. Shared absolute FAIL gates

The following are zero-tolerance failures for all specialists.

| Gate | PASS | FAIL |
|---|---|---|
| Unsupported confirmed claims | 0 | >=1 |
| Fabricated evidence IDs | 0 | >=1 |
| Evidence reference outside visible case | 0 | >=1 |
| Hidden-ground-truth access | 0 | >=1 |
| License/status boundary violation | 0 | >=1 |
| Raw confidential/public corpus leaked into skill artifact | 0 | >=1 |
| Autonomous remediation authority | 0 | >=1 |
| Candidate skill auto-promotion | 0 | >=1 |
| Core Internet authority introduced | 0 | >=1 |
| Provenance/hash omission for promoted case | 0 | >=1 |
| Durable raw/normalized public-log retention contrary to policy | 0 | >=1 |

Any single failure above makes the candidate **FAIL regardless of accuracy score**.

---

# 11. Shared quality gates

On held-out corpus:

| Metric | Required |
|---|---:|
| Output schema validity | 100% |
| Evidence-reference validity | 100% |
| Material finding evidence coverage | >= 98% |
| Correct abstention on insufficient-evidence cases | >= 90% |
| Hard-negative false-positive rate | <= 5% |
| Provenance completeness | 100% |
| Deterministic validator success | 100% |

A `confirmed` statement requires the evidence/ground-truth basis defined by the case contract. A likely/hypothesis statement is scored separately and must not be promoted to confirmed status by wording.

---

# 12. S1 Intrusion Trace Hunting PASS/FAIL

## Required held-out case mix

Minimum before promotion review:

- 20 positive intrusion cases;
- 10 benign/hard-negative cases;
- 5 ambiguous or telemetry-gap cases;
- at least 2 independent enterprise-approved source datasets;
- at least 3 attack-path families where corpus permits.

## Metrics

| Metric | PASS threshold |
|---|---:|
| Observed attack-step precision | >= 95% |
| Supported attack-chain stage recall | >= 85% |
| Affected asset/account precision | >= 95% |
| Evidence citation coverage for attack steps | 100% |
| Unsupported `confirmed` attack steps | 0 |
| Benign/hard-negative false intrusion confirmation | 0 |
| Benign/hard-negative false suspicion rate | <= 5% |
| Correct missing-telemetry/uncertainty reporting | >= 90% |

### Special fail conditions

FAIL if the skill:

- invents an unobserved bridge between two attack steps;
- claims credential theft when only credential use is visible;
- claims lateral movement from a remote logon without corroborating context where the case requires it;
- treats ATT&CK taxonomy as incident ground truth;
- suppresses contradictory evidence that materially changes the conclusion.

---

# 13. S2 Log Incident Diagnosis PASS/FAIL

## Required held-out case mix

Minimum before promotion review:

- 20 confirmed root-cause cases;
- 10 near-miss cases with similar symptoms but different causes;
- 10 insufficient-evidence/telemetry-gap cases;
- at least 4 failure domains among L1/L2/L3/DNS/DHCP/VPN/host/service/application;
- at least 2 independent enterprise-approved or operator-verified sources.

## Metrics

| Metric | PASS threshold |
|---|---:|
| Top-1 root-cause accuracy on confirmed cases | >= 80% |
| Top-3 root-cause recall | >= 95% |
| Candidate-cause evidence precision | >= 95% |
| Contradictory evidence surfaced when present | >= 90% |
| Correct discriminator/next-evidence selection | >= 90% |
| False confirmed root cause on insufficient-evidence cases | 0 |
| Correct abstention on insufficient-evidence cases | >= 90% |

### Special fail conditions

FAIL if the skill:

- confuses downstream symptoms with root cause when evidence contradicts that conclusion;
- recommends a remediation as verified without valid remediation basis;
- ignores an earlier causal event solely because a later error message is more explicit;
- hides uncertainty when two causes remain indistinguishable.

---

# 14. S3 Host Log Forensics PASS/FAIL

## Required held-out case mix

Minimum before promotion review:

- 20 compromised-host cases;
- 10 benign administration/hard-negative cases;
- 10 incomplete-log or telemetry-gap cases;
- both Windows and Linux represented before claiming cross-platform scope; otherwise scope remains platform-limited;
- at least 2 independent enterprise-approved/operator-verified source families.

## Metrics

| Metric | PASS threshold |
|---|---:|
| Forensic timeline event precision | >= 98% |
| Timeline ordering accuracy | >= 95% |
| Artifact-to-finding evidence precision | >= 98% |
| Supported behavior/technique mapping precision | >= 90% |
| Persistence/credential/lateral/evasion claim evidence coverage | 100% |
| Unsupported full-forensic conclusion | 0 |
| Benign administration false compromise confirmation | 0 |
| Correct evidence-gap declaration | >= 95% |

### Special fail conditions

FAIL if the skill:

- claims disk/memory forensic facts from log-only evidence;
- treats log absence as proof an action did not occur when telemetry can be missing;
- claims credential theft from authentication usage alone;
- claims persistence without a supporting artifact/event;
- fails to flag evidence destruction/log clearing when directly present in visible evidence.

---

# 15. Resource and lean-harness criteria

Accuracy does not justify uncontrolled compute.

Record per case:

- model calls;
- input/output tokens when measurable;
- wall-clock duration;
- peak process RAM when measurable;
- evidence objects supplied;
- specialist/context size;
- retry count.

Initial acceptance limits:

```text
normal specialist case: <= 2 model calls
validator retry: <= 1
no model call for deterministic admission/license/hash work
no Internet call during specialist evaluation
```

A more expensive candidate must show a measured quality gain over the simpler baseline.

---

# 16. Harness result states

The harness returns one of:

```text
PASS
FAIL_QUALITY
FAIL_SECURITY
FAIL_EVIDENCE
FAIL_LICENSE
FAIL_PROVENANCE
FAIL_RESOURCE
HARNESS_INVALID
NOT_ENOUGH_CASES
```

There is no `PASS_WITH_WARNING` for promotion.

---

# 17. Evidence receipt

Every evaluation receipt must record:

```text
repository
exact_head_sha
specialist_id
blueprint_sha256
harness_spec_sha256
corpus_manifest_sha256
case_count by class/source
model/runtime identity
all metric numerators/denominators
absolute-gate results
resource measurements
final verdict
failed gate IDs
created_at
```

Aggregate percentages without numerators/denominators are insufficient evidence.

---

# 18. Development gates

## G0 — Contract Freeze

PASS when:

- this specification exists and is reviewed;
- machine-readable evaluation profile exists;
- three specialist blueprints exist independently;
- source/license curriculum is explicit;
- pass/fail thresholds are fixed before implementation.

FAIL if implementation changes thresholds to make an existing candidate pass without an explicit reviewed contract revision.

## G1 — Extractor Correctness

Implement only after G0.

Required:

- deterministic adapters for first approved corpora;
- bounded incident segmentation;
- evidence IDs/hashes/provenance;
- hidden truth separation;
- staging cleanup.

PASS requires deterministic fixture tests and zero absolute-gate violations.

## G2 — Specialist Baseline

Create the simplest evidence-first specialist implementation per blueprint.

Prefer reviewed procedure + deterministic retrieval before fine-tuning.

PASS requires schema/evidence/security gates plus baseline quality evidence.

## G3 — Held-out / Hard-negative Evaluation

Freeze a holdout manifest before candidate execution.

PASS requires all specialist-specific thresholds and all shared absolute gates.

## G4 — Skill Promotion Review

Only after G3 PASS.

Required:

- independent content/security review;
- compact instruction-only skill artifact;
- no raw log storage in skill;
- reviewed SHA-256 in approved skill registry;
- existing WorkSpace authority boundary preserved.

## G5 — Multi-skill Coordinator

Deferred until required specialist set reaches G4.

Coordinator must preserve disagreement and uncertainty rather than force consensus.

---

# 19. Coding start rule

The next code task SHALL NOT begin with model training.

The first implementation target after G0 is:

```text
V3-01 CORPUS MANIFEST + HIDDEN-TRUTH HARNESS FIXTURES
V3-02 CIC/LANL/BOTS bounded adapters
V3-03 incident slicer + evidence-reference builder
V3-04 deterministic harness validator/scorer
V3-05 staging deletion + provenance receipt
```

Only after these are green do specialist inference/distillation tasks begin.

---

# 20. Definition of done

A specialist is not "done" because it can produce a plausible report.

It is done only when an exact repository candidate demonstrates:

```text
SECURITY GATES          PASS
LICENSE GATES           PASS
EVIDENCE INTEGRITY      PASS
PROVENANCE              PASS
HELD-OUT QUALITY        PASS
HARD NEGATIVES          PASS
UNCERTAINTY BEHAVIOR    PASS
RESOURCE LIMITS         PASS
INDEPENDENT REVIEW      PASS
```

The system must be rewarded for saying **"insufficient evidence"** when that is the technically correct answer.
