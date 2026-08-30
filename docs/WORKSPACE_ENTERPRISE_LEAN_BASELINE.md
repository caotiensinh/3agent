# WorkSpace Enterprise Lean Baseline v1

## Status

This is the default engineering baseline for WorkSpace internal-enterprise features.

It is a control-alignment profile, not a certification claim. WorkSpace does not claim ISO, SOC 2, or other certification without an independent organizational audit.

## Product default

WorkSpace defaults to **E2 — Enterprise Confidential / Lean**.

The target is not maximum model size, maximum context, or maximum GPU utilization. The target is the highest verified useful work per unit of constrained infrastructure while preserving hard security boundaries.

```text
avoid
> reuse
> precompute
> compact
> deterministic code
> parallelize independent I/O
> accelerate
> scale model
> scale hardware
```

A feature that needs larger hardware only because its harness wastes context, retries, or duplicate work is not optimized.

## Control references

WorkSpace engineering controls are mapped where relevant to:

- ISO/IEC 42001 — AI management-system governance;
- ISO/IEC 27001 — information-security management;
- NIST AI RMF and the Generative AI Profile — AI risk and trustworthiness;
- NIST Cybersecurity Framework 2.0 — Govern, Identify, Protect, Detect, Respond, Recover;
- NIST SSDF SP 800-218 — secure software development;
- OWASP GenAI/LLM risk guidance — model/application-specific abuse classes;
- SLSA — source/build provenance and supply-chain integrity.

These references guide engineering controls. They do not replace deployment-specific legal, privacy, contractual, or certification requirements.

## Enterprise tiers

| Tier | Intended use | Minimum posture |
| --- | --- | --- |
| E0 | disposable experiment | public/synthetic data, isolated, no production authority |
| E1 | normal internal | authentication, scoped access, audit metadata, tests, rollback |
| E2 | confidential enterprise default | local inference, data boundary, least privilege, default-deny egress, provenance, validators, recovery |
| E3 | high assurance | independent review, stronger approvals, signed/frozen evidence where applicable, stricter change/release gates |

A higher tier adds assurance. It must not automatically mean a larger model or more model calls.

## Hard invariants

The following are not optimization tradeoffs:

- confidential egress violation: `0`;
- successful unauthorized capability use: `0`;
- raw credential/secret exposure to logs: `0`;
- model-controlled authorization: `0`;
- unbounded retry/agent loop: `0`;
- evidence-free mandatory PASS: `0`.

Security may cost CPU cycles, but security policy should first remove dangerous capability rather than add expensive inspection after the fact.

## Weak-hardware-first acceptance rule

For every new feature, evaluate in this order:

1. Can deterministic code solve it with acceptable quality?
2. Can an existing artifact/cache/result be reused safely?
3. Can input be reduced before inference?
4. Can a smaller model solve the verified task?
5. Can independent I/O or CPU work be parallelized without increasing model memory?
6. Only then consider a larger context, larger model, dual GPU, additional service, or new framework.

The burden of proof is on the more expensive design.

## Resource metrics

Every optimization must preserve the same task scope and verified-quality gate.

Primary metrics:

```text
Verified Task Success Rate
First-Pass Verified Success Rate
Tokens per Verified Task
GPU Seconds per Verified Task
Time to Verified Result
Peak VRAM / RAM
Model Calls per Verified Task
Tool Calls per Verified Task
Retry Tokens / Total Tokens
Context Retention / Utilization
Cache Hit Value
```

A cheaper result that fails mandatory evidence/security gates is not an optimization.

## Skill prompt budget

Instruction skills are compact procedures, not knowledge storage.

Hard v1 limits:

```text
max skill file              3072 bytes
max skills per model load   2
max loaded skill text       4096 bytes
```

Default workflow disclosure is narrower still:

```text
Research      research-web-trust only
Presentation  no default skill body
Daily Report  no default skill body
```

Presentation and Daily Report evidence rules are already encoded in deterministic code and explicit stage prompts. Repeating the same instructions as skill bodies would increase prompt/prefill cost without adding authority.

Research retains the public-web trust boundary because raw public source text enters model context and must remain explicitly lower-trust data.

Other approved skills are progressively disclosed only when a task/stage has a measured need.

## Feature Definition of Done

An enterprise feature is complete only when applicable gates pass:

```text
functional behavior
security boundary
data handling
deterministic validation
failure/timeout bounds
rollback or safe failure
audit metadata
provenance
resource budget
regression tests
```

Do not add a gate that has no material risk or acceptance value. Enterprise rigor is not process accumulation.

## Dependency admission

A new package, model server, daemon, database, vector store, agent framework, or external service is rejected by default unless benchmark evidence shows that:

```text
MeasuredBenefit > Complexity + ResourceCost + SecurityRisk + OperationalBurden
```

and verified quality/security do not regress.

The preferred dependency is the one already installed and adequate. The preferred service is no new service.

## Skill admission

Public skill reputation is not trust. External material must be pinned and reviewed for provenance, license, prompt control, executable behavior, network, credentials, persistence, telemetry, destructive actions, and dependency risk.

WorkSpace prefers concept extraction plus project-owned instruction-only implementation.

## Review triggers

Re-review this baseline when any of these change materially:

- confidential/public trust-zone architecture;
- model authority or external model support;
- egress/broker behavior;
- skill execution policy;
- credential handling;
- logging/telemetry;
- cache sharing across trust domains;
- default model/context/GPU strategy;
- enterprise target workload or hardware class.
