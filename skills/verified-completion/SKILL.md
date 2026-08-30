---
name: verified-completion
description: Decide PASS, BLOCK, or UNKNOWN from exact-candidate evidence and mandatory validators without accepting model confidence as proof.
license: Project-internal
---

# Verified Completion

Use before declaring non-trivial work complete.

- Reconstruct required gates from the task or change contract.
- Bind evidence to the exact candidate, artifact, configuration, or source fingerprint when available.
- Prefer deterministic rule, schema/parser, build/type check, focused test, integration test, then authoritative external evidence.
- Reject stale or mismatched evidence rather than inheriting PASS.
- A model review may support analysis but never replaces a stronger available validator.
- Return PASS only when every mandatory gate passes; otherwise return BLOCK with failed/missing gates or UNKNOWN when evidence cannot decide.
