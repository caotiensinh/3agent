# WorkSpace D5-02a Exact Body Duplicate Suppression

## Status

D5-02a is a **benchmark candidate**, not a production-default optimization.

The production-compatible default remains:

```text
WORKSPACE_EVIDENCE_EXACT_BODY_DEDUPE=false
```

No fuzzy matching, embedding similarity, semantic clustering or model judgment is used.

## Problem

Research search already canonicalizes duplicate URLs, but two different URLs can still return the same cleaned evidence body. Sending both complete bodies to synthesis wastes context and can make mirrored content look like independent corroboration.

D5-02a removes only this exact redundancy from the synthesis prompt.

## Deterministic rule

For an already-vetted source body `B`:

```text
sha256(B_utf8)
```

is computed in memory. A later source body is suppressed only when its complete cleaned UTF-8 body has the same SHA-256 as a body that was already supplied **in full** to synthesis.

A truncated, empty or budget-skipped source never establishes a duplicate canonical. This prevents a hard-context boundary from causing every copy of the evidence to disappear.

The comparison is exact. Whitespace changes, different wording, partial overlap and semantically equivalent text are **not** duplicates under D5-02a.

## Provenance behavior

Suppression removes the duplicate body from the rendered synthesis context; it does not erase the source from WorkSpace evidence state.

The source remains present in the authoritative source/assessment metadata. The metadata-only packing receipt records:

- whether exact-body suppression was enabled;
- whether the source body was supplied in full;
- whether the source was suppressed as an exact duplicate;
- the canonical `source_id` that already supplied the identical body;
- aggregate duplicate-body and saved-character counts.

The receipt does **not** contain the source body, title, URL or body SHA-256.

This is deliberate: even a hash of confidential text can reveal equality and can support dictionary-style guessing if persisted outside the privacy boundary.

## Hard-budget interaction

D5-02a does not weaken D5-03/D5-04 invariants:

```text
len(rendered_evidence) <= policy.budget_chars
```

and a provenance/data-boundary header is still either emitted completely with evidence or not emitted at all.

Duplicate detection happens only for already-vetted evidence and grants no network, tool, file, cache or model authority.

## Benchmark lineage

`exact_body_dedupe` is part of `workspace-evidence-packing-policy/v3` and therefore part of the effective benchmark configuration fingerprint.

A baseline with suppression disabled and a candidate with suppression enabled cannot be treated as the same configuration lineage.

## Acceptance rule

D5-02a must not be enabled by default merely because duplicate characters were removed.

Promotion requires the existing fixed-task optimization gate to show, at minimum:

1. no regression in verified task success rate;
2. no regression in first-pass verified success rate;
3. no regression in verified task count;
4. no regression in evidence coverage;
5. measurable token-efficiency benefit under the configured acceptance threshold.

Existing context precision/recall diagnostics are not redefined for this candidate. If suppressing duplicate vetted text lowers the current context-recall proxy, the metric must report that honestly; the implementation must not change the metric definition to manufacture a better result.

If the measured benefit is too small to justify the added branch of logic, the candidate should remain disabled or be removed.

## Out of scope

D5-02a does not implement:

- near-duplicate detection;
- semantic similarity or embeddings;
- diversity/MMR ranking;
- source-authority merging;
- automatic confidence inflation from mirrored sources;
- D5-05 progressive body expansion.

Those behaviors can change recall or corroboration semantics and require separate evidence and benchmarks.
