# WorkSpace D5 Hard Evidence Packing v2

## Purpose

D5-03/D5-04 close two deterministic correctness gaps in the Research synthesis evidence packer:

1. the hard context budget must cover the **entire rendered evidence string**, including inter-source separators;
2. provenance/data-boundary headers are critical spans and must never be partially truncated.

No model decides these behaviors.

## Hard-pack invariant

For every call to `pack_evidence_sources()`:

```text
len(rendered_evidence) <= policy.budget_chars
```

The final rendered length is checked again after packing. Any programming path that exceeds the configured budget fails closed with `EVIDENCE_HARD_PACK_BUDGET_EXCEEDED`.

The historical implementation budgeted source blocks before joining them with `\n---\n`, which meant separators could push the final output beyond the configured limit. v2 charges separators to the same budget.

## Critical provenance spans

A source block begins with:

```text
[SOURCE_ID]
TITLE: ...
URL: ...
TEXT:
```

This header defines provenance and the evidence/data boundary. It is atomic:

- if the complete header plus at least one evidence character fits, the body may be truncated to the remaining budget;
- if that minimum does not fit, the source is skipped;
- a partial header is never emitted.

This protects source IDs, citations/provenance and the `TEXT:` boundary from truncation ambiguity.

## Compatibility

When the budget is comfortably large enough for all sources, the rendered output remains byte-compatible with the historical format, including trailing newlines and `\n---\n` separators.

The behavior changes only at the budget boundary where the previous packer could exceed the budget or cut a provenance header.

The receipt wire schema remains `workspace-evidence-packing-receipt/v1` because the authoritative source-level fields consumed by existing D3 metrics are unchanged. The receipt now also identifies the deterministic algorithm as:

```text
workspace-evidence-hard-pack/v2
```

and adds metadata-only invariants such as:

- `separator_chars`;
- `hard_budget_respected`;
- `critical_provenance_header_truncated`;
- `sources_skipped_for_header_budget`;
- per-source `provenance_header_preserved` and `skip_reason`.

No raw source title, URL or evidence body is copied into the receipt.

## Security / privacy

This change adds no network, file, tool, cache or model authority.

Receipts remain metadata-only. Raw prompts, model responses, evidence bodies, credentials and confidential business content are not logged by the packer.

## D5 relationship

After this item:

- D5-03 hard context packing is complete for the authoritative Research synthesis packer and Context Engine paths;
- D5-04 critical provenance-span protection is enforced in both paths;
- D5-02 near-duplicate/diversity semantics remain separate because removing corroborating sources can affect verified quality;
- D5-05 progressive body expansion remains benchmark-gated because skipping candidate bodies can affect recall.
