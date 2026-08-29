# WorkSpace D5 Structural Context Map v1

## Purpose

D5-01 makes the context path observably structural-first without changing the existing deterministic lexical ranking or evidence output.

The execution order is:

```text
TaskContract validation
→ zero-budget deterministic short circuit
→ metadata-only knowledge map
→ bounded structural receipt
→ body search using the exact cached map
→ deterministic lexical ranking
→ exact duplicate removal
→ TaskContract hard pack
```

The structural receipt is control-plane metadata. It is not model context and it does not grant source, network, file or tool authority.

## No unbenchmarked recall shortcut

The first-view receipt is bounded to at most 64 map entries, but the full already-read metadata map is handed to the unchanged `LocalKnowledgeIndex.search()` implementation through a cached-map view.

Therefore D5-01 does **not** pre-filter source bodies by title or metadata and does not change retrieval recall/ranking semantics merely to save reads.

Progressive/targeted body expansion remains D5-05 and must be measured before it is allowed to skip candidate sources.

## Retrieval trace

`PackedContext.to_dict()` includes a metadata-only `retrieval_trace` with schema:

```text
workspace-context-retrieval-trace/v1
```

It records:

- whether structural map occurred before body retrieval;
- map entry count and bounded preview count;
- preview bundle/risk counts;
- deterministic ranking strategy identifier;
- exact-dedup strategy identifier;
- ranked candidate count;
- duplicate count;
- accepted hit count;
- hard-budget invariant;
- critical provenance-header truncation invariant;
- whether progressive expansion is active.

The structural preview itself does not emit titles, URLs or body text.

## Zero-work path

When `TaskContract.context_budget.max_retrieved_tokens == 0`, Context Engine returns before reading the knowledge map or any body chunk. This provides an explicit deterministic-before-retrieval short circuit.

## Critical provenance boundary

When a source does not fit, body text may be shortened conservatively. The evidence/data-boundary header is never partially emitted: it is preserved in full or that source is skipped.

The final packed output is deterministically re-counted. Exceeding the TaskContract retrieval budget is a programming error and fails closed.

## Scope of completion

D5-01 is complete with this structural-first trace. The following remain distinct work:

- D5-02: near-duplicate/diversity policy beyond current deterministic rank + exact dedupe;
- D5-03: prove hard packing across every synthesis/context path, not only Context Engine;
- D5-04: extend critical-span protection to every evidence packing path;
- D5-05: progressive targeted body expansion with verified-quality non-regression.
