# WorkSpace D7-07 Metric Version Registry v1

## Purpose

Optimization evidence is invalid when two snapshots use the same metric name but different formulas or semantics. D7-07 binds every production D3 core metric to an explicit versioned definition and canonical registry fingerprint.

## Registry

Schema:

`workspace-metric-registry/v1`

Registry ID:

`workspace-d3-core-metrics-v1`

Definitions cover D3-01 through D3-07 and pin:

- stable metric ID;
- human-readable name;
- metric semantic version;
- unified-snapshot output path;
- source metric schema;
- concise formula/semantic contract.

The canonical registry SHA-256 changes whenever any definition changes.

## Snapshot binding

Every newly generated `workspace-unified-metrics/v1` snapshot contains:

- `metric_registry` with its canonical hash;
- the existing `metric_map`, now projected from the same registry.

No D3 metric formula is changed by this work.

## Benchmark lineage

New benchmark manifests copy the metric-registry SHA-256 into lineage in addition to the full metrics payload hash. Validation fails closed if a manifest claims a registry fingerprint that does not match the embedded metrics registry.

Legacy `workspace-unified-metrics/v1` and benchmark snapshots created before D7-07 remain readable when they contain no registry. They cannot claim a D7-07 registry fingerprint retroactively.

## Change discipline

A future semantic/formula change must:

1. update the affected metric version;
2. update its semantic definition;
3. produce a different registry SHA-256;
4. regenerate evaluation/benchmark evidence under the new registry;
5. never compare old/new metric values as if their definitions were identical without an explicit migration analysis.

## Security/privacy

The registry contains metric definitions only. It stores no task prompts, responses, evidence bodies, credentials, URLs, commands or confidential business data. It grants no model/tool/network/write authority.
