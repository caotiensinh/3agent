# Held-out Lane 4 — Same-Benchmark Regression Policy v0.1

## Goal

Compare one exact production baseline run and one exact revision run over the same
held-out benchmark without executing a model or granting promotion authority.

## Required equality before comparison

The comparator fails closed unless baseline and revision bind:

- the same benchmark ID and benchmark SHA-256;
- the exact same case-ID set;
- the same case SHA-256 for every case;
- the same executor SHA-256 for every matched case.

Each benchmark run also requires every outcome subject SHA-256 to equal the run's
subject SHA-256. Duplicate case IDs/hashes are rejected.

## Classification

Each matched case is classified deterministically as one of:

- regression: baseline PASS -> revision FAIL;
- improvement: baseline FAIL -> revision PASS;
- unchanged pass;
- unchanged fail.

## Strict release policy

`strict_release_passed=true` only when:

1. regression count is zero; and
2. the revision passes every held-out case.

This deliberately prevents a revision from being accepted merely because it is
"not worse" while still failing held-out cases.

## Output

The metadata-only comparison contains run/subject/benchmark hashes, bounded counts,
regressed/improved case IDs, deterministic reason codes and a content-addressed
`comparison_sha256`.

## Authority boundary

Evaluation decision only. No model/tool execution, staging, approval, promotion,
materialization, supersession, rollback, network, credential or deployment authority
is introduced.
