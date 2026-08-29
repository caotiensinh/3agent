# WorkSpace D7 Evaluation Lab — Golden + Replay v1

## Scope

This baseline closes the deterministic foundation for D7-01 and D7-02.

It does not claim model-quality evaluation is complete. Instead it creates a versioned, repository-owned golden corpus for control-plane behavior and a replay engine that can run in CI without GPU, model downloads, network access or confidential data.

## Golden corpus

`evaluation/golden_control_plane_v1.json`

Schema:

`workspace-evaluation-corpus/v1`

The corpus pins representative accepted and rejected policy/routing cases including:

- internal small-first general work;
- confidential analysis;
- public allowlisted-web research;
- internal code review;
- public classification;
- confidential deterministic NO_LLM retrieval;
- high-risk human-gated analysis;
- rejected confidential public-web authority;
- rejected NO_LLM tool expansion.

Each case contains only deterministic policy inputs and expected compact control-plane outputs. It contains no confidential business material.

## Replay engine

`workspace-eval` replays every case through the production:

`TaskContractCompiler -> DeterministicRoutePlanner`

and checks versioned golden expectations for relevant fields such as:

- accept/reject outcome;
- network scope;
- allowed tools;
- required validators;
- evidence requirement;
- MODEL vs NO_LLM route;
- route reason code;
- initial/max model tier;
- escalation authority;
- retry/escalation hard limits.

A mismatch fails closed.

## Lineage

Every replay requires an exact 40-hex Git `source_ref`. The replay output records:

- corpus ID;
- canonical corpus SHA-256;
- exact source ref;
- case count;
- pass/fail counts;
- per-case mismatch keys and deterministic actual projection.

This makes replay evidence comparable across candidate SHAs without copying prompts, evidence bodies or model output.

## Operator command

```bash
workspace-eval \
  --corpus evaluation/golden_control_plane_v1.json \
  --source-ref <exact-40-hex-sha> \
  --output evaluation-replay.json
```

Exit code is non-zero if corpus validation fails or any golden expectation regresses.

## Security properties

- no model invocation;
- no Internet access;
- no execution gateway;
- no task database mutation;
- no credentials;
- no raw confidential content;
- rejected authority requests are first-class golden outcomes;
- exact corpus hash and Git lineage are preserved.

## Remaining D7 work

This is the deterministic D7 foundation. Remaining work still includes richer regression/adversarial/model-quality corpora, edge/large-context and concurrency corpora, explicit metric-version registry, holdout discipline, and a promotion pipeline that combines these results with verified benchmark evidence.
