# D4 Representative Reuse Closure — 2026-08-30

## Exact evidence boundary

WorkSpace attempted the D4 representative real-workload reuse measurement against exact source:

`0cf95cfc0126856b932414967a61ec0e0af5722e`

Execution evidence:

- GitHub Actions run: `33268295997` — PASS;
- job: `99142156477`;
- artifact: `9719314497`;
- artifact ZIP SHA-256: `sha256:d71900821df80d094050119fbd55f404148a2cf1fd586af09c7d1e2291b19fba`;
- runner class: self-hosted Linux x64 with two RTX 5090 GPUs;
- source observation receipt SHA-256: `sha256:e192a0ccc764e069abc2b05ea2a94f0097a4968ce5bde7e1c53a8090405639a1`.

The durable repository receipt is:

`evaluation/d4_representative_closure_20260830.json`

## Result

The D4 observer searched only expected WorkSpace metadata telemetry locations and did not find a readable real-workload inference telemetry file.

The deterministic report therefore returned:

- telemetry discovery: `not-found`;
- eligible events in the seven-day window: `0`;
- required minimum events: `20`;
- reuse opportunity rate: `0.0`;
- prompt-eval duration share: unavailable;
- decision: `INSUFFICIENT_REPRESENTATIVE_DATA`;
- allowed action: `collect_more_metadata`;
- production serving change authorized: `false`;
- backend cache hit claimed: `false`.

This is a valid evidence result. Missing representative workload data must not be replaced with benchmark traffic or synthetic tasks and then mislabeled as real workload.

## Runtime telemetry path verification

The WorkSpace orchestrator already resolves inference telemetry to:

`WORKSPACE_INFERENCE_TELEMETRY`

when explicitly configured, otherwise to:

`<artifact_root>/activity/inference.jsonl`

and installs that value into the process environment before model clients are constructed. Inference telemetry remains metadata-only. Therefore this closure did not identify a product telemetry wiring defect; it identified absence of representative live workload observations on the measured host.

## D9 decision

D9 serving/cache benchmark eligibility is **not established**.

Current decision:

`D9_SERVING_CACHE_BENCHMARK = NOT_ELIGIBLE`

Do not start a vLLM/SGLang/LMCache/backend-cache comparison from this evidence. First collect normal WorkSpace production-like workload metadata until the reviewed D4 minimum is met, then rerun `workspace reuse-report`.

Even a future `SERVING_CACHE_BENCHMARK_ELIGIBLE` result would authorize only a benchmark, never a production serving migration.

## Privacy boundary

No raw inference telemetry was uploaded or committed. The closure stores only aggregate counts, decision codes, evidence IDs and hashes. It does not store raw prompts, raw responses, prefix hashes, credentials or business content.
