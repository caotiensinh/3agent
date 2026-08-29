# Benchmark Readiness Receipt v1

WorkSpace fixed-task RTX5090 benchmark execution now creates one metadata-only environment receipt before the benchmark begins.

Schema:

`workspace-benchmark-readiness/v1`

Command:

```bash
workspace-benchmark-readiness \
  --source-ref <exact-40-hex-sha> \
  --repo-root . \
  --model qwen3:30b \
  --output /path/to/environment.json
```

## Purpose

The benchmark suite already verifies fixed tasks, isolated variant state, exact Git lineage, local-only policy and verified-quality acceptance. The readiness receipt closes a different evidence gap: the GitHub Actions log previously checked GPU/model availability but did not publish a normalized artifact describing the hardware/runtime used for the benchmark.

The receipt records only:

- exact benchmark source SHA;
- capture time;
- readiness checks and compact failure reason codes;
- GPU count;
- count of GPUs whose name contains `RTX 5090`;
- GPU product names, driver versions and total VRAM MiB;
- Ollama version;
- requested local model ID and whether it is already installed;
- canonical environment and receipt SHA-256 fingerprints.

It intentionally does **not** record:

- hostname;
- username;
- IP address;
- GPU UUID or serial number;
- raw `ollama show` output;
- prompt, response, evidence or business data.

## Fail-closed readiness rules

The current fixed hardware benchmark requires all of the following:

1. checkout `HEAD` equals the exact requested `source_ref`;
2. tracked Git worktree is clean;
3. `nvidia-smi` is available and returns valid rows;
4. at least two visible GPUs have names containing `RTX 5090`;
5. the matching RTX5090 GPUs use one driver version;
6. Ollama is available;
7. the requested model is already installed locally.

The readiness command does not install, pull, upgrade or repair anything. A failed condition returns a non-zero exit code, so the benchmark workflow stops before model execution.

## Fingerprint semantics

`environment_sha256` covers only the normalized hardware/runtime environment object. It deliberately excludes capture time and Git source SHA so two benchmark runs on the same hardware/runtime can be compared directly.

`receipt_sha256` covers the entire receipt except the receipt hash itself, including source SHA and capture time. Tampering therefore invalidates the receipt.

## Workflow artifact boundary

`.github/workflows/benchmark-context-packing.yml` publishes `environment.json` in the same metadata-only artifact as:

- `suite.json`;
- each variant `benchmark.json`;
- each variant `isolation.json`.

This receipt improves reproducibility evidence. It does **not** make an unexecuted benchmark PASS, does not authorize 40k/32k context promotion and does not replace D7-05/D7-06 representative evidence requirements.
