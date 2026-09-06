# Qwen3 Embedding Candidate Audit and Runtime Acceptance

Status: candidate evidence + gated runtime acceptance workflow  
Approval state: **NOT APPROVED**  
Runtime authority: **NONE until admitted to `config/models.approved.json` after review**

## Candidate identity

| Field | Candidate value |
| --- | --- |
| WorkSpace candidate id | `qwen3-embedding-0.6b` |
| Provider | Hugging Face |
| Repository | `Qwen/Qwen3-Embedding-0.6B` |
| Exact revision | `97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3` |
| Declared upstream license | `apache-2.0` |
| Intended capability | `retrieval.embedding` |
| Intended local subdir | `qwen3-embedding-0.6b` |

The revision above is immutable input to the audit. `main`, `latest`, mutable branches and tags are not accepted by the auditor.

## Why candidate evidence is separate from approval

Downloading a file and calculating a hash proves what bytes were inspected. It does **not** prove that:

- the upstream license has been reviewed for the target deployment;
- the selected artifact set is sufficient for fully offline runtime loading;
- the model meets WorkSpace quality, latency, memory and security acceptance criteria;
- the model should be enabled for any task route;
- the model should replace deterministic retrieval.

For that reason `scripts/audit_hf_model_candidate.py` always emits candidate-only evidence and `scripts/accept_hf_model_candidate.py` always emits a non-authoritative acceptance receipt. Neither script edits the approved model manifest.

```json
{
  "status": "candidate_only",
  "approval": {
    "approved": false
  }
}
```

A runtime acceptance PASS is evidence for a later admission decision; it is not the admission decision itself.

## Candidate artifact set

The explicit candidate allowlist is:

```text
config/model-candidates/qwen3-embedding-0.6b.artifacts.txt
```

It contains the model, tokenizer and Sentence Transformers configuration files observed for this candidate. README and repository metadata are intentionally excluded from the runtime candidate set.

The source record also pins the known large-file SHA-256 anchor for `model.safetensors`. A real acceptance run must regenerate evidence from the exact immutable revision and compare the regenerated evidence against every pinned source anchor before offline loading begins.

## Produce candidate evidence only

Install only the deployment/review dependency:

```bash
python -m pip install -e '.[model-provisioning]'
```

Run the audit with the exact revision:

```bash
python scripts/audit_hf_model_candidate.py \
  --repo-id Qwen/Qwen3-Embedding-0.6B \
  --revision 97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3 \
  --artifact-file config/model-candidates/qwen3-embedding-0.6b.artifacts.txt \
  --output qwen3-embedding-0.6b.candidate-evidence.json
```

The default audit path:

1. requires an exact 40-character revision;
2. downloads only the explicit artifact allowlist into generated staging;
3. removes Hugging Face local download metadata;
4. rejects symlinks and unrequested/missing regular files;
5. calculates SHA-256 and exact byte size for each candidate artifact;
6. writes candidate evidence only;
7. deletes staging automatically.

For a gated/private reviewed candidate, a token may be supplied through `HF_TOKEN`. The token is never included in evidence output.

## Retain the already-audited bytes for acceptance

A separate review/acceptance process may avoid downloading the same model twice by explicitly adding:

```bash
--snapshot-output /path/to/non-existing/verified-snapshot
```

Retention is fail closed:

- the destination must not already exist;
- only the exact audited regular-file set is copied;
- symlinks remain forbidden;
- the retained copy is rechecked against the just-produced SHA-256 and byte-size evidence;
- normal audit behavior remains temporary when `--snapshot-output` is absent.

The retained directory is review staging, not the production model store and not runtime download authority.

## Runtime acceptance runner

`scripts/accept_hf_model_candidate.py` consumes candidate evidence plus the retained local snapshot. It:

- requires `candidate_only`, `runtime_download=false`, and `approval.approved=false` evidence;
- rechecks exact artifact paths, byte sizes and SHA-256 before model loading;
- loads through `LocalEmbeddingAdapter` with `local_files_only=True` and `trust_remote_code=False`;
- forces `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`, and telemetry disabled;
- validates query/document vector row count, dimensions, finite values and normalization;
- exercises residency eviction and reload;
- blocks Python socket connection attempts during load/inference;
- emits `workspace.model-candidate-acceptance/v1` with `approval.approved=false`.

## Gated real Qwen3 acceptance workflow

The manual workflow is:

```text
.github/workflows/qwen3-embedding-runtime-acceptance.yml
```

It is intentionally `workflow_dispatch` only. It is not triggered by pull requests or normal pushes because the candidate is approximately 1.2 GB and real model acceptance is a deliberate review operation.

The workflow executes this boundary:

```text
immutable candidate source
  -> download exact allowlist once
  -> audit exact files + SHA-256 + size
  -> compare regenerated evidence with pinned source anchors
  -> retain the verified snapshot
  -> remove OS network egress with a Linux network namespace
  -> run LocalEmbeddingAdapter load/inference/evict/reload
  -> validate non-authoritative acceptance receipt
  -> delete model bytes and local model caches
  -> upload JSON evidence/receipt only
```

Before downloading the model, the workflow proves that the hosted runner can create a network namespace containing no external interface. If that isolation prerequisite is unavailable, the workflow fails before the expensive model download.

The workflow artifact must contain only:

```text
qwen3-embedding-candidate-evidence.json
qwen3-embedding-runtime-acceptance.json
```

Model weights and the retained snapshot are deleted and must never be uploaded as GitHub Actions artifacts.

## Required review before production admission

Production admission still requires all of these gates:

- exact source revision verified;
- upstream license reviewed for the intended deployment and distribution model;
- every runtime file has SHA-256 + size evidence;
- real offline Sentence Transformers load passes;
- query/document embedding smoke tests pass;
- embedding dimensions and normalization contract pass;
- no network activity occurs during runtime load/inference;
- deterministic retrieval remains available as fallback/provenance lane;
- production acceptance benchmark meets defined retrieval-quality thresholds;
- production latency and RAM/VRAM limits are measured on representative hardware;
- GPU residency/unload behavior is verified on the intended accelerator environment;
- explicit human review approves admission.

A CPU-hosted runtime acceptance PASS closes the offline-load/runtime-contract gate. It does **not** prove GPU VRAM performance or production retrieval quality.

## Admission boundary

Only after the real acceptance receipt, production benchmark, license review and explicit human approval may a separate admission change add `qwen3-embedding-0.6b` to `config/models.approved.json`.

The admission change must preserve:

```text
GitHub: scripts + manifests + schemas + tests + evidence metadata
Deployment: exact approved revision download + integrity verification
Runtime: offline local resolver + on-demand residency
GitHub repository: no model weights
```

Until that separate admission is reviewed and merged, this Qwen3 model remains a candidate with zero production runtime authority.
