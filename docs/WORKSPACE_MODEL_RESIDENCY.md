# WorkSpace On-Demand Model Residency

Status: implementation baseline  
Scope: local model lifecycle, VRAM residency, resource reclaim  
Security posture: local-only, deployment-provisioned, runtime-download forbidden

## 1. Decision

WorkSpace MUST NOT preload the complete AI model pack into VRAM.

Model files are provisioned to local disk during reviewed deployment. Runtime model residency is demand-driven:

```text
approved deployment manifest
        |
        v
local model disk/cache
        |
        | capability actually requests model
        v
resource admission
        |
        v
load/use model in VRAM
        |
        v
release active lease
        |
        +---- reuse while useful
        |
        +---- TTL/LRU unload when idle
        |
        +---- earlier LRU reclaim under VRAM/RAM pressure
```

A model existing on disk is not the same as a model being resident in VRAM.

## 2. PicoLM-derived operating rule

WorkSpace applies the constraint-first optimization ladder to model execution:

```text
avoid > reuse > precompute > compact > parallelize > accelerate > add hardware
```

For model residency this means:

1. **Avoid** loading a model when no capability needs it.
2. **Reuse** an already-resident model instead of unloading/reloading it between adjacent requests.
3. **Precompute** deterministic retrieval, parsing, correlation and cached evidence before invoking a larger model.
4. **Compact** context and evidence so the smallest sufficient model can be selected.
5. **Parallelize** only independent work that fits the resource budget.
6. **Accelerate** with GPU scheduling only after unnecessary work has been removed.
7. **Add hardware** only when measured workload cannot meet requirements after the earlier steps.

The model router therefore optimizes useful work, not resident-model count.

## 3. Hard invariants

Production rules:

- no `preload_all` mode;
- no fixed number of resident models;
- no runtime model download;
- no model identifier may come from user/file/web/model output;
- active model leases are never eviction candidates;
- resource admission remains authoritative;
- VRAM/RAM pressure may reclaim only inactive models;
- pressure reclaim uses deterministic LRU order;
- normal idle cleanup requires TTL expiration;
- resource reclaim receives one bounded retry only;
- thermal, power and busy-GPU failures do not trigger memory eviction;
- model weights remain outside the Git repository;
- deployment and runtime authority remain separate.

## 4. Lifecycle states

A model can conceptually be in these states:

```text
PROVISIONED_ON_DISK
      |
      | first approved capability request
      v
ACTIVE_LEASE
      |
      v
RESIDENT_REUSABLE
      |
      +---- request -> ACTIVE_LEASE
      |
      +---- idle TTL -> EVICTED_TO_DISK
      |
      +---- memory pressure + inactive -> EVICTED_TO_DISK
```

There is deliberately no `REMOTE_DOWNLOAD` runtime state.

## 5. Demand loading

`ModelResidencyManager.acquire()` does **not** load a model. It records a lease and observes whether the model is already resident.

The normal local inference transport is the only operation that causes an already-provisioned model to be materialized by the local backend. For Ollama this is the `/api/generate` request.

Consequences:

- no speculative loading;
- no startup VRAM flood;
- no separate loader thread;
- no autonomous model discovery;
- the capability request itself is the demand signal.

## 6. Reuse

A resident model stays available for a short bounded period so adjacent workflow stages can reuse it without paying load latency repeatedly.

The secure profile currently uses:

```json
{
  "keep_alive": "2m",
  "residency": {
    "enabled": true,
    "strategy": "on_demand",
    "idle_ttl_seconds": 120,
    "eviction_policy": "idle_lru",
    "runtime_download": false
  }
}
```

The TTL is a reuse window, not a guarantee that a model will remain resident for that entire time. Memory pressure can reclaim an inactive model earlier.

## 7. Lease and eviction safety

Every managed inference obtains a model lease before execution and releases it after execution.

The manager tracks in-process reference counts. On high-assurance Linux deployments it also uses shared/exclusive `flock` leases:

- inference holds a shared lease lock;
- eviction must obtain an exclusive non-blocking lock;
- if another process still uses that model, exclusive acquisition fails and eviction skips it;
- kernel file locks are released automatically if a process exits.

This avoids relying only on stale in-memory reference counts.

## 8. Idle eviction

Normal eviction is TTL + LRU:

```text
resident models
    -> remove excluded/current model
    -> remove active leased models
    -> remove models younger than idle TTL
    -> sort by last-used timestamp
    -> deterministic model-name tie break
    -> unload oldest first
```

Unknown externally resident models are observed before becoming an eviction candidate. This prevents a new WorkSpace process from immediately unloading pre-existing local model state it has not yet classified.

## 9. Pressure eviction

The inference wrapper keeps existing resource admission authoritative.

If admission fails specifically because projected **VRAM or RAM** exceeds budget:

```text
admission denied for memory
        |
        v
find inactive resident models
        |
        v
LRU reclaim
        |
        v
retry admission/inference ONCE
```

A second failure is returned as authoritative.

No reclaim/retry occurs for:

- GPU temperature failure;
- GPU power failure;
- temporary busy GPU timeout;
- malformed model metadata;
- unrelated local inference errors.

This avoids converting a real safety signal into an eviction loop.

## 10. Current integration

The default secure single-endpoint Ollama path is integrated through:

- `src/three_agent/model_residency.py`
- `src/three_agent/orchestrator.py`
- `src/three_agent/config.py`
- `config/workspace.secure.json`

The existing `ResourceBudgetManager` still decides whether a model may start. Residency management only reduces avoidable resident memory before a bounded retry.

The worker-pool path remains a separate integration boundary because each GPU-affined Ollama endpoint requires its own residency manager and lock scope. It must not be declared complete until its routing tests cover per-worker eviction.

## 11. Hugging Face model adapters

Future Hugging Face backends must implement the same lifecycle contract rather than adding their own uncontrolled cache policy.

Examples:

- Qwen3 Embedding: load local snapshot only when retrieval requires embedding;
- Qwen3 Reranker: load only when candidate reranking is required;
- Chronos-2: load only when a monitoring forecast is requested;
- security specialist model: load only for a routed specialist analysis.

Required backend behavior:

```text
load_from_local_snapshot_only()
is_resident()
unload()
```

Runtime adapters MUST use local files only and MUST NOT call Hugging Face Hub to repair a missing model. A missing local model is a deployment/provisioning failure.

## 12. Deployment boundary

Deployment is allowed to obtain reviewed model artifacts. Runtime is not.

Deployment responsibilities:

1. read approved model manifest;
2. resolve exact approved revision;
3. download into staging;
4. verify provenance/integrity/license policy;
5. promote to local model store;
6. run smoke/benchmark gates;
7. write deployment receipt;
8. enable runtime offline mode.

Runtime responsibilities:

1. select an already-approved role/model mapping;
2. prove resources are available;
3. acquire a residency lease;
4. invoke the local backend;
5. release lease;
6. reuse or evict according to policy.

Runtime must never convert a missing model into permission to access the Internet.

## 13. Metrics

The residency snapshot exposes at least:

- acquisitions;
- reuse hits;
- evictions;
- active leases;
- idle TTL;
- eviction policy;
- runtime-download state;
- fixed-model-count flag.

These support later measurements such as:

```text
reuse_rate = reuse_hits / acquisitions
load_latency_p50/p95
model_evictions_per_hour
VRAM_before / VRAM_after
resource_denials_before / after reclaim
```

Optimization claims are not accepted without these measurements.

## 14. Acceptance criteria

The default secure path is ready only when automated tests prove:

- acquiring a lease does not load/download a model;
- already-resident models are reused;
- idle models expire after TTL;
- active leases cannot be evicted;
- cross-process active evidence can block eviction;
- LRU ordering is deterministic;
- memory pressure can reclaim inactive models and retry once;
- non-memory resource failures do not cause eviction;
- runtime download configuration is rejected;
- no fixed resident-model count is introduced;
- existing resource-admission tests remain green;
- canonical-module and security CI remain green.

## 15. Next implementation boundary

After the default Ollama path passes CI:

1. add per-worker residency managers to `OllamaWorkerPool`;
2. add the approved Hugging Face model manifest/provisioner;
3. implement local-only embedding/reranker/Chronos backend adapters;
4. benchmark load/reuse/eviction behavior on the dual-RTX5090 host;
5. tune TTL from measured workload rather than intuition.
