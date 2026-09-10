# WorkSpace On-Demand Model Residency

Status: implementation baseline  
Scope: local model lifecycle, VRAM residency, resource reclaim  
Security posture: local-only, deployment-provisioned, runtime-download forbidden

## 1. Decision

WorkSpace MUST NOT preload the complete AI model pack into VRAM.

Model artifacts are provisioned to local disk during reviewed deployment. Runtime residency is demand-driven:

```text
approved deployment manifest
        |
        v
local model disk/cache
        |
        | capability actually requests model
        v
select smallest sufficient backend/model
        |
        v
resource admission
        |
        v
ACTIVE LEASE -> local inference -> VRAM residency
        |
        v
release lease
        |
        +---- reuse while useful
        +---- TTL/LRU unload when idle
        +---- earlier LRU reclaim under VRAM/RAM pressure
```

A model existing on disk is not the same as a model being resident in VRAM.

## 2. PicoLM-derived operating rule

WorkSpace applies the constraint-first optimization ladder:

```text
avoid > reuse > precompute > compact > parallelize > accelerate > add hardware
```

Applied to model execution:

1. **Avoid** loading a model when no capability needs it.
2. **Reuse** an already-resident model instead of reloading identical weights.
3. **Precompute** deterministic retrieval, parsing, correlation and cached evidence before model inference.
4. **Compact** context/evidence so the smallest sufficient model can be selected.
5. **Parallelize** only independent work that fits the measured resource budget.
6. **Accelerate** after unnecessary work and data movement are removed.
7. **Add hardware** only after measurements prove the earlier stages are insufficient.

The router optimizes useful work, not resident-model count.

## 3. Hard invariants

Production rules:

- no `preload_all` mode;
- no fixed resident-model count;
- no runtime model download;
- no runtime remote repair of a missing model;
- no model identifier/revision from user, file, web, telemetry or model output;
- active model leases are never eviction candidates;
- Linux processes coordinate eviction with kernel file locks;
- resource admission remains authoritative;
- memory pressure may reclaim only inactive models;
- pressure reclaim uses deterministic LRU order;
- normal idle cleanup requires TTL expiration;
- memory reclaim receives one bounded retry only;
- thermal, power and busy-GPU failures do not trigger memory eviction;
- model weights remain outside the Git repository;
- deployment authority and runtime authority remain separate.

## 4. Lifecycle

```text
PROVISIONED_ON_DISK
      |
      | approved capability needs this model
      v
ACTIVE_LEASE
      |
      | local backend materializes weights
      v
RESIDENT_REUSABLE
      |
      +---- new demand -> ACTIVE_LEASE
      +---- idle TTL -> EVICTED_TO_DISK
      +---- memory pressure + inactive -> EVICTED_TO_DISK
```

There is deliberately no `REMOTE_DOWNLOAD` runtime state.

## 5. Demand loading

`ModelResidencyManager.acquire()` does not load or download a model. It records a lease and observes whether the model is already resident.

The normal local inference request remains the only demand signal that can materialize an already-provisioned model. For Ollama this is the local `/api/generate` request.

Therefore there is:

- no speculative preload;
- no startup VRAM flood;
- no autonomous model discovery;
- no background model loader with network authority.

## 6. Reuse window

The secure profile uses:

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

The TTL is a bounded reuse window, not a guarantee. Memory pressure can reclaim an inactive model earlier.

## 7. Lease safety and cross-process protection

Every managed inference takes a model lease before execution and releases it afterward.

The manager maintains in-process reference counts. On high-assurance Linux deployments it additionally uses shared/exclusive `flock` leases:

- inference holds a shared lock for the model/backend scope;
- eviction must obtain an exclusive non-blocking lock;
- an active process prevents exclusive acquisition;
- eviction therefore skips a model still in use elsewhere;
- kernel locks disappear automatically when a process exits.

Backend URL and model names are hashed for lock filenames; raw model names are not used as filesystem paths.

## 8. Idle eviction

Normal cleanup is TTL + deterministic LRU:

```text
resident models
    -> exclude current model
    -> exclude local active leases
    -> exclude cross-process active leases
    -> exclude models younger than TTL
    -> sort by last-used time, then model name
    -> unload oldest first
```

A resident model not previously observed by the manager is observed first rather than immediately evicted.

## 9. Pressure reclaim

The existing `ResourceBudgetManager` remains authoritative.

If admission fails specifically because projected **VRAM or RAM** exceeds policy:

```text
memory admission denial
        |
        v
find inactive resident models
        |
        v
LRU reclaim
        |
        v
retry exactly once
```

No reclaim/retry occurs for:

- temperature safety failures;
- power safety failures;
- temporary busy-GPU timeouts;
- unrelated inference failures.

A second resource failure is authoritative. There is no unbounded eviction/retry loop.

## 10. Single-endpoint integration

The canonical secure local endpoint uses one shared residency manager for role-routed Ollama clients. Research, presentation/report and deep-model clients therefore share one view of resident weights on that endpoint.

Relevant files:

- `src/three_agent/model_residency.py`
- `src/three_agent/orchestrator.py`
- `src/three_agent/config.py`
- `config/workspace.secure.json`

## 11. Multi-GPU worker-pool integration

`OllamaWorkerPool` creates a separate residency manager for each endpoint:

```text
gpu0 worker -> residency scope A
gpu1 worker -> residency scope B
dual worker -> residency scope C
```

This prevents an eviction decision on one endpoint from being mistaken for the residency state of another endpoint.

Routing also applies the reuse rule before estimating model load cost:

```text
if candidate model already resident on worker:
    candidate_load_bytes = 0
else:
    candidate_load_bytes = estimated_model_bytes
```

This avoids rejecting an otherwise safe worker by double-counting weights already present in VRAM.

## 12. Hugging Face backend contract

Future Qwen embedding/reranker, Chronos and security-specialist backends must use the same lifecycle instead of inventing independent cache policies.

Required conceptual operations:

```text
load_from_local_snapshot_only()
resident_models() / is_resident()
unload()
```

Runtime Hugging Face adapters MUST use approved local snapshots only. A missing local snapshot is a deployment failure; it is not permission to reach Hugging Face Hub.

## 13. Deployment boundary

Deployment may obtain approved artifacts. Runtime may not.

Deployment:

1. read reviewed model manifest;
2. resolve exact revision;
3. download into staging;
4. verify provenance, integrity and license policy;
5. promote into local model store;
6. run smoke/benchmark gates;
7. write deployment receipt;
8. enable offline runtime mode.

Runtime:

1. select trusted role/model mapping;
2. do deterministic work first;
3. select the smallest sufficient model;
4. perform resource admission;
5. acquire residency lease;
6. invoke local backend;
7. release lease;
8. reuse or evict according to policy.

## 14. Metrics

Residency state exposes:

- acquisitions;
- reuse hits;
- evictions;
- active leases;
- idle TTL;
- eviction policy;
- runtime-download state;
- fixed-model-count flag;
- Linux cross-process flock posture.

Operational measurements should include:

```text
reuse_rate = reuse_hits / acquisitions
load_latency_p50/p95
model_evictions_per_hour
VRAM_before / VRAM_after
resource_denials_before / after reclaim
```

No optimization claim is accepted without measurement.

## 15. Acceptance criteria

Automated tests must prove:

- acquiring a lease does not load/download a model;
- already-resident models are reused;
- idle models expire after TTL;
- active leases cannot be evicted;
- cross-process activity can block eviction;
- LRU order is deterministic;
- memory pressure can reclaim inactive models and retry once;
- non-memory resource failures do not trigger eviction;
- runtime download configuration is rejected;
- no fixed resident-model count is introduced;
- worker endpoints have independent residency scopes;
- worker routing does not double-count an already-resident model;
- existing resource-admission tests remain green;
- canonical-module and Internet-egress security CI remain green.

## 16. Next implementation boundary

After this lifecycle converges in CI:

1. add the approved Hugging Face model manifest/provisioner;
2. implement local-only Qwen3 Embedding adapter;
3. implement local-only Qwen3 Reranker adapter;
4. implement local-only Chronos-2 monitoring adapter;
5. benchmark load/reuse/eviction behavior on the dual-RTX5090 host;
6. tune TTL from measured workload rather than intuition.
