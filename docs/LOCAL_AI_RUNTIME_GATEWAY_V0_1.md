# Local AI Runtime Gateway v0.1

Status: implementation candidate  
Scope: read-only local runtime/model status plane; no model inference routing yet

## Goal

Provide one canonical backend service between WorkSpace UI/orchestration and AI runtimes that are already installed locally. Model weights remain outside Git. The v0.1 service answers operational questions only:

- which trusted local runtime origins are configured;
- whether those runtimes are healthy;
- which configured Ollama models are already installed;
- which manifest-approved Hugging Face models are integrity-valid in the local model store.

The status plane is observation only. It never grants TaskModelAuthority, CapabilityAuthority, model admission, download permission, or remediation authority.

## Boundary

```text
UI / future API / operator script
              |
              v
      LocalAIStatusService
              |
       +------+-------+
       |              |
       v              v
  Ollama GET       ApprovedModelManifest
  /api/tags             +
  loopback only    RuntimeModelResolver
       |              |
       v              v
 installed names   verified local artifacts
```

Not implemented in v0.1:

- model generation;
- streaming inference;
- model selection/escalation;
- vLLM/OpenAI-compatible inference transport;
- model download/pull/update;
- remote/LAN runtime origins;
- changes to `config/models.approved.json`.

## Network policy

Network-backed local AI runtimes are restricted to an origin on:

- `localhost`;
- IPv4 loopback `127.0.0.0/8`;
- IPv6 loopback `::1`.

Credentials, URL paths, query strings, fragments, DNS names other than the exact `localhost`, private LAN addresses, and public addresses are rejected. This prevents a status request from becoming an SSRF or arbitrary internal-network probe.

Ollama v0.1 health uses only:

```text
GET <trusted-loopback-origin>/api/tags
```

The response is bounded to 1 MiB and the timeout is restricted to 0.1..10 seconds. There is no `/api/pull`, `/api/create`, or remote discovery path.

## Hugging Face local status

Hugging Face model status is derived only from:

```text
config/models.approved.json
        +
WORKSPACE_MODEL_STORE (or explicit model_store)
        +
RuntimeModelResolver
```

`RuntimeModelResolver` remains authoritative for exact revision/receipt/artifact membership/hash validation. Missing or invalid artifacts are reported unavailable. Runtime download remains forbidden.

The canonical production manifest may legitimately contain zero models. In that state the local HF runtime is healthy as a status mechanism but reports `NO_APPROVED_MODELS` and no model availability.

## Operator inspection

The standalone command is intentionally outside the main CLI entrypoint until this status service passes the repository regression gates:

```bash
python scripts/local_ai_status.py \
  --config config/workspace.secure.json \
  --manifest config/models.approved.json \
  --store /var/lib/workspace/models
```

The output schema is:

```text
workspace-local-ai-status/v1
```

Every snapshot declares:

```json
{
  "authority": "observation",
  "runtime_download": false,
  "grants_model_authority": false,
  "grants_capability_authority": false
}
```

## Next phase

Only after v0.1 passes CI should v0.2 add the inference abstraction:

```text
ModelGateway.generate
ModelGateway.embed
ModelGateway.rerank
ModelGateway.classify
```

Those operations must consume TaskModelAuthority and existing resource/residency budgets. The UI/API layer should call the gateway/service and must never call Ollama, vLLM, Transformers, or model files directly.
