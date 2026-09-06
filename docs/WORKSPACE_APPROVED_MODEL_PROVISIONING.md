# WorkSpace Approved Model Provisioning

Status: implementation baseline  
Scope: reviewed model identity, deployment-time acquisition, integrity verification, runtime local-only resolution

## 1. Security decision

WorkSpace separates model acquisition from model execution.

```text
review / approval
      |
      v
config/models.approved.json
      |
      | explicit deployment command only
      v
network-capable provisioner
      |
      v
controlled staging directory
      |
      v
SHA-256 + size verification
      |
      v
atomic local promotion + receipt
      |
      +-------------------------------+
                                      |
                                      v
runtime -> offline resolver -> local path -> on-demand VRAM residency
```

A missing runtime model is a provisioning failure. It is never permission to download, repair, update, or discover a remote model.

## 2. Manifest authority

The canonical manifest is:

```text
config/models.approved.json
```

Manifest v1 is intentionally fail-closed. The committed baseline contains no approved Hugging Face models until their source revision, license, and artifact hashes have been reviewed.

Each approved model must contain:

- stable WorkSpace model id;
- provider `huggingface`;
- canonical `owner/name` repository id, not a URL;
- exact 40-character source commit hash;
- local relative destination;
- one or more approved capabilities;
- reviewed license identifier;
- explicit artifact file list;
- SHA-256 for every approved artifact;
- optional exact artifact size.

Floating revisions such as `main`, `latest`, branches, or mutable tags are rejected.

## 3. Runtime prohibition

The manifest must contain:

```json
{
  "runtime_download": false
}
```

Any other value is invalid.

`RuntimeModelResolver` also forces:

```text
HF_HUB_OFFLINE=1
TRANSFORMERS_OFFLINE=1
HF_HUB_DISABLE_TELEMETRY=1
```

The runtime resolver contains no downloader implementation.

## 4. Deployment-only acquisition

The optional deployment dependency is installed separately:

```bash
python -m pip install -e '.[model-provisioning]'
```

Manifest validation is network-free:

```bash
workspace-model-provision \
  --manifest config/models.approved.json \
  --store /var/lib/workspace/models \
  --validate-only
```

Provisioning is explicit and operator initiated:

```bash
workspace-model-provision \
  --manifest config/models.approved.json \
  --store /var/lib/workspace/models \
  --model <approved-model-id>
```

An access token, when required by an approved private/gated repository, is read from `HF_TOKEN` by default. The token is not written into the model receipt.

## 5. Controlled staging and promotion

The provisioner:

1. resolves the model only from the reviewed manifest;
2. calls the Hub downloader with the exact approved commit hash;
3. requests only approved artifact paths;
4. requires the downloader to write into a generated staging directory;
5. checks file existence, exact size when configured, and SHA-256;
6. writes a local provisioning receipt;
7. atomically promotes the verified staging directory into the model store;
8. preserves an existing installed model if new staging validation fails.

Model binary data is never committed to Git.

## 6. Provisioning receipt

A promoted model contains:

```text
.workspace-model-receipt.json
```

The receipt binds the installed snapshot to:

- model id;
- provider;
- repository id;
- exact revision;
- approved manifest digest;
- license identifier;
- verified artifact digests and sizes;
- provisioning timestamp.

The receipt is evidence, not permission to bypass the manifest. Runtime requires both a current approved manifest and a matching receipt.

## 7. Runtime resolution

Runtime model selection must use a trusted WorkSpace model id/capability mapping. User prompts, uploaded files, web content, or another model must not be allowed to supply arbitrary repository ids or revisions.

Runtime resolution:

```text
trusted model id
      |
      v
manifest.require(model_id)
      |
      v
local directory exists?
      | no -> FAIL CLOSED
      v
receipt identity matches manifest?
      | no -> FAIL CLOSED
      v
artifact SHA-256 matches?
      | no -> FAIL CLOSED
      v
return verified local path
```

The first successful resolution in a process is integrity verified and then cached for reuse. The on-demand VRAM residency layer remains responsible for deciding when the verified local model is loaded into GPU memory.

## 8. Relationship to Ollama provisioning

The existing Ollama deployment scripts already perform explicit deployment-time model pulls. They are not runtime download paths.

Manifest v1 deliberately starts with Hugging Face snapshot governance because HF specialist adapters require exact repository revisions and file-level integrity. Ollama digest pinning and migration of `enable_model_pool.sh` into the same approval registry is a separate compatibility step; it must not be faked with invented digests.

## 9. Acceptance criteria

Automated tests must prove:

- floating HF revisions are rejected;
- repository URLs cannot replace canonical repo ids;
- path traversal is rejected;
- missing artifact SHA-256 is rejected;
- runtime download cannot be enabled;
- capability lookup comes only from the approved manifest;
- provisioner uses the exact approved revision;
- download output cannot escape controlled staging;
- SHA-256/size mismatch prevents promotion;
- an existing install survives failed replacement;
- runtime forces HF/Transformers offline mode;
- missing local models fail closed;
- artifact tampering is detected;
- receipt/manifest identity mismatch is detected;
- unapproved model ids are rejected.

## 10. Next boundaries

After this baseline is green:

1. review and pin the first real HF model revisions and artifact hashes;
2. add local-only Qwen3 Embedding adapter;
3. add local-only Qwen3 Reranker adapter;
4. add Chronos forecasting adapter only if monitoring evidence shows a real need;
5. connect each adapter to `ModelResidencyManager` so loading remains on-demand;
6. add signed/offline-verifiable manifest receipts if the deployment threat model requires protection against privileged local tampering;
7. migrate Ollama deployment identity to digest-pinned approval records without breaking existing field installations.
