# WorkSpace Product Versioning v2

## User-facing version

Beginning with Workflow V4, the WorkSpace product version is displayed in this form:

```text
ver.0.0.1
```

Product UI, health responses, operator messages, and release documentation use the `ver.X.Y.Z` label.

The next compatible patch releases should normally advance as `ver.0.0.2`, `ver.0.0.3`, and so on. Minor/major meaning can be formalized later without changing the `ver.` display prefix.

## Python package migration

The historical WorkSpace package line reached `0.18.0` before the new user-facing version scheme was adopted. Publishing the new product line as Python package `0.0.1` would sort below `0.18.0`, which could prevent normal package upgrade flows.

Therefore the Python package metadata uses the PEP 440 epoch form:

```text
1!0.0.1
```

The epoch is package-manager metadata only. It preserves monotonic upgrade ordering from the historical package line and is not the WorkSpace product label.

Mapping for this release:

```text
Product/UI/API/docs:  ver.0.0.1
Python package:       1!0.0.1
Release generation:   v4
Version scheme:       workspace-release/v2
Production gateway:   chat_gateway_v17
Rollback context:     chat_gateway_v16
```

`chat_gateway_v16` remains the independently tested deterministic multi-turn context layer. `chat_gateway_v17` composes that context layer with the bounded Workflow V4 runtime; the version transition must not remove the multi-turn acceptance CLI.

Code should import product-version values from `three_agent.version` rather than duplicating display-version literals when practical.
