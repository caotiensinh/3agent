# Consolidation Error History

This file records only observed consolidation failures, their verified root causes, and the corrective action taken during PR #311 convergence.

## 2026-09-04 — Versioning test required forbidden implementation-generation files

**Observed failure / blocker**

`tests/test_versioning_v4.py` asserted that multiple physical production implementation files such as `chat_gateway_v17.py` through `chat_gateway_v22.py` and `workspace_frontend_v18.py` must exist. That requirement directly blocked repository-wide physical consolidation under the Single Canonical Module Rule.

**Root cause**

A product-version contract test had accumulated implementation-topology assertions. Product release/version validation and source-file generation topology are separate concerns; the test encoded the historical `*_vN.py` layout as a required release invariant.

**Fix**

Commit `5643f38487c43815e25403ccb54f616027acccca` removed the physical-version-file existence requirements while retaining product/package version checks and acceptance-CLI presence checks. Canonical entrypoint migration remains a separate convergence gate and is not declared complete by this fix.

## 2026-09-03 — Skill registry schema regressed during history reconciliation

**Observed failure / blocker**

Exact-head CI failed at the `Skill security admission` step before unit tests could run.

**Root cause**

`skills/registry.json` on the reconciliation branch had reverted to an incompatible candidate-style registry shape instead of the canonical secure instruction-only registry expected by the runtime admission loader.

**Fix**

Commit `3a60dcbec0d1d6a3c280209281f306cb0ed5c753` restored the canonical skill registry contract. Subsequent exact-head harness jobs passed `Skill security admission` and `Compile`, allowing CI to reach unit tests.

## 2026-09-03 — Secure workspace config public-search contract regressed

**Observed failure / blocker**

Installer shell-contract validation failed after branch reconciliation.

**Root cause**

`config/workspace.secure.json` had `public_search_enabled=false`, conflicting with the reviewed sanitized public-research contract while the strict egress gateway remained authoritative.

**Fix**

Commit `acb56a851d21f978d10898c4d6cb6842528dc14d` restored `public_search_enabled=true` without enabling direct egress or weakening the strict sanitized egress policy. Subsequent shell-contract validation passed.
