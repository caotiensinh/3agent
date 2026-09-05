# Consolidation Error History

This file records only observed consolidation failures, their verified root causes, and the corrective action taken during PR #311 convergence.

## 2026-09-04 — Multiturn acceptance self-binding initially omitted the canonical module handle import

**Observed failure / blocker**

The first baseline-delta attempt to flatten `chat_multiturn_acceptance_v2.py` into canonical `chat_multiturn_acceptance.py` stopped before final targeted tests. The V2 diagnostics referenced the base acceptance module namespace, and the transformation correctly avoided a recursive self-import but generated `acceptance = sys.modules[__name__]` without importing `sys`.

**Root cause**

The physical V2 module had a valid cross-module reference to the base canonical module. After flattening both layers into one physical module, that dependency becomes a self-module binding rather than an import. The first transformation changed the binding model but omitted the standard-library dependency required to resolve the module object.

**Fix**

Commit `c7f61b61c55cfa04f11f39cd6d5ac36969c3cfdf` changed the transformation to inject `import sys` before binding `acceptance = sys.modules[__name__]`. Workflow run `33829305539` then passed the consolidation gate and commit `9bb302b9fc47b900fc35c1bced42a65d1b75404c` merged metadata-only runtime diagnostics into canonical `chat_multiturn_acceptance.py`, rewrote the acceptance entrypoint to canonical, deleted physical `chat_multiturn_acceptance_v2.py`, and produced zero new targeted-test failure keys.

## 2026-09-04 — Workflow state-machine rewrite initially touched test-helper module names

**Observed failure / blocker**

The first baseline-delta attempt to flatten `workflow_state_machine_v4.py` and `workflow_state_machine_v4_budgeted.py` produced one new collection failure in `tests/test_workflow_state_machine_v4_budgeted.py`: its helper import `test_workflow_state_machine_v4` had been rewritten to `test_workflow_state_machine`, which does not exist.

**Root cause**

The first consolidation rewrite used unrestricted string replacement for `workflow_state_machine_v4`. That pattern correctly targeted production module paths but also matched the unrelated pytest helper-module filename. Production topology and test-module filenames are different namespaces and must not be rewritten with the same unqualified rule.

**Fix**

Commit `1feb71e849ffac1ea0e7539e834478a33098f7d8` narrowed rewrites to explicit production import paths such as `three_agent.workflow_state_machine_v4` and `from .workflow_state_machine_v4`. Workflow run `33828935186` then passed the baseline-delta gate. Commit `72e9a5a0ce381796261948b6aed6ed0d49194071` preserved V4 bounded-parallel and aggregate-parent-budget behavior in canonical `workflow_state_machine.py`, rewrote production/test imports of the production modules, and removed both physical V4 implementation files with zero new targeted-test failures.

## 2026-09-04 — Knowledge gateway V3 depended on missing canonical visual extraction capability

**Observed failure / blocker**

The first test-gated attempt to consolidate `src/three_agent/knowledge_gateway_v3.py` into `src/three_agent/knowledge_gateway.py` was blocked during collection because `knowledge_gateway_v3.py` and `tests/test_multimodal_attachments_v4.py` imported `NATIVE_IMAGE_EXTENSIONS`, `VisualAsset`, `extract_native_visual`, and `extract_visual_assets` from canonical `document_extractors.py`, but those symbols were absent. The same baseline also exposed a stale production import of the already-removed `workflow_design_v3` module in `chat_gateway_v15.py`.

**Root cause**

History reconciliation preserved consumers from a later multimodal layer while the canonical document-extractor implementation remained at an earlier capability level. The version-chain topology therefore hid two invalid assumptions: a consumer still depended on a deleted workflow-design generation file, and multimodal gateway behavior depended on visual-extraction primitives that had never been preserved in the canonical document extractor.

**Fix**

Commit `79e31c4bd355a2c523655d02ce318b470163117c` rewrote `chat_gateway_v15.py` to import `WorkflowDesignCompilerV3` from canonical `workflow_design.py`. The subsequent test-gated consolidation added the required visual-extraction behavior to canonical `document_extractors.py`, preserved scanned-PDF/native-image/Office embedded-media behavior, merged the multimodal gateway implementation into canonical `knowledge_gateway.py`, rewrote versioned references, and deleted physical `knowledge_gateway_v3.py`. Workflow run `33828538316` completed successfully with no new targeted-test failures; the prior multimodal collection error was eliminated.

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

### 2026-09-04 — workspace_frontend_security circular-version chain

- Observed failure mode: `workspace_frontend_v14.py` consumed `workspace_frontend_security_v1.py`, while the canonical security module consumed `workspace_frontend_v15.py`. Repointing V14 directly to the old canonical implementation would therefore create a V14 → canonical-security → V15 → V14 circular import.
- Root cause: security UI generations carried both frontend-version dependency and implementation authority instead of exposing version-independent canonical overlay builders.
- Fix: move the V1 Security Analyst overlay into `workspace_frontend_security.py`, expose V2/V3 SOC and boundary behavior as canonical builder functions, lazily materialize compatibility HTML only after V15 is available, rewrite consumers to the canonical module, and remove the physical V1 module.
- Regression protection: `tests/test_workspace_frontend_security_canonicalization.py` verifies the physical V1 module is absent, the V13→V15 chain imports without a cycle, and Security Analyst/configuration/SOC/boundary markers are preserved.
