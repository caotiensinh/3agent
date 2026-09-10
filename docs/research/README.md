# Exact Research Source Archive

This directory complements the normalized WorkSpace research set (`00_SOURCE_INDEX.md` through `05_MASTER_IMPLEMENTATION_CHECKLIST.md`) by preserving the **complete attached source documents** used in the study.

## Why both forms exist

- `01_...` through `04_...` are project-integrated, normalized engineering documents.
- `sources/` is immutable provenance: the complete original research text, gzip-compressed only for repository transport/storage.
- A research statement becomes project policy only when it is explicitly promoted into the WorkSpace doctrine/checklist.

## Exact source set

| ID | Original source | Archive path | Raw SHA-256 after reconstruction |
|---|---|---|---|
| R1 | Original WorkSpace Efficient Reasoning / deep-research report | `sources/efficient-reasoning-v1.md.gz.part-*` | `46c41d370b902dcdbc53685ffbbc24d4631edd637ff6306006794124f027de2b` |
| R2 | WorkSpace Efficient Reasoning Doctrine v2.0 | `sources/efficient-reasoning-v2-full.md.gz.part-*` | `27ff5f8aeb86eb2b7dda73277772cfad63a36dc55fc9467da82fcb7df12ebeba` |
| R3 | WorkSpace Efficient Reasoning Doctrine v2.0 — Fact-Checked, Corrected, and Expanded | `sources/efficient-reasoning-v2-fact-checked.md.gz` | `7757a4268765115507d6f4d2b036cba904764f343338d943046d8eb5bb210d1c` |
| R4 | WorkSpace Efficiency Playbook v3 | `sources/workspace-efficiency-playbook-v3.md.gz` | `f5a54ee256412f5205ec9b8c17a5f6aa111045dc72a6fcfa40fdf50b80c22687` |

Large gzip files are split only because repository-connector transport has payload limits. The split is not a semantic transformation.

## Reconstruct and verify

```bash
mkdir -p /tmp/workspace-research

cat docs/research/sources/efficient-reasoning-v1.md.gz.part-* \
  | gzip -dc > /tmp/workspace-research/efficient-reasoning-v1.md

cat docs/research/sources/efficient-reasoning-v2-full.md.gz.part-* \
  | gzip -dc > /tmp/workspace-research/efficient-reasoning-v2-full.md

gzip -dc docs/research/sources/efficient-reasoning-v2-fact-checked.md.gz \
  > /tmp/workspace-research/efficient-reasoning-v2-fact-checked.md

gzip -dc docs/research/sources/workspace-efficiency-playbook-v3.md.gz \
  > /tmp/workspace-research/workspace-efficiency-playbook-v3.md

printf '%s  %s\n' \
  46c41d370b902dcdbc53685ffbbc24d4631edd637ff6306006794124f027de2b /tmp/workspace-research/efficient-reasoning-v1.md \
  27ff5f8aeb86eb2b7dda73277772cfad63a36dc55fc9467da82fcb7df12ebeba /tmp/workspace-research/efficient-reasoning-v2-full.md \
  7757a4268765115507d6f4d2b036cba904764f343338d943046d8eb5bb210d1c /tmp/workspace-research/efficient-reasoning-v2-fact-checked.md \
  f5a54ee256412f5205ec9b8c17a5f6aa111045dc72a6fcfa40fdf50b80c22687 /tmp/workspace-research/workspace-efficiency-playbook-v3.md \
  | sha256sum --check
```

## Project reading order

1. `01_PICOLM_PHILOSOPHY.md` — foundation: resource scarcity, bounded working set, deterministic mechanisms.
2. R1 — original reasoning doctrine.
3. R3 — fact-check/correction layer; where factual/current-capability claims conflict, R3 is preferred research evidence.
4. R2 — expanded engineering doctrine.
5. R4 — implementation and benchmark playbook.
6. `05_MASTER_IMPLEMENTATION_CHECKLIST.md` — executable order; this is where research ideas become engineering work items.

Imported: 2026-08-29 (Asia/Tokyo).
