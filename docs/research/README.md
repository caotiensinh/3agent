# WorkSpace Efficient-Reasoning Research Archive

This directory preserves the research inputs used to derive the WorkSpace engineering doctrine and implementation checklist.

## Governance

- Files under `docs/research/sources/` are **immutable research/provenance inputs**, not executable policy.
- Normative project rules live in the project governance/specification documents and the Pico-first doctrine derived from these sources.
- A research claim does not become a project requirement until it is explicitly promoted into a normative document and backed by implementation evidence.
- The source documents are preserved byte-for-byte after reconstruction and are verified by SHA-256.

## Source set

| ID | Source | Archive path | Raw SHA-256 |
|---|---|---|---|
| R1 | WorkSpace Efficient Reasoning Doctrine v1.0 / deep research report | `sources/efficient-reasoning-v1.md.gz.part-*` | `46c41d370b902dcdbc53685ffbbc24d4631edd637ff6306006794124f027de2b` |
| R2 | WorkSpace Efficient Reasoning Doctrine v2.0 | `sources/efficient-reasoning-v2-full.md.gz.part-*` | `27ff5f8aeb86eb2b7dda73277772cfad63a36dc55fc9467da82fcb7df12ebeba` |
| R3 | WorkSpace Efficient Reasoning Doctrine v2.0 — Fact-Checked, Corrected, and Expanded | `sources/efficient-reasoning-v2-fact-checked.md.gz` | `7757a4268765115507d6f4d2b036cba904764f343338d943046d8eb5bb210d1c` |
| R4 | WorkSpace Efficiency Playbook v3 | `sources/workspace-efficiency-playbook-v3.md.gz` | `f5a54ee256412f5205ec9b8c17a5f6aa111045dc72a6fcfa40fdf50b80c22687` |

Large gzip archives are split only to keep repository-connector transport atomic. The split is not a semantic transformation.

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

## Reading order

1. `R1` — original efficient-reasoning doctrine and PicoLM-derived resource discipline.
2. `R3` — fact-check/correction layer. Where R1 and R3 conflict on factual attribution or current capability, R3 wins as research evidence.
3. `R2` — expanded engineering doctrine and architecture detail.
4. `R4` — implementation-order playbook and benchmark gates.
5. `../PICO_FIRST_ENGINEERING_PHILOSOPHY.md` — normative WorkSpace interpretation.
6. `../IMPLEMENTATION_CHECKLIST.md` — executable implementation order.

Imported: 2026-08-29 (Asia/Tokyo).
