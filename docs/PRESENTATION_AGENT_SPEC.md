# Presentation Agent V1 Specification

Status: implementation candidate  
Agent: `presentation` / `資料作成・発表AI`

## 1. Purpose

Agent 2 converts verified Research Agent output into professional presentation artifacts. Its job is narrative design and rendering, not independent fact discovery.

This specification extends the repository `docs/SPEC.md` M3 presentation-renderer milestone.

## 2. Source-of-truth boundary

Canonical input is Agent 1's `TASK-ID_handoff.json` schema 1.0.

A run is eligible only if:

- task IDs match
- schema is supported
- `presentation_ready == true`
- at least one `key_facts` item is present

The handoff gate is authoritative for both dry-run and live presentation generation.

Raw research JSON is optional secondary lineage. If present, Agent 2 compares the handoff's factual claim/source mapping to the raw verified facts and rejects a mismatch.

## 3. Evidence model

### Verified facts

Agent 1 fact IDs are preserved exactly: `F001`, `F002`, ...

### Inferences

Agent 1 handoff schema 1.0 does not assign inference IDs, so Agent 2 assigns deterministic IDs `I001`, `I002`, ... without altering inference text or source IDs.

### Sources

Each claim retains source IDs. Source URLs are taken only from handoff `sources`.

### Proposals

New recommendations are allowed only as proposal-class content and are not source-backed unless Agent 1 supplied them as evidence.

## 4. Planner boundary

The local LLM is a planner, not a factual author.

Allowed planner fields:

- title/subtitle
- slide kind/title
- claim references
- proposal points
- non-factual context
- speaker notes

Visible factual claim text is materialized by deterministic Python code from selected claim IDs.

Unknown claim IDs are hard failures.

## 5. Validation

Hard failures:

- missing/blocked/invalid handoff
- task/schema mismatch
- raw research/handoff factual mismatch
- unknown claim ID
- duplicate/missing slide title
- empty non-title slide
- more than six visible items
- deck with no verified fact referenced
- render failure
- requested PDF conversion failure

## 6. Deterministic appendices

After planner validation:

- selected source URLs are grouped into source slides, maximum four per slide
- unresolved items are retained
- Agent 1 source conflicts are retained with severity
- appendix content cannot be suppressed by planner output

## 7. PPTX rendering

Renderer requirements:

- Office Open XML `.pptx`
- 16:9
- real title placeholder on all slides
- structural re-open inspection after save
- body target >=20 pt
- source IDs in notes/footer
- textual `Fact` / `Inference` / `Proposal` classification
- no dependency on installed Microsoft PowerPoint

Implementation dependency: `python-pptx>=1.0.2,<2`.

## 8. PDF rendering

Optional PDF conversion uses `soffice`/LibreOffice. PPTX is created first. Missing converter is an explicit failure when PDF was requested.

## 9. Artifact contract

`presentation-artifact/v1` includes:

- `task_id`
- `agent_id`
- `status`
- canonical handoff path + SHA-256
- optional raw research path + SHA-256
- source quality metrics
- presentation options
- validated plan
- `presentation-qa/v1`
- generated paths
- timestamp

## 10. QA contract

`presentation-qa/v1` reports at least:

- status/errors/warnings
- unique slide titles
- source-bounded factual content
- referenced/available claim counts
- referenced verified-fact count
- evidence coverage ratio
- source appendix presence
- limitations visibility
- accessibility structural targets
- PPTX render inspection when rendered

## 11. CLI

```bash
3agent presentation TASK-ID \
  --live \
  --audience "部長・R&Dチーム" \
  --purpose "技術選定の判断" \
  --language ja \
  --slides 6 \
  --format pptx
```

Formats: `source`, `pptx`, `pdf`, `all`.

Without `--live`, Agent 2 creates a deterministic evidence-backed layout without claiming LLM planning occurred.

## 12. State transitions

Upstream evidence blocker:

`* -> WAITING_HUMAN`

Successful generation:

`PRESENTATION_CREATING -> PRESENTATION_COMPLETED`

Planner/lineage/render failure:

`PRESENTATION_CREATING -> FAILED`

## 13. Out-of-scope V1

- pixel-perfect corporate branding
- automatic image acquisition
- diagram generation
- PowerPoint animations
- arbitrary company template remapping
- semantic visual scoring with a vision model

These can be added after structural/evidence correctness is stable.
