# Enterprise Document Intelligence V1

## Goal

WorkSpace must safely ingest batches of long business documents (tens to hundreds of pages) without pretending that prompt truncation equals whole-file understanding.

## Core separation: ingestion completeness vs answer context

Full ingestion is a persistent preprocessing contract. Answer context is a bounded view generated only after ingestion.

1. **Inventory** every file and child content unit (page, slide, sheet, table, image, archive member).
2. **Parse/vision/OCR** every supported required unit under explicit resource budgets.
3. Write a **coverage ledger** with `complete`, `partial`, or `rejected` and reason codes.
4. Persist normalized unit text, structural metadata, hashes, provenance, and skill versions.
5. Build local lexical/semantic indexes and hierarchical summaries.
6. At question time, retrieve only relevant evidence plus document/section summaries; never use prompt size as ingestion coverage.

Whole-file claims are permitted only when the ledger is `complete`.

## Content-unit model

Each unit has a stable ID, parent ID, locator, SHA-256, media kind, parser/skill ID+version, status, warnings/errors, extracted text pointer, visual-semantic pointer, token/character counts, and timestamps. Locators include PDF page, PPT slide, XLSX sheet/range, DOCX section/table, native image, and ZIP member path.

## Scale strategy

### Batch scheduler

- owner/tenant scoped queue
- bounded worker pools by workload: CPU parse, OCR/vision GPU, embedding/index, summarization/reasoning
- backpressure from memory/VRAM/disk pressure
- priority and cancellation per job
- idempotent checkpoint/restart
- content-hash dedupe and cache reuse
- no repeated OCR/vision for unchanged units

### Hierarchical understanding

For a 100+ page file, store:
- page/unit evidence
- section summaries
- document summary
- collection summary
- searchable local index

Question answering traverses collection -> document -> section -> exact evidence. This permits large corpora without injecting all text into one LLM call.

### Coverage ledger

Required counters include expected/processed/failed/skipped units, machine-text pages, OCR-required/completed pages, visual-required/completed units, sheets/slides/tables, archive members, truncated units, unsupported units, and final coverage state.

Any safety/resource cap hit makes coverage `partial` unless the unit was explicitly out of scope by user policy. `partial` must be visible to the answer layer.

## Large pasted text

Long user-authored paste is persisted as an internal UTF-8 `.txt` artifact with SHA-256 and owner/conversation/message lineage. History carries a compact pointer. The artifact retains `origin=current_user_paste`, so it remains current-user instruction authority rather than ordinary untrusted attachment instructions.

## Enterprise acceptance gates

- 1, 10, 100, and 500-file batch fixtures
- 1, 50, 100, and 300-page PDF fixtures
- scanned and mixed-text/scan PDFs
- Office documents with tables, embedded images and large sheets
- archive bombs/path traversal/encrypted/nested archive tests
- restart midway and exact resume
- duplicate-content reuse
- forced parser/OCR/Vision failure must produce `partial`, never `complete`
- deterministic audit record of every skill/version used
- no Internet dependency during document processing unless an administrator explicitly approves an allowlisted skill profile
