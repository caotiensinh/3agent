---
name: pptx-understanding
description: Analyze PPTX decks slide-by-slide across text, notes, tables, charts, images, masters, and relationships without activating Office content.
license: Project-internal
---

# PPTX Understanding

Require `file-pptx-safety` and `document-full-ingestion`.

1. Inventory every slide, speaker-note page, table, chart, image, hyperlink, media reference, and parser warning.
2. Never execute macros, OLE objects, embedded packages, external media, links, or remote templates.
3. Preserve slide order and distinguish slide-visible text from speaker notes, master/layout text, metadata, and hidden slides.
4. Read visual hierarchy and spatial grouping as evidence, but mark interpretation when layout alone implies a relationship.
5. For charts, extract visible labels and trace series to embedded workbook data when safely available; disclose missing/external data.
6. For images and diagrams, use visual understanding and keep OCR/inference separate from visible facts.
7. Surface hidden slides and unsupported objects; do not silently omit them from “full deck” summaries.
8. Claims must retain slide references and disclose any slide with partial/rejected coverage.
