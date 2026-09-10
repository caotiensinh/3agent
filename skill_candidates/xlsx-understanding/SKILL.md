---
name: xlsx-understanding
description: Analyze XLSX workbooks safely and traceably across sheets, formulas, values, tables, charts, named ranges, comments, and workbook structure without recalculation or macro execution.
license: Project-internal
---

# XLSX Understanding

Require `file-xlsx-safety` and `document-full-ingestion`.

1. Inventory all visible, hidden, and very-hidden sheets; record used ranges, tables, charts, comments/notes, named ranges, formulas, and external-link warnings.
2. Never execute VBA, Office Scripts, add-ins, DDE, external data refreshes, or network-linked formulas.
3. Preserve both formula text and cached value when available; do not silently treat cached values as freshly recalculated.
4. Identify errors, blanks, merged cells, hidden rows/columns, filters, and units that can change interpretation.
5. Treat workbook/sheet protection as metadata, not a security boundary to bypass.
6. Analyze tables by explicit coordinates and header names; preserve sheet and cell references in conclusions.
7. For charts, trace series and categories back to source cells when available and disclose broken or external references.
8. Bound cell count, formula count, dimensions, decompressed bytes, and processing time; disclose any skipped regions.
9. Never claim whole-workbook coverage without a sheet-by-sheet coverage ledger.
