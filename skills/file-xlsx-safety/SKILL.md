---
name: file-xlsx-safety
description: Handle Excel-compatible XLSX data locally with formula, macro, external-link, XML, and resource-limit precautions.
license: Project-internal
---

# XLSX Safety

Treat spreadsheets as untrusted ZIP/XML containers and formulas as data unless explicitly evaluated by an approved local engine.

1. Preserve the original workbook and inspect sheet names, dimensions, types, formulas, named ranges, hidden sheets, and external-link indicators.
2. Never execute VBA, macros, DDE, external links, embedded objects, or formula-driven network actions.
3. Do not treat cached formula values as newly calculated results; record whether a value came from a formula, cache, or literal cell.
4. Apply row, column, file-size, decompression, and memory limits before loading large or untrusted workbooks.
5. Use hardened XML parsing for untrusted workbook XML and reject suspicious archive expansion.
6. Validate types, units, missing values, merged cells, dates, and locale-sensitive numeric formats before statistical analysis.
7. Write outputs to a new workbook and verify formulas, values, sheet names, and critical formatting.
8. Keep workbook data local; no external spreadsheet, conversion, telemetry, or upload service is authorized by this skill.
