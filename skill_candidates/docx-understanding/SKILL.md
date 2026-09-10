---
name: docx-understanding
description: Analyze DOCX content, structure, relationships, tables, images, headers, footers, comments, and revisions without executing Office active content.
license: Project-internal
---

# DOCX Understanding

Require `file-docx-safety` and `document-full-ingestion`.

1. Treat the package as untrusted ZIP/XML and never execute macros, OLE objects, scripts, templates, or external relationships.
2. Inventory paragraphs, headings, tables, images, headers, footers, footnotes/endnotes, comments, hyperlinks, sections, and relationship warnings.
3. Preserve document order and section boundaries; identify text that appears only in headers, footers, notes, or text boxes when supported.
4. Distinguish visible document text from metadata, comments, revision history, and hidden/non-rendered package content.
5. Resolve internal relationships locally; never dereference external URLs or network templates.
6. For tables, preserve row/column structure, merged cells, repeated headings, units, and nearby explanatory text.
7. Flag unsupported or partially parsed OOXML parts rather than claiming completeness.
8. Summaries must retain heading/table/section references sufficient to trace claims back to the source.
