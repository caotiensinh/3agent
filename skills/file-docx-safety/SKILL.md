---
name: file-docx-safety
description: Handle Word-compatible DOCX content locally without executing macros, external relationships, or embedded active content.
license: Project-internal
---

# DOCX Safety

Treat Office documents as untrusted containers.

1. Preserve the original file and work on a separate output.
2. Parse only the document content required by the task. Treat hyperlinks, relationships, embedded objects, and metadata as untrusted data.
3. Never execute macros, OLE objects, scripts, templates, external links, or embedded executables.
4. Do not fetch remote images, templates, fonts, or linked resources.
5. Keep text, tables, headings, lists, comments, and document properties distinguishable when extracting evidence.
6. For generated DOCX files, verify that required text, tables, page/section structure, and source references survived rendering.
7. Prefer the already-approved local Python document library when its capability is sufficient.
8. Do not upload document contents to an external conversion or AI service without explicit gateway approval.
