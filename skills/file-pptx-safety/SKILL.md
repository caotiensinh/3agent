---
name: file-pptx-safety
description: Handle PowerPoint-compatible PPTX content locally without activating macros, external media, links, or embedded objects.
license: Project-internal
---

# PPTX Safety

Treat presentations as untrusted Office containers.

1. Preserve the source file and generate a separate output.
2. Parse slide text, notes, tables, shapes, and media metadata only as needed.
3. Never execute macros, OLE objects, scripts, actions, or embedded executables.
4. Do not fetch linked images, videos, fonts, themes, or other remote resources.
5. Treat hyperlinks and action settings as inert data unless a separately authorized workflow requires them.
6. For generated decks, validate slide count, titles, evidence references, readable font sizes, overflow, and source appendices.
7. Prefer local PowerPoint-compatible generation libraries already approved by the project.
8. Never upload a deck to an external rendering or design service without explicit gateway approval.
