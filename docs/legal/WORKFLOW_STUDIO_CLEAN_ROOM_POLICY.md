# Workflow Studio clean-room and provenance policy

## Purpose

Workflow Studio is WorkSpace-owned code. External open-source projects may be studied to understand general diagram-editor and workflow interaction patterns, but their source code, UI assets, stencils, icons, trademarks, example data and product-specific visual identity are not copied into WorkSpace unless a separate dependency/import review explicitly authorizes that use.

This file is an engineering provenance control, not a substitute for legal advice.

## Default rule

Every external project consulted for Workflow Studio must be recorded in `docs/legal/WORKFLOW_STUDIO_OSS_PROVENANCE.json`.

The default status is:

- `code_imported=false`
- `assets_imported=false`
- `dependency_added=false`
- `trademark_reused=false`

A change to any of those values requires a separate review that records the exact component/version, license and NOTICE obligations, redistribution obligations, branding constraints, security review and rollback plan.

## Clean-room implementation rule

WorkSpace implementation is written from WorkSpace requirements and contracts. Research notes may describe general interaction concepts such as zoom/pan, selection, node/edge editing, property inspection, undo/redo and auto-layout. Implementation code must be independently authored against WorkSpace's own workflow contract and tests.

Do not copy source snippets, CSS/component markup, icons/stencils/templates/example diagrams, screenshots as production assets, branded names/logos, or project-specific data models when WorkSpace already has its own contract.

## Data ownership and customer content

Workflow descriptions, contracts, revisions and audit metadata remain local WorkSpace application data. Saving a draft never sends workflow content to a reference project, public service or external model.

The Workflow Draft store records immutable revision hashes and actor/timestamp metadata so an enterprise can establish who changed a design and when.

## AI-generated workflow provenance

AI output is treated as an untrusted proposal. A generated workflow becomes a saved WorkSpace draft only after deterministic V4 validation. Saved drafts carry an origin marker (`workspace_ai`, `human` or `import`) and immutable revision hashes. Origin does not grant execution authority.

## Current reference set

The machine-readable registry currently lists diagrams.net/draw.io, xyflow, LogicFlow and Rete.js as inspiration-only sources. No code, assets, runtime dependency or trademark from those projects is introduced by the Workflow Studio Draft Library feature.
