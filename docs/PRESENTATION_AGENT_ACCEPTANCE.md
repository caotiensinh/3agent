# Presentation Agent V1 Acceptance

## Implemented

- Evidence Gate and cross-day research lookup
- Stable `F*` / `I*` evidence catalog
- evidence-ID-only LLM planning contract
- deterministic validation
- deterministic source and limitation appendices
- research SHA-256 lineage
- structural presentation QA metadata
- PPTX renderer with source footers and speaker notes
- optional LibreOffice PDF conversion
- CLI audience/purpose/language/slide/format controls
- unit tests for evidence validation and PPTX generation

## Security / truth posture

Agent 2 may have broad machine permissions in test mode, but visible factual slide content remains bounded to Agent 1 claim IDs. New external factual research belongs to Agent 1.

## Remaining advanced work

V1 does not claim pixel-level visual QA, automatic company-template adaptation, arbitrary chart generation or image-search/layout automation. Those remain follow-on capabilities.
