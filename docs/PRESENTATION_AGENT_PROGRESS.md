# Agent 2 / Presentation V1 Progress

Status: implementation candidate on `feature/agent2-presentation-v1-final`.

Implemented scope:

- Agent 1 handoff schema 1.0 gate
- evidence claim catalog with preserved `F001...` fact IDs
- deterministic `I001...` inference IDs
- local-LLM deck planning by claim reference only
- hard rejection of unknown claim IDs and inference-only decks
- deterministic source/conflict/limitation appendices
- JSON/Markdown artifact lineage with SHA-256
- Linux PPTX rendering with title placeholders and speaker notes
- optional LibreOffice PDF conversion
- cross-day research handoff lookup
- structural QA and renderer reopen inspection

Acceptance authority remains GitHub CI plus a real local Ollama run on the RTX workstation.
