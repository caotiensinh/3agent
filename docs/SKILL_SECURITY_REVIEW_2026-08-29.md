# Skill Security Review — 2026-08-29

Status: APPROVED FOR THE PROJECT-WRITTEN INSTRUCTION-ONLY SKILLS LISTED IN THIS RECORD

## Purpose

This review expands the 3Agent skill catalog without expanding runtime authority. The approved artifacts are short project-written `SKILL.md` instruction files. No third-party script, package installer, hook, MCP server, browser session, API client, binary, template bundle, executable resource, or automatic updater is copied into the repository by this change.

The security goal is simple: a skill may improve reasoning structure, but it must not create a new path that can transmit task data, credentials, files, prompts, logs, or model output to a destination outside the gateways already controlled by 3Agent.

## Approved skills

- `data-analysis-local`
- `language-quality`
- `coding-quality`
- `software-development`
- `presentation-design`
- `file-docx-safety`
- `file-xlsx-safety`
- `file-pptx-safety`
- `file-pdf-safety`

Every approved entry is instruction-only, SHA-256 pinned, scoped to explicit agent IDs, and declares zero network, credential, persistent-self-modification, and vendored-executable authority. A modification to an enabled skill invalidates its digest and causes loading to fail until deliberate review updates the registry.

## Public sources reviewed

### Agent Skills open specification

Reviewed revision: `agentskills/agentskills@69ef37e9424c0a7ea9dd2293b559e43ec8176379`

Approved concept: progressive disclosure—discover lightweight skill metadata first and load detailed instructions only when the task actually needs that capability. No external runtime or automatic skill installer is adopted.

### seb1n/awesome-ai-agent-skills

Reviewed revision: `seb1n/awesome-ai-agent-skills@75865a5d037a4cdaa7f409a4ec14ab9b0292920b`

License observed for the library: MIT.

Reviewed areas include data analysis, code review/debugging/testing, frontend/design, report generation, PDF processing, technical writing/proofreading/translation, and software/project decomposition.

Positive patterns include explicit workflows, validation before conclusion, edge-case handling, reproducibility, source/report traceability, and separation of analysis from communication.

Risk decision: the upstream library permits optional scripts/resources and some skills describe direct integrations or external tooling. 3Agent does not copy those resources and does not automatically install the catalog. Only general workflow ideas are rewritten in shorter project-owned wording. Upstream updates are not trusted automatically.

### Anthropic public skills repository

The public repository was reviewed because its DOCX/PDF/PPTX/XLSX skills are strong architectural references.

Decision: REJECTED AS A SOURCE FOR VENDORED OR DERIVED DOCUMENT SKILL CONTENT.

The relevant document skills are source-available under restrictive terms rather than a permissive open-source license. 3Agent therefore does not copy, vendor, translate, or derive those instructions. The project document skills are written independently around local processing and security requirements.

### Executable skill catalogs

Some public catalogs include self-contained executable scripts, dependency metadata, terminal authority, automatic installers, or third-party integrations.

Decision: NO RUNTIME ADOPTION unless separately reviewed. Those components increase supply-chain and execution surface and are unnecessary for the instruction-only 3Agent tier.

## Local file-tool candidates

### DOCX

Current project dependency: `python-docx`. License observed: MIT.

Approved for local DOCX generation/inspection within its supported capabilities. Do not execute macros, OLE objects, external templates, or linked content. No cloud document converter is authorized.

### PPTX

Current project dependency: `python-pptx`. License observed: MIT.

Approved for local PPTX generation/inspection within its supported capabilities. Do not activate macros, actions, linked media, OLE objects, or remote assets. No external rendering/design service is authorized.

### XLSX

Candidate library: `openpyxl`. License observed: MIT/Expat.

Upstream documentation warns that standard XML parsing is not sufficient protection against XML entity-expansion attacks in untrusted files and recommends `defusedxml`.

Decision: skill guidance is approved now, but actual untrusted-XLSX ingestion is not approved until implementation includes archive limits, hardened XML handling, macro/external-link refusal, and regression tests. No new XLSX parser dependency is added by this skill-only change.

### PDF

Candidate library: `pdfplumber`. License observed: MIT.

Decision: skill guidance is approved now. Actual untrusted-PDF parsing should be introduced separately with page/file/resource limits and active-content refusal. No cloud OCR or conversion service is authorized.

## Data-exfiltration review

The approved skills contain no HTTP/HTTPS runtime URLs, upload endpoints, API credentials, telemetry instructions, shell commands, package-install commands, credential-store access, hooks, MCP declarations, self-update behavior, or persistent cross-task memory writes.

The existing skill loader additionally rejects suspicious executable command blocks, external runtime URLs, secret-like literals, sensitive credential paths, hidden bidirectional/tag characters, extra files, symlinks, missing reviews, agent-scope violations, and digest mismatches.

## File-content trust rule

Office/PDF files are untrusted data. Their text may contain instructions addressed to an AI. Those instructions do not gain authority merely because they appear in a document.

The harness must keep this order:

1. file parser extracts inert content;
2. file/security policy records metadata and warnings;
3. Agent evidence logic decides relevance;
4. only system/profile/approved-skill instructions control behavior.

Document content cannot authorize network access, shell execution, credential access, external uploads, or policy changes.

## Progressive-disclosure rule

The approved catalog is intentionally larger than the default prompt. Adding a skill to the registry does not mean every agent call should load it. Runtime integration should select the smallest relevant skill set for each stage.

Recommended Research stages: planning uses web-trust; source assessment uses source-credibility plus web-trust; synthesis uses evidence-synthesis plus data-quality; structured-data tasks add data-analysis; software/code tasks add coding/software-development; Office/PDF tasks add only the matching file-safety skill.

Recommended Presentation stages: evidence-boundary plus presentation-design; language pass adds language-quality; output-specific work adds only the requested file-safety skill.

Recommended Daily Report: daily-report-evidence plus language-quality only.

## Re-review triggers

Re-review is mandatory if any enabled skill, SHA-256, agent scope, provenance, runtime authority, parser/renderer dependency, network behavior, file-format support, telemetry destination, or automatic skill update behavior changes.

No skill marketplace, latest-branch sync, one-line external installer, package post-install hook, or external skill service is trusted automatically.
