# Skill Security Review — web-document-understanding

Date: 2026-09-03
Lane: 7
Status: candidate-ready-for-CI

## Purpose

Analyze local HTML/Markdown and already-retrieved web evidence without implicitly granting browser execution, remote fetch, or prompt-injection authority.

## Reviewed upstream ideas

- `microsoft/markitdown@83ce26def9f54b02dfb9d683c7cb47fee17ce4bc`
  - retained concepts: deterministic normalization of HTML and text-oriented formats for downstream analysis.
- Existing WorkSpace enterprise safety and research gateway policies remain authoritative for network access.

## Clean-room boundary

No upstream converter, browser, plugin, MCP service, prompt text, or package is vendored. The candidate is WorkSpace-owned instruction text.

## Removed / denied capabilities

- JavaScript/WASM/event-handler execution
- implicit browser navigation
- remote images/CSS/font/frame/script/API fetching
- local-file dereferencing
- content-driven tool/policy authority
- extension/plugin installation
- shell/process execution

## Safety invariants

- source markup is preserved separately from normalized text
- remote references remain inert by default
- page instructions are untrusted evidence
- boilerplate filtering remains reversible
- fenced code and embedded HTML are inert
- unavailable dynamic regions are disclosed

## Admission gates

1. Size/front matter/hash checks pass.
2. No network capability is introduced.
3. Content cannot change higher-level policy or tool authority.
4. Exact-head CI and regression suite pass before registry admission.
