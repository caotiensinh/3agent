# WorkSpace Chat Fidelity Acceptance

## Purpose

WorkSpace ordinary chat must preserve the current user's intent, requested language, and requested output shape without silently converting the request into the Research → Presentation → Daily Report workflow.

This acceptance harness adds a deterministic, repeatable quality gate for representative Vietnamese, English, and Japanese chat requests. It does **not** use another LLM as a judge.

## Two evidence levels

### 1. Deterministic contract / CI mode

```bash
workspace-chat-acceptance
```

This mode performs no model call and no network call. It validates:

- corpus schema and unique case IDs;
- language resolution for every prompt;
- stable corpus SHA-256;
- deterministic answer-evaluation logic exercised by unit tests;
- language, required-concept, forbidden-wrapper, output-shape, item-count, and size constraints.

A PASS in CI means the acceptance machinery is internally consistent. It does **not** mean the installed local model has passed the corpus.

### 2. Live local-model mode

```bash
workspace-chat-acceptance --live
```

This mode loads the same WorkSpace configuration and calls `Orchestrator.llm`, which is the same local model route used by ordinary direct chat. It uses the same direct-chat system prompt, trust domain `workspace-local-chat`, template version `workspace.chat.direct.v1`, and the same maximum of two attempts for language/format repair.

Before creating the runtime, the harness checks every configured Ollama endpoint. Only `localhost` or literal loopback/private/link-local IP endpoints are accepted. Public hostnames, public IP addresses, wildcard destinations such as `0.0.0.0`, and non-HTTP(S) schemes must fail closed.

Run one case with:

```bash
workspace-chat-acceptance --live --case vi_https_port_number
```

Multiple `--case` options may be supplied. Raw model responses are not persisted by this tool. For an interactive synthetic debugging run only, `--show-responses` prints them to stdout:

```bash
workspace-chat-acceptance --live --case en_https_json_only --show-responses
```

## Representative corpus

The built-in corpus covers 12 synthetic, non-confidential cases across Vietnamese, English, and Japanese. It includes:

- DNS diagnosis and a DNS-check command;
- HTTP 404 one-sentence explanation;
- exact three-item Japanese network checklist;
- HTTPS port as a single-number-only answer;
- HTTPS metadata as JSON-only output;
- Japanese code-block-only command output;
- exact three-item bind-port diagnosis;
- exact identifier preservation for `WORKSPACE_LLM_MODEL`;
- normal-chat `ping` vs `traceroute` explanation with research-wrapper rejection;
- one-line translation to English;
- exact two-step Vietnamese port-8080 troubleshooting;
- Linux listening-socket command-only output.

The corpus is integrity-addressed with a stable SHA-256 over its canonical definition.

## Language-neutral output rule

The normal response-language gate remains strict for prose. WorkSpace bypasses prose-language validation only when the **current user request explicitly asks for a language-neutral output shape**:

- JSON only;
- only a number;
- code/command only or without explanation.

The returned answer must then match that shape exactly. For example, a JSON-only request rejects explanatory prose wrapped around otherwise valid JSON. Merely mentioning code, JSON, or a number is not enough to bypass the language gate. A request such as “explain this code in Vietnamese” still requires Vietnamese prose.

## Evaluation rules

The evaluator is deterministic. A case can require one or more of:

- target language / direct-chat validator PASS;
- at least one term from each required concept group;
- absence of forbidden Research/Report wrapper markers;
- strict JSON object shape and required keys;
- strict single-number output;
- code/command-only shape;
- exact bullet count;
- exact text where appropriate;
- maximum line and character limits.

Semantic failures do not trigger an invented model retry. The live runner only mirrors the production bounded repair for direct language/format/routing validation. Required-concept and other acceptance failures are reported as failures.

## Privacy and authority

- The corpus contains synthetic public technical examples only.
- The harness does not enable public web research.
- The harness does not grant execution, network, workflow, or administrative authority.
- Raw responses are not persisted by default.
- Live endpoint validation does not perform DNS resolution of arbitrary hostnames.
- A live acceptance PASS is local product-quality evidence only. It is **not** an external evaluator attestation and must not be used to close D7 holdout/evaluator blockers or any other external evidence requirement.
