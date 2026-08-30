# WorkSpace Chat Language and Intent Fidelity

## Purpose

This document defines the WorkSpace v0.14 chat contract that prevents an ordinary user conversation from being silently converted into the Research → Presentation → Human Report workflow and prevents a Japanese default from overriding an explicit current-message language request.

## Normal chat routing

`mode=chat` with the normal `source` output is a direct, local-only answer path:

```text
current user message
        |
        v
language + request-control resolver
        |
        v
bounded local conversation/file context
        |
        v
local Ollama model
        |
        v
response-language + routing validation
        |
        v
chat response
```

The direct path does **not**:

- start Research Agent;
- start Presentation Agent;
- create a Human Report;
- perform public web search;
- create a research Task solely to answer an ordinary chat message;
- grant execution, repository, or network authority.

Research/artifact workflows remain available only when the user explicitly selects `web_search`, `deep_research`, or requests an artifact output such as PDF/PPTX/all.

## Response-language precedence

WorkSpace resolves the response language deterministically in this order:

1. language command prefix in the current message (`/ja`, `/vi`, `/en`);
2. explicit natural-language instruction in the current message;
3. explicit UI language selection (`ja`, `vi`, `en`);
4. deterministic detection when the UI selection is `Auto`;
5. trusted local fallback configuration (`THREE_AGENT_CHAT_LANGUAGE`, default `ja`).

Examples that must override a Japanese UI/default:

- `Hãy trả lời bằng tiếng Việt ...` → Vietnamese;
- `Bạn hãy trả lời bằng tiếng Anh ...` → English;
- `Please reply in English ...` → English;
- `Reply in Vietnamese ...` → Vietnamese;
- `日本語で答えて ...` → Japanese;
- `英語で答えて ...` → English.

The current message remains authoritative. Previous conversation text is context only and cannot override an explicit current-message language instruction.

## Prompt fidelity

The v0.14 chat parser does not use `" ".join(message.split())` on the user request. Newlines and fenced code are preserved after optional leading slash controls are removed. This prevents multiline commands, code samples, lists, and formatting from being flattened before local inference.

## Local context

Direct chat may use:

- recent messages from the same owner-scoped conversation;
- text extracted from uploads already validated and owned by the same WorkSpace account.

Recent messages are bounded. Local attachment text is bounded and delimited as untrusted data. Instructions embedded inside an uploaded document are not authoritative instructions to WorkSpace.

## Output validation

A direct chat response is checked before it becomes the final assistant message.

The validator rejects:

- a clearly Japanese response when English was requested;
- a clearly Japanese/English response when Vietnamese was requested;
- a clearly English response when Japanese was requested;
- empty responses;
- obvious leakage from the old research/report wrapper such as `# WorkSpace Report`, `Agent 1 · Research`, `presentation_ready`, or `NO_VERIFIED_FACT` when those terms were not part of the user request.

One bounded local repair generation is permitted. If the second response still fails the gate, WorkSpace fails closed instead of publishing the wrong-language answer.

## Audit/privacy boundary

Direct-chat activity records contain metadata such as mode, target language, language-resolution source, effort level, upload count, attempt count, and validator result. Raw user prompts and raw model responses are not copied into activity telemetry.

Conversation text remains in the owner-scoped local chat-history database as before. Direct chat does not create a research Task merely to provide a conversational answer, so research/evaluation metrics are not polluted with unvalidated chat-only work.

## Workflow Studio

Workflow Studio now uses the same Response language selector. `Auto` is resolved from the current workflow description rather than silently hard-coding Japanese. Compiling a workflow remains design-only and does not grant execution authority.
