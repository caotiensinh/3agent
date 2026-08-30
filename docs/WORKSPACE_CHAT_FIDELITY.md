# WorkSpace Chat Language and Intent Fidelity

WorkSpace v0.15 separates ordinary conversation from the evidence workflow and makes the current user request authoritative for response language.

## Routing

`mode=chat` with normal `source` output uses the local model directly. It does not start Research Agent, Presentation Agent, Human Report, public web search, or create a research Task merely to answer a conversational message.

`web_search`, `deep_research`, and explicit artifact output such as PDF/PPTX/all continue to use the existing evidence-bounded workflow and its TaskContract, validator, DLP, ownership, and authorization boundaries.

Workflow Dispatch V2 is unchanged in authority: manual trigger, low-risk fixed profile, administrator admission/authorization, and the existing execution/validation boundary.

## Language precedence

Language is resolved locally and deterministically:

1. `/ja`, `/vi`, or `/en` in the current message;
2. an explicit natural-language instruction in the current message;
3. an explicit UI choice;
4. deterministic detection when UI is `Auto`;
5. `THREE_AGENT_CHAT_LANGUAGE` fallback.

Examples:

- `Hãy trả lời bằng tiếng Việt ...` → Vietnamese even if the UI previously selected Japanese.
- `Bạn hãy trả lời bằng tiếng Anh ...` → English.
- `Please reply in English ...` → English.
- `Reply in Vietnamese ...` → Vietnamese.
- `日本語で答えて ...` → Japanese.
- `英語で答えて ...` → English.

Previous messages are context only. They cannot override an explicit language instruction in the current user message.

## Prompt fidelity

The v0.15 parser preserves newlines and fenced code. It removes only recognized leading slash controls instead of flattening the message with whitespace normalization.

Recent conversation context is bounded. Local attachment text is bounded and clearly delimited as untrusted data. Instructions embedded in an attachment do not gain instruction authority.

## Output gate

A direct response is checked for the requested language and for leakage from the old research/report wrapper. One bounded local repair generation is allowed. If the second result still fails, WorkSpace fails closed instead of publishing a wrong-language answer.

The same final language gate is applied to reader-facing research/report answers before the gateway publishes them. A mismatched answer is removed from the job view and replaced by a failed status; audit artifacts can remain locally for diagnosis.

## UI and Workflow Studio

The Response language selector now defaults to `Auto · follow current request`. Workflow Studio compile and Dispatch preparation use the same selector rather than hard-coding Japanese. `Auto` is resolved server-side before an executable dispatch record is prepared.

## Privacy and metrics

Direct-chat activity logging is metadata-only (mode, target language, resolution source, effort, upload count, retry/validator status). Raw prompts and raw responses are not copied into activity telemetry. Conversation text remains in the existing owner-scoped local chat-history database.

Ordinary chat does not create a research Task, so research/evaluation metrics are not polluted by normal conversation-only work.
