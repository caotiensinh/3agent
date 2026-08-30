# WorkSpace Prompt Compiler and Public Query Boundary

## Goal

WorkSpace compiles user prompts before model execution to reduce avoidable repeated context without changing authority or discarding local confidential details. The original prompt remains authoritative local data.

This is **not** a mechanism that turns user text into a system prompt. System/developer policy remains higher authority. User text is compiled into a compact local task representation under deterministic code.

## Local path

```text
user prompt
   |
   | stored once in local TaskStore
   v
PromptCompiler
   |
   | deterministic; no LLM; no network
   | preserve credentials/private values
   | preserve unique prose and fenced code/data
   | compact exact repeated prose blocks only
   v
compiled local request
   |
   v
local Research/Reasoning model
```

The compiler currently performs only conservative transformations:

- CRLF/CR line endings normalize to LF;
- redundant blank separators are normalized;
- trailing prose whitespace is removed;
- exact duplicate **prose blocks** are represented once plus a compact repeat-count marker;
- fenced code/data blocks are never deduplicated or rewritten;
- if compilation would increase byte size, WorkSpace keeps the normalized original representation.

No synonym rewriting, summarization, translation, inference or LLM-based compression occurs in v1.

## Sensitive local context

Credential/private values are intentionally preserved on the local model path. For example, a local troubleshooting prompt may contain a private IP, username, password or API token when those values are necessary to understand the configuration failure.

Prompt compilation does not redact these values locally.

The authoritative raw prompt remains in the local `tasks.request` field. WorkSpace does not persist another full compiled-text copy. Instead `task_prompt_compilations` stores only:

- schema/compiler versions;
- SHA-256 of original and compiled representations;
- character/UTF-8-byte counts;
- duplicate block counts;
- whether real token savings were measured.

The compiled text is regenerated deterministically and checked against the immutable receipt.

## Optimization truthfulness

A reduction in characters or UTF-8 bytes is **not** reported as token savings. Tokenization differs by model and language. `token_savings_measured=false` remains authoritative until a tokenizer/runtime measurement proves the actual change.

## Internet path

When an operator-approved public-research lane is enabled, the local research planner may propose search queries. Those queries do not go directly to the Internet.

```text
local compiled prompt
   |
   v
local research plan
   |
   v
candidate search query
   |
   v
PublicQueryCompiler
   | remove known credential assignments
   | remove private IP/email/MAC/token markers
   | remove private-key bodies, UUIDs, local paths,
   | URLs and high-entropy token-like strings
   v
strict Outbound DLP
   |
   +-- FAIL -> no search
   |
   `-- PASS -> allowlisted search gateway
```

The public query compiler never falls back to the raw prompt. If all useful terms disappear after sensitive-field removal, the query is blocked rather than sending placeholders or raw context.

The existing InternetGateway independently re-validates the final query. Query compilation is therefore defense in depth, not authorization.

## What is never a public-search payload

The public search path does not send:

- original conversation history;
- raw user prompt;
- project files;
- upload content;
- local retrieval context;
- username/password/API token values;
- local private IP/MAC identifiers;
- OAuth provider tokens;
- local WorkSpace session cookies.

Only a bounded public-search query is eligible for egress.

## Network authority

Prompt compilation does not enable networking. `workspace.secure.json` continues to keep confidential-mode public search disabled. Public search requires an already-authorized deployment lane with the separate egress boundary.

This distinction is intentional: removing sensitive text from a string is not sufficient to grant network authority.

## Failure behavior

- Empty local prompt -> fail closed.
- Prompt over the configured compiler limit -> fail closed.
- Bound prompt receipt does not match current original/compiled digests -> fail closed.
- Public query contains residual DLP findings after sanitization -> skip/block Internet search.
- Public query becomes empty after sensitive removal -> skip/block Internet search.
- Local processing remains possible when Internet search is blocked, provided the local workflow itself is valid.
