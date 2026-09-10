# WorkSpace current-request output contract fidelity

## Why this exists

The first real P2 multi-turn local-model run on exact main `5aee0c2233bc5a7a8c9368a526681e6b14df9ae8` proved that language/context routing alone was not enough. The local model frequently returned thousands of characters when the current user request explicitly asked for one sentence, two or three bullets, one command, or one number.

The live run kept raw prompts and answers out of persisted evidence. The sanitized result showed response lengths up to 10,313 characters and deterministic failures such as `format:non_bullet_text`, `limit:lines`, `limit:chars`, `format:not_code_only`, and `format:not_single_number`. P2 therefore remained FAIL.

## Authority boundary

`ChatOutputContract` is compiled only from the **current user request**. Prior conversation and attachments cannot grant or modify this contract.

The contract controls response shape and bounded generation only. It does not grant network, tool, model, filesystem, workflow, or execution authority.

Supported explicit constraints currently include:

- exact bullet count in Vietnamese, English, or Japanese;
- one concise sentence;
- JSON only;
- command/code only;
- a single numeric value;
- bounded default prose for ordinary chat.

## Runtime behavior

`ContractAwareProjectChatService` retains the existing deterministic language and conversation-context policy, then:

1. compiles a response contract from the current request;
2. tightens it to one concise clarification when a follow-up has no eligible prior context;
3. passes the contract as a mandatory system-level response-shape instruction;
4. disables model thinking output for ordinary direct chat;
5. derives `num_predict` from the contract instead of always allowing 4096 predicted tokens;
6. validates existing language/neutral-format rules;
7. validates the deterministic output contract;
8. retries once with the exact failure reason;
9. fails closed if the second attempt still violates the current request.

The original user prompt is not rewritten into system authority. The system-level contract contains only deterministic constraints derived from that prompt.

## Context classifier correction

A Japanese standalone prompt may enumerate `1つ目`, `2つ目`, and `3つ目`. The previous classifier treated any occurrence of `2つ目` as a cross-turn reference. The numbered-item follow-up pattern is now start-anchored, so an internal list remains standalone while a request beginning with `2つ目...` remains a follow-up.

## Live evidence policy

The live multi-turn workflow now targets the dedicated `workspace-benchmark` self-hosted runner label and still performs a read-only two-RTX-5090 inventory check inside the job.

The sanitized report path is exported **before** running the live acceptance command. Therefore a semantic FAIL still uploads the bounded sanitized report; raw prompts and raw answers are never persisted in that report.

A CI PASS is not a P2 semantic PASS. P2 may be declared PASS only after a post-merge live run on the real local model passes the unchanged five-case/twelve-turn corpus and its sanitized evidence is inspected.
