# P2 live multi-turn fidelity evidence

## Source evidence

The first live semantic run executed the local model on exact main SHA `5aee0c2233bc5a7a8c9368a526681e6b14df9ae8` with the unchanged five-case / twelve-turn corpus.

Observed boundaries were healthy: local model execution occurred, public egress remained disabled, the production database was not mutated, and raw prompts/answers were not persisted in the report.

The semantic verdict was FAIL. The dominant failure was current-request output-shape fidelity rather than response-language routing: bounded bullet and sentence requests produced multi-thousand-character answers, neutral code/number-only requests could fail after retry, and the Japanese standalone numbered-list case exposed an internal-enumeration false positive in follow-up classification.

## Production repair

This patch keeps the acceptance corpus unchanged and repairs production behavior instead:

- compile a deterministic response-shape contract from the current request only;
- bound final generation by requested output shape;
- validate exact bullet count, one-sentence shape, JSON-only, code/command-only and single-number output;
- keep one bounded repair attempt with the prior deterministic failure reason;
- preserve High-effort local reasoning while keeping the final answer subject to the same output contract;
- tighten missing-reference responses to one concise clarification sentence;
- prevent Japanese internal numbered lists from being classified as cross-turn follow-up;
- route live acceptance only to the dedicated `workspace-benchmark` runner;
- export the sanitized report path before execution so failure evidence can still be uploaded.

## Evidence discipline

Passing ordinary CI does not prove semantic fidelity. The P2 verdict remains open until the unchanged corpus is executed again on the trusted local-model runner and the sanitized report records `passed=true` on the merged exact source SHA.
