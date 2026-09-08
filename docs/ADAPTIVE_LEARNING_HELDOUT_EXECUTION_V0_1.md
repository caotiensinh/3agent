# Held-out Lane 3 — Isolated Skill Execution v0.1

## Goal

Execute one exact skill subject against one exact held-out prompt without granting
tool, network, credential, filesystem, deployment, learning-store or promotion
authority to the model.

## Trust split

The child model **only generates response text**. It cannot mark its own result
PASS/FAIL.

The parent process validates a content-addressed case containing bounded literal
`required_terms` and `forbidden_terms`, runs the child in `python -I`, and computes
the verdict deterministically from the returned response.

Regex assertions are deliberately not accepted. This avoids arbitrary evaluator
logic and regex denial-of-service risk.

## Exact identity

Each execution packet binds:

- exact subject ID and subject SHA-256;
- exact skill name and LF-canonical skill SHA-256;
- exact skill document bytes;
- exact held-out case SHA-256.

Trailing newlines are part of the canonical skill identity. The runner does not
strip the document before hashing, so a production/candidate subject cannot be
silently rewritten at the execution boundary.

## Isolation

The production executor:

- requires loopback Ollama;
- starts a separate `python -I -m` worker;
- uses a temporary working directory;
- passes a narrow environment;
- sets `shell=False` and `close_fds=True`;
- supplies no tool schema and no runtime tool registry;
- sets deterministic temperature `0`;
- bounds packet and response sizes.

The worker imports no task store, adaptive-learning store, checkpoint authority,
promotion service, tool registry or deployment API.

## Result receipt

The metadata-only receipt stores hashes and counts only:

- subject / skill / case / executor / response SHA-256;
- response byte size;
- required/forbidden assertion counts;
- deterministic reason codes;
- PASS/FAIL.

It excludes raw prompt, raw skill document and raw model response.

## Non-goals

This lane does not compare baseline vs revision, aggregate a benchmark, decide
release regression policy, or promote/supersede a production skill.
