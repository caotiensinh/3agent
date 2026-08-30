# WorkSpace Multi-turn Live Acceptance

## Purpose

This acceptance suite validates real local-model behavior across several turns of one conversation. It is the live complement to the deterministic conversation-context policy in gateway v16.

The suite asks four separate questions:

1. Does a standalone request receive zero prior chat content?
2. Does an explicit follow-up receive bounded completed prior context?
3. Does the current request keep authority over language and output format?
4. Does a missing reference produce clarification instead of invented history?

## Trust boundary

The live suite runs through `ContextAwareProjectChatService`, the same ordinary-chat service used by gateway v16. It does not call the public-research workflow, Internet gateway, execution gateway, Workflow V3 mutation endpoints, or administrator APIs.

Before any model call, all configured model endpoints must resolve syntactically to localhost, private IP, or link-local IP. Public model endpoints fail closed.

## Production-data isolation

A live run does **not** reuse the production chat database.

The runner creates a temporary WorkSpace configuration that redirects:

- SQLite database;
- artifact root;
- profile root;
- Internet audit log;
- execution audit log;

to a temporary directory. Internet and execution gateways are disabled in this isolated configuration.

The temporary directory is deleted after the run.

The installed WorkSpace configuration is read only to obtain the local model configuration and policy. The suite does not write to the deployed `$HOME/3agent` tree.

## Corpus

Schema:

`workspace-chat-multiturn-acceptance/v1`

The initial corpus covers:

- Vietnamese reference chains: standalone -> `cái thứ hai` -> `phần đó`;
- English reference with a current-turn Vietnamese language override;
- Japanese reference chains with `2つ目` and `その設定`;
- stale-history isolation using a known prior marker followed by an unrelated standalone HTTPS-port request;
- a missing-context Vietnamese `tiếp theo?` request that must be marked unavailable and clarified.

Each turn declares expected language, expected context mode, output constraints, required semantic groups, and optional minimum context-message count.

## Evidence

The default JSON report intentionally excludes raw prompts and raw answers.

Per turn it records only:

- PASS/FAIL;
- failure codes;
- expected and actual language;
- expected and actual context mode;
- admitted context-message count;
- bounded retry/model-call count;
- response SHA-256 and character count;
- prompt SHA-256 and structural markers such as current-request boundary, standalone/follow-up policy, recent-context presence, and unavailable-context marker.

The top-level report contains source SHA, package version, corpus SHA-256, case/turn counts, endpoint count, a hash of the configured model identity, and privacy assertions.

A report is a live semantic PASS only when:

- `live_model_executed` is `true`;
- top-level `passed` is `true`;
- source SHA is the exact candidate/main SHA being evaluated;
- every selected case and every turn passes.

A contract-only report has `live_model_executed=false` and must never be represented as live-model evidence.

## CLI

Validate the deterministic contract without calling a model:

```bash
workspace-chat-multiturn-acceptance --contract
```

Run the complete local-model corpus:

```bash
WORKSPACE_CONFIG="$HOME/3agent/config/workspace.secure.json" \
workspace-chat-multiturn-acceptance \
  --live \
  --source-sha "$(git rev-parse HEAD)" \
  --output /tmp/workspace-multiturn-acceptance.json
```

Select one or more cases with repeated `--case` arguments.

## GitHub Actions safety

`.github/workflows/live-chat-multiturn-acceptance.yml` uses the self-hosted RTX 5090 runner only from trusted `main`:

- automatic trigger: relevant files pushed to `main`;
- manual trigger: `workflow_dispatch`, still guarded by `github.ref == refs/heads/main`;
- no `pull_request` trigger;
- checkout credentials are not persisted;
- a fresh virtual environment is created under `$RUNNER_TEMP`;
- no application deployment script is called;
- no `apt`, driver, kernel, `systemctl`, runner-service, Ollama-service, or production `.venv` mutation is performed.

The workflow uploads only the sanitized JSON evidence and retains it for 14 days.

## Evidence boundary

A PASS proves the selected multi-turn corpus passed on the local model available to that exact run. It does not prove every possible natural-language reference will be resolved correctly, and it does not close unrelated external holdout/evaluator requirements such as D7 evidence gates.
