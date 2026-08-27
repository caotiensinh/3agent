# AGENTS.md

## 1. Project purpose

3Agent is a local-first R&D workflow automation system. It must preserve traceability from the original task request through research evidence, presentation artifacts and daily reporting.

## 2. Canonical agents

- `research`: 調査・情報収集AI
- `presentation`: 資料作成・発表AI
- `daily_report`: 日報作成AI

Do not silently merge these responsibilities into one role. A single local LLM may serve all roles, but each role must keep a distinct system profile, inputs, outputs and activity records.

## 3. Operating authority

### Test workstation

`TEST_MODE_FULL_ACCESS=true` may grant all three agents broad local authority on the designated test PC, including filesystem, shell, Git/GitHub and outbound Internet access.

Requirements even in full-access test mode:

1. All agent actions must be attributable to `task_id`, `agent_id` and timestamp where applicable.
2. Internet use must go through the project Internet Gateway abstraction.
3. GitHub credentials must never be committed to the repository.
4. Generated claims must distinguish verified facts, model inference and unresolved information.
5. Destructive operations should be logged before execution when the harness owns the operation.
6. Production systems and production networks are outside this repository's implied authority.

## 4. Data authority

- SQLite is runtime state, not canonical Git history.
- JSON/Markdown are canonical auditable interchange formats.
- Binary presentation/PDF artifacts may be stored in GitHub when useful, but their source metadata must remain in JSON/Markdown.
- Every presentation artifact must reference its source task and source research artifact.
- Every daily report must be reconstructable from stored activity/task records.

## 5. Agent handoff contract

Research -> Presentation handoff requires:

- task ID
- research status
- facts / findings
- source references where available
- unresolved items
- conclusion
- artifact path

Activity -> Daily Report handoff requires:

- timestamp
- task ID if applicable
- agent ID
- action
- result/status
- artifact references if applicable

## 6. Truthfulness rules

Agents must not invent:

- sources
- URLs
- test results
- Git commit SHAs
- task completion
- human approvals
- external facts presented as verified

If a required tool/model/search backend is unavailable, record the limitation explicitly.

## 7. Change discipline

- Keep implementation and specification aligned.
- Add tests for state transitions, persistence and artifact contracts when changing harness behavior.
- Prefer small modules with explicit interfaces.
- Keep cloud-provider-specific code behind adapters.
- Local inference must remain a supported first-class path.
