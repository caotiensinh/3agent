# Presentation Agent V1 Acceptance

Agent 2 is accepted when all items below pass on the same candidate SHA.

## Contract tests

- Agent 1 handoff fact IDs remain stable.
- Inferences remain inference-class evidence.
- Blocked handoff cannot produce a presentation.
- Unknown claim IDs hard-fail.
- Inference/proposal-only decks hard-fail; at least one verified fact must be selected.
- Duplicate slide titles hard-fail.
- Visible factual text exactly matches evidence catalog text.
- Sources and limitations are appended deterministically.
- Cross-day handoff lookup selects the newest date.
- Dry-run output is deterministic and does not claim LLM planning.
- PPTX saves and reopens.
- Every PPTX slide has a PowerPoint title placeholder.
- Speaker notes preserve evidence source IDs.

## Repository regression

- Python 3.11 harness CI PASS.
- Python 3.12 harness CI PASS.
- Existing Research Agent tests PASS.
- Existing Daily Report Agent tests PASS.
- Installer contract CI PASS.

## Live workstation acceptance

On the Ubuntu RTX 5090 test machine:

1. Agent 1 produces `presentation_ready=true`.
2. `3agent presentation TASK-ID --live --language ja --format pptx` succeeds.
3. Generated JSON shows valid handoff/raw-research lineage.
4. Generated PPTX opens in PowerPoint/LibreOffice.
5. Sources and unresolved/conflict appendices match the source handoff.
6. No unknown or unsourced factual statement is introduced by Agent 2.

GitHub-hosted CI validates deterministic logic/rendering; the local RTX workstation validates the real Ollama planning path.
