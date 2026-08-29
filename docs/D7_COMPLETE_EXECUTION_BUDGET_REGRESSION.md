# D7 Regression: Complete Execution Budget Pinning

The deterministic regression corpus pins the complete TaskContract execution envelope, not only model retry/escalation limits.

For accepted regression cases, replay may assert:

- `max_steps`
- `max_tool_calls`
- `max_retries`
- `max_escalations`
- `max_wall_time_ms`

These values come directly from the production `TaskContractCompiler`. Changing any pinned limit changes the regression corpus outcome and therefore the repository-owned regression evidence used by the promotion gate.

This closes a gap exposed after D0-04: a future optimization must not silently increase step/tool/wall-time authority while preserving only retry/escalation parity.

The golden corpus payload is deliberately not rewritten; its legacy shape/hash compatibility remains intact. The regression corpus is the versioned location for the expanded execution-boundary expectations.
