# Diagnostic Multi-Lane Convergence

## Purpose

Keep collector development parallel while preventing repeated conflicts in shared authority and runtime wiring files.

## Lane ownership

Collector lanes own only their capability-specific collector modules, tests, and narrow documentation.

The convergence lane owns shared changes to:
- `src/three_agent/diagnostics/runtime_registry.py`
- `src/three_agent/task_contract.py`
- `src/three_agent/capability_authority.py`
- `src/three_agent/capability_invocation_adapter.py`
- shared evidence primitive registration when needed
- promotion / burn-down integration tests

## Merge gates

A collector may enter convergence only when:
1. fixed argv / no-shell behavior is covered by tests;
2. network access is `none` unless a separately reviewed capability explicitly requires otherwise;
3. effect remains `read` for evidence collectors;
4. missing local evidence is not converted into a remote-service/root-cause claim;
5. no credential or user-content extraction is introduced;
6. focused collector tests pass under the repository test runner.

Convergence then adds exact authority/resource/effect contracts and capability bindings, followed by exact-head CI and measured burn-down deltas.
