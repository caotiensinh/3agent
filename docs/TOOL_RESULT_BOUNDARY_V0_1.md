# Tool Result Boundary v0.1

Status: bounded output projection for reviewed tool/adaptor results.

## Goal

Prevent an authorized tool call from returning an unbounded or unnecessarily credential-bearing text payload into the WorkSpace runtime/model/UI path.

This is an output/result boundary. It is not an authority source, evidence store, process sandbox, or replacement for tool-specific collectors.

## First production consumer

`src/three_agent/office_it_tools.py::execute_local_read(...)`

Before v0.1 the local Windows collectors used bounded event-count and execution-time inputs but returned the entire captured `stdout` and `stderr` strings. v0.1 projects both fields through `bound_process_output(...)` before they leave the collector API.

## Default limits

- `stdout`: 64 KiB UTF-8 returned text
- `stderr`: 8 KiB UTF-8 returned text
- helper hard maximum for one configured field: 256 KiB

Truncation is UTF-8 safe and never returns a partial code point.

These are projection limits. The current `subprocess.run(capture_output=True)` collector can still allocate the complete child output in host memory before projection. A future streaming adapter may enforce process-I/O memory bounds when the generic invocation contract is implemented. This v0.1 document must not be used to claim that capture memory is bounded.

## Disclosure handling

The returned projection removes unsafe ASCII control characters except newline, carriage return, and tab, and redacts common credential literal forms before truncation:

- password/passwd/pwd assignments;
- token/secret/API-key assignments;
- Authorization assignments;
- Bearer and Basic authorization values;
- PEM private-key blocks.

This is defense in depth, not a general secret-classification engine. Tool-specific sensitive-output policy and downstream UI/model minimization still apply.

## Audit metadata

For each raw text field the boundary records:

- raw UTF-8 byte count;
- SHA-256 of the exact raw UTF-8 representation;
- returned UTF-8 byte count;
- truncation flag;
- redaction count;
- schema version.

The raw digest is computed before redaction/truncation so an external trusted evidence store can later prove which original output was observed without requiring the model-visible projection to contain the original bytes.

The v0.1 boundary itself does not persist those original bytes and the digest does not make the returned text canonical runtime Evidence.

## Security invariants

1. Output size limits do not grant execution authority.
2. The boundary accepts no shell command, target, credential, approval, or filesystem scope.
3. Truncation/redaction metadata cannot unlock a workflow dependency by itself.
4. Raw SHA-256 is an audit identity only until a canonical Evidence adapter binds it to task/node/authority identity.
5. A tool execution still requires the existing `TaskCapabilityAuthority` check before invocation.
6. A future generic adapter must apply the boundary to every model/UI-facing result path, including error/fallback paths.
7. Authorization refusal and transport ambiguity must remain distinct from ordinary tool errors; result projection must not convert either into a fallback execution decision.

## Regression coverage

`tests/test_tool_result_boundary.py` covers:

- common credential redaction;
- raw digest/byte-count preservation;
- UTF-8-safe byte bounds;
- private-key redaction;
- independent stdout/stderr limits;
- invalid limit fail-closed behavior.

`tests/test_office_it_result_boundary.py` drives the real Office IT collector caller with a mocked subprocess boundary and proves:

- the production collector actually invokes result bounding;
- large stdout/stderr do not leave the API unbounded;
- common credential literals are not returned;
- exact raw digests remain available in audit metadata;
- the existing fixed argv + `shell=False` behavior is preserved.

## Next convergence steps

1. Add result/evidence requirements to the canonical runtime-wide CapabilityDescriptor.
2. Make the generic capability adapter enforce descriptor-specific limits within the platform hard maximum.
3. Normalize successful and failed invocations into canonical `ExecutionObservation`.
4. Bind original/raw output identity to content-addressed Evidence where policy requires retention.
5. Add long-running streaming adapters that bound child-process I/O before complete in-memory capture.
6. Extend the same boundary to network, Linux, camera, provider, plugin, and MCP adapters.
