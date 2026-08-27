# Test Mode Full-Access Boundary

## Decision

The designated dual-RTX-5090 workstation is a test machine. V1 therefore supports:

`TEST_MODE_FULL_ACCESS=true`

This setting is intended to remove unnecessary development friction while preserving enough structure to harden the same system later.

## Capabilities in test mode

All three agents can be authorized for:

- filesystem read/write
- command execution
- local Git
- GitHub operations through configured tooling
- outbound Internet through the project Internet Gateway
- local LLM access

## Guardrails retained even in test mode

- secrets are never committed
- activity is attributable
- gateway access is logged
- generated evidence tracks task/agent identity
- test authority does not imply production authority
- the system must not claim unperformed tests/research

## Threat model status

V1 is **development convenience mode**, not a security sandbox. The Python gateway provides architectural centralization and auditability, but it cannot stop arbitrary separately executed software from using the network or shell.

Production hardening requires OS/container enforcement and least privilege.
