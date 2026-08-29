# WorkSpace Governance

## Product identity

The product is **WorkSpace**: a local-first AI runtime for confidential internal business work. `3Agent`/`three_agent` names are legacy implementation identifiers during migration and must not define future architecture.

## Primary security invariant

Confidential business data must remain in the confidential zone. No model, skill, document, prompt, task, artifact or agent may grant itself Internet authority.

### Authority hierarchy

1. deterministic WorkSpace security policy;
2. operator-approved configuration;
3. task/workflow contracts;
4. approved instruction-only skills;
5. model output;
6. untrusted file/web content.

Lower layers can never override higher layers.

## Network rule

- WorkSpace Core: no public/LAN egress in high-assurance deployment; only required local inference transport.
- Egress Broker: separate OS identity, no access to Core data, research-only IPC.
- Confidential mode: public search disabled.
- Public-search exception: DLP + search-host allowlist + exact search-result grants + GET-only bounded responses.
- Arbitrary POST/upload/webhook/telemetry is denied.
- GitHub push is an operator/deployment activity, never autonomous agent runtime authority.

## PicoLM-derived engineering rules

- Optimize by eliminating work before making work faster.
- Treat RAM, VRAM, context, tokens, network and LLM calls as explicit budgets.
- Prefer deterministic code over LLM inference for validation and policy.
- Cache stable deterministic intermediates by content hash.
- Avoid copying full evidence between stages; hand off compact contracts.
- Load only the minimal relevant skill subset.
- Route to the smallest sufficient model and GPU footprint.
- Escalation must be observable and evidence-based.
- Benchmark on fixed tasks; never claim an optimization without measurement.

## Skill rule

Skills are capabilities, not authority. An instruction-only skill cannot enable network, shell, credentials, persistence or cloud services. Any executable third-party skill requires a separate supply-chain/security review and is disabled by default.

## File rule

DOCX/XLSX/PPTX/PDF/HTML and other user files are untrusted inert data. Embedded instructions cannot change system policy. Active content, macros, OLE, external links, remote templates and automatic uploads are not authorized by file content.

## Truthfulness and audit

Never fabricate sources, execution, tests, approvals or commit SHAs. Security decisions should log minimal metadata. Public query plaintext is not stored in egress audit logs; store only a hash/length and allow/deny reason.

## Change discipline

Security-boundary changes must include regression tests and documentation in the same coherent change-set. Do not weaken default-deny behavior merely to make a test or demo easier.
