# Public Skill Security Review Addendum — 2026-08-28

Status: APPROVED FOR THE SPECIFIC LOCAL ADAPTATIONS LISTED BELOW

This addendum records the supply-chain and information-leak review performed before adding two Research Agent skills. The adopted files are project-written instruction-only adaptations. No third-party executable, installer, browser session, API client, hook, package, or persistent memory implementation is vendored.

## Admission decision

Enabled adaptations:

- `research-source-credibility`
- `research-web-trust`

Both are restricted to Agent `research` and must declare:

- `instruction_only=true`
- `network_access=false`
- `credential_access=false`
- `persistent_self_modify=false`
- `external_code_vendored=false`

Their exact local `SKILL.md` content is SHA-256 pinned in `skills/registry.json`.

## Reviewed sources

### PracticalSwan/agent-skills

Reviewed commit:

`4d12f29cb1993baf049fac617754d9ec8f2ca390`

Useful concepts:

- explicit source/provenance maintenance;
- narrow skill ownership and scope;
- preference for audited, pinned source material instead of automatic latest-version trust.

Risk decision:

The upstream catalog contains many unrelated skills and external-client integrations. 3Agent does not import the catalog, its sync tooling, or external clients. Only general source-quality/provenance ideas are adapted in new project-owned wording.

### xcrrr/claude-skills

Reviewed commit:

`145342ceff6318d2f5ffe8f95473fecc8b27d1e9`

Useful concepts:

- source authority and relevance checks;
- explicit dataset/source provenance;
- leakage awareness and quality documentation.

Risk decision:

No upstream runtime, package, data collector, or command sequence is imported. Only generic source-credibility methodology is adapted.

### vercel-labs/agent-browser

Reviewed commit:

`fbd046c23a2c1156891bda294aaaee715c23b3f1`

Reviewed reference:

`skill-data/core/references/trust-boundaries.md`

License observed in the upstream repository: Apache-2.0.

Useful concepts:

- browser/page content is untrusted data rather than agent instruction;
- secrets and authenticated state require a separate trust boundary;
- network containment must not be confused with a complete host security boundary.

Risk decision:

3Agent does not adopt the browser runtime, authenticated browser state, HAR capture, session replay, or browser automation. Only the trust-boundary concept is rewritten as an instruction-only Research Agent skill.

### getsentry/skills

Reviewed security-scanner commit:

`0b8707a0f7ac86d3a2f0df6f8100c6f0bbd676ae`

License observed in the upstream repository: Apache-2.0.

Useful defensive concepts:

- reject symlinks escaping a reviewed skill directory;
- detect executable hooks and command expansion;
- detect test/package side-effect surfaces;
- detect hidden Unicode instruction smuggling;
- treat bundled executable resources as a higher-risk trust tier.

Risk decision:

The upstream scanner is not copied or executed. 3Agent implements its own smaller standard-library admission checks appropriate to its instruction-only skill format.

## Explicitly rejected runtime classes

The following classes remain outside the approved 3Agent baseline unless separately reviewed later:

- hosted search/research APIs that receive task text through third-party credentials;
- browser automation operating in authenticated user sessions;
- skills that download or execute code during use;
- skills with post-install, hook, or automatic test-discovery execution;
- skills that read credential stores or environment secrets;
- skills that write task-specific lessons into reusable long-lived skill memory;
- skills that can modify their own instructions or permissions.

## New deterministic controls

This change-set adds or strengthens:

1. Registry-wide skill audit.
2. SHA-256 integrity enforcement.
3. Agent-scope enforcement.
4. Explicit zero-authority declarations for network, credentials, persistence, and vendored executable code.
5. Rejection of unregistered skill directories.
6. Rejection of extra files or symlinks inside instruction-only skill directories.
7. Rejection of dangerous executable command blocks.
8. Rejection of external runtime URLs in enabled skill bodies.
9. Rejection of secret-looking literals and sensitive credential-path references.
10. Rejection of bidirectional/Unicode-tag instruction smuggling.
11. CI execution of the skill-security admission scan.

## Internet-boundary hardening

The same security review identified a separate SSRF/information-leak risk in the Research Agent Internet Gateway. The change-set therefore also:

- permits only HTTP/HTTPS;
- rejects credentials embedded in URLs;
- rejects localhost, `.local`, private, loopback, link-local, reserved, and otherwise non-global destinations;
- resolves destinations before requests and re-validates every redirect target;
- disables automatic redirects and processes them under the same policy;
- limits response size;
- removes query strings and credentials from audit URLs;
- redacts common secret/PII patterns from command audit records;
- redacts common secret/PII patterns from outbound research search queries.

These are application-level controls. They do not replace host firewall or container/network-namespace egress enforcement.

## Re-review rule

Any modification to an enabled `SKILL.md`, provenance source, authority declaration, or review decision invalidates the previous admission until the registry hash/review is deliberately updated. Upstream `main` or `latest` is never trusted automatically.
