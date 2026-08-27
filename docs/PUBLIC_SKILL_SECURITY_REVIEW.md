# Public Skill Security Review

Review date: 2026-08-28 (Asia/Tokyo)

## Decision policy

No public Agent Skill, prompt pack, script, browser action, MCP helper, or reusable agent instruction may be enabled in 3Agent merely because it is useful or public.

Before adoption, the review must answer:

1. What exact upstream repository and commit were inspected?
2. Does the candidate read local files beyond the task scope?
3. Does it read environment variables, credentials, browser sessions, cookies, SSH/Git configuration, or tokens?
4. Does it send task/user content to any external endpoint, telemetry service, API, browser action, or cloud model?
5. Does it execute shell/subprocess commands or download additional code at runtime?
6. Does it persist task-specific content into a reusable skill, memory, lesson log, cache, or repository file?
7. Can instructions from fetched web content modify the skill or its future behavior?
8. Is executable code vendored into 3Agent?
9. Is the license compatible with the way we use the material?
10. Can the useful behavior be reimplemented as local instruction-only guidance with less authority?

3Agent defaults to the lower-authority option. Current approved skills are project-written adaptations of reviewed ideas, not blind copies of third-party runtimes.

## Reviewed public projects

### 1. Yila-AI/awesome-research-skills — APPROVED FOR CONCEPT ADAPTATION ONLY

- Repository: `Yila-AI/awesome-research-skills`
- Reviewed upstream commit: `423803c3afd37d775e075a03934cbb37e30afe2d`
- Primary reviewed skill: `skills/science-research-writing/SKILL.md`
- Reviewed helper: `skills/science-research-writing/scripts/check_draft_invariants.py`
- Upstream license noted in repository metadata/CITATION: Apache-2.0.

Useful ideas adopted in our own words:

- evidence ledger / provenance discipline;
- preserve numbers, scope, uncertainty, limitations, and claim strength;
- never invent citations or unsupported scientific content;
- deterministic checks are necessary but not sufficient for semantic review.

Security findings:

- The reviewed `check_draft_invariants.py` uses local parsing/regex/JSON/path operations and contains no HTTP client, telemetry, credential lookup, token handling, or upload path.
- The skill instructs the agent to operate on supplied research materials. That is acceptable only inside 3Agent's local evidence boundary; supplied materials must not be forwarded to an upstream service by the skill itself.
- We do **not** vendor or auto-run the upstream script. The applicable principles are reimplemented as instruction-only local skills and deterministic project code.

Decision: **APPROVE CONCEPTS, DO NOT IMPORT RUNTIME CODE.**

### 2. Toadoum/ai-research-skill — PARTIAL APPROVAL; SELF-MODIFYING MEMORY REJECTED

- Repository: `Toadoum/ai-research-skill`
- Reviewed commit: `bc98310bc2dc5c600f89f60099eed6cb950f6de1`
- Reviewed file: `SKILL.md`
- Reviewed scripts directory listing: `scripts/log_lesson.py`, `scripts/new_experiment.py`
- Skill frontmatter declares MIT.

Useful ideas adopted:

- cite only sources actually inspected;
- treat suspiciously strong results as a reason to check leakage/contamination;
- preserve reproducibility context and evidence;
- do not hide negative/null results.

Rejected behavior:

- The upstream skill includes a recursive `LESSONS.md` self-improvement loop that records triggers, mistakes, fixes, evidence pointers, file paths/run IDs, and corrections.
- Persisting those task-specific details into a reusable skill directory can retain confidential project names, internal paths, experiment identifiers, or user corrections beyond the original task.
- If that skill directory is later committed or synchronized, the persistent lesson log becomes a realistic information-leak path.
- Automatically promoting repeated lessons into permanent instructions also creates a prompt-injection/persistence surface if untrusted web content influences the lesson.

Decision: **APPROVE selected research-discipline concepts only. DO NOT ENABLE upstream lesson persistence, self-modification, or scripts.**

### 3. browsing-skills/browsing-skills — NOT APPROVED FOR 3AGENT BASELINE

- Repository: `browsing-skills/browsing-skills`
- Reviewed public code/search snapshot commit: `07855b500d210751fa4d5c54bc553bf30581d345`
- Project design uses browser actions such as `page.evaluate()` and Chrome Bridge action execution for website-specific automation.

Security findings:

- Browser automation can run in an authenticated browser context and therefore may have access to session-derived data that is outside a research task's intended scope.
- Website-specific actions can submit requests or mutate accounts, not merely read public information.
- Giving Research Agent a browser session would bypass the current narrow `InternetGateway` fetch boundary and greatly expand the set of data that could leave the machine.
- It also expands prompt-injection exposure because arbitrary page content and active browser state become part of the tool surface.

Decision: **REJECT for current baseline.** Public-web research stays behind the 3Agent `InternetGateway`; no authenticated browser session is granted to Agent 1.

### 4. anthropics/skills — FORMAT/REFERENCE ONLY

- Repository: `anthropics/skills`
- Public snapshot inspected around commit `3b3fad96af16a10759d930941b4520ba0c40edae` through GitHub code search.
- The repository demonstrates the `SKILL.md` structure and includes both open-source examples and document skills with different/source-available licensing terms.

Security/licensing findings:

- The format itself is useful, but installing an entire third-party marketplace/plugin would add files and possibly executable helpers outside the narrow 3Agent review boundary.
- Because licensing differs by subfolder, we do not copy document-skill implementations wholesale.

Decision: **USE THE SIMPLE SKILL MANIFEST PATTERN ONLY; DO NOT AUTO-INSTALL THE MARKETPLACE OR COPY MIXED-LICENSE RUNTIMES.**

## Approved 3Agent adaptations

The following project-local skills are enabled only as reviewed instruction text:

- `research-evidence-synthesis`
  - derived from evidence-preserving / claim-strength ideas found in Yila-AI and the citation discipline found in Toadoum;
  - no direct network, shell, credential, or persistence authority.

- `research-data-quality`
  - project-specific data cleaning/QA gate using the same evidence-preserving principles;
  - deterministic 3Agent code remains authoritative for `presentation_ready`.

- `presentation-evidence-boundary`
  - project-specific downstream rule: Agent 2 consumes only approved research handoff data and must not invent facts.

- `daily-report-evidence`
  - project-specific rule: Agent 3 reports only recorded tasks/activities/artifacts and may not fabricate progress.

No upstream executable code is currently imported into these four skill folders.

## Mandatory anti-exfiltration controls

An enabled skill must have all of these registry declarations:

```json
{
  "instruction_only": true,
  "network_access": false,
  "credential_access": false,
  "persistent_self_modify": false,
  "external_code_vendored": false,
  "review": "docs/PUBLIC_SKILL_SECURITY_REVIEW.md"
}
```

The loader must fail closed when:

- the review file is missing or escapes the repository root;
- the skill hash changes after review;
- the skill contains a `scripts/` directory;
- the registry grants network, credential, persistent self-modification, or vendored executable authority;
- the skill is requested by an agent outside its approved scope.

## Future review rule

Upstream updates are **not automatically trusted**. A newer commit, release, or rewritten SKILL.md must be reviewed as a new candidate. Do not replace a pinned reviewed concept with `main`/`latest` at runtime.
