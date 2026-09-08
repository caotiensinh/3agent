# Approved Skill Catalog Telemetry v0.1

## Purpose

This slice closes the catalog-observability gap without creating another skill
registry, loader, selector, database, or runtime authority surface.

The implementation reuses:

- `ApprovedSkillCatalog` for canonical list/search/view disclosure;
- `ApprovedSkillLoader` for production integrity and agent scope;
- `TaskStore.activities` as the existing audit-safe activity ledger;
- `record_learning_reuse(...)` as the authoritative exact-version reuse receipt.

Telemetry is observational only. It never grants tools, network access,
credentials, filesystem mutation, learning promotion, or execution authority.

## Events

The schema is:

`workspace-approved-skill-catalog-telemetry/v1`

Actions:

- `skill_catalog_listed`
- `skill_catalog_viewed`
- `skill_catalog_selected`

Every event is task/agent bound through the existing activity ledger when a task
id is available.

## List and search telemetry

Catalog list/search can expose up to 16 metadata rows. Persisting every name and
SHA could exceed the existing activity-details budget, so list/search events
record only:

- `surface`: `list` or `search`;
- `count`;
- `skill_set_sha256`: deterministic SHA-256 over the sorted exact production
  `name + production_sha256` identities.

The raw query is never logged. Descriptions, categories, tags, domains, skill
procedure bodies, prompt text, references, credentials, and task request content
are never written into the telemetry payload.

The set digest is observational evidence, not an integrity authority. Production
integrity continues to come only from the canonical loader/registry checks.

## View telemetry

A successful explicit catalog view records:

- `surface=view`;
- count;
- exact production skill name;
- exact production SHA-256.

The event is emitted only after `ApprovedSkillCatalog.view_for_agent(...)`
returns successfully. A wrong-agent, disabled, unapproved, or tampered skill
therefore emits no successful view observation.

## Runtime selection telemetry

`PreparedLearningReuse` carries the exact canonical production skill name next
to the already-reviewed production instruction block. The runtime does not parse
or infer the name from prompt or skill-body text.

For materialized learned-skill reuse:

1. adaptive retrieval selects exact active learning versions;
2. canonical production materialization binding is verified;
3. `ApprovedSkillCatalog.view_for_agent(...)` loads the reviewed production body;
4. exact production telemetry identity is resolved from the audited registry;
5. `skill_catalog_viewed` is attempted;
6. `record_learning_reuse(...)` writes the authoritative task/version reuse receipt;
7. only after step 6 succeeds is `skill_catalog_selected` attempted;
8. synthesis receives the previously reviewed production instruction block.

This ordering prevents a selection observation from claiming reuse before the
existing effectiveness/audit receipt accepts the exact version.

## Failure semantics

Integrity and identity resolution remain fail closed. If the production registry
or exact skill identity cannot be audited, learned-skill reuse is withheld.

Telemetry persistence is different: it is a secondary observational sink and
must not become a new runtime authority gate. Once canonical integrity and the
authoritative reuse receipt have succeeded, an activity-ledger write failure is
reported only as a best-effort metadata-only warning:

`skill_catalog_telemetry_warning`

The warning contains only stage and exception type. It never includes prompt,
request, skill, or evidence content.

## Bounds

- list/search identity input: maximum 16, matching bounded catalog search;
- view/selected exact identities: maximum 2, matching canonical production skill
  load ceiling;
- activity details: explicitly capped at 800 characters before persistence;
- list/search payload size is independent of name length because identities are
  represented by count plus one fixed-size set digest.

## Privacy contract

Telemetry MUST NOT contain:

- raw user request or compiled prompt;
- list/search query;
- skill description, tags, category, or domain text;
- `SKILL.md` procedure/body;
- reviewed reference bodies;
- candidate/adaptive-learning content;
- evidence bytes;
- credentials, secret values, or environment values;
- model output.

## Non-goals

This slice does not:

- change catalog search ranking;
- change skill load limits;
- create automatic skill activation;
- add new effectiveness thresholds;
- alter promotion/materialization/supersession authority;
- implement stale-skill or quarantine policy;
- create a telemetry database or external metrics exporter.

## Test contract

Regression coverage proves:

- list emits count plus deterministic set digest without content;
- the maximum 16-row list remains within the existing activity-details budget;
- search never logs its query or matched description;
- successful view records exact production identity only;
- failed/wrong-agent view records no successful view event;
- runtime identity resolution uses audited registry state rather than optional
  search metadata;
- selected event is task/agent bound and metadata-only;
- materialized runtime reuse carries the exact production skill name and
  unmaterialized skills carry none.
