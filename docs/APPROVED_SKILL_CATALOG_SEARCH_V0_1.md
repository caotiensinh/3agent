# Approved Skill Catalog Metadata Search V0.1

## Purpose

Add bounded search/filtering to the existing `ApprovedSkillCatalog` without
creating another skill selector, trust model, registry, loader, or authority
surface.

The progression remains:

`audited registry -> compact metadata -> bounded search -> explicit one-skill view`

Search never loads or indexes procedure bodies or reference bodies.

## Canonical boundary

`ApprovedSkillLoader` remains the only production skill trust boundary.

`ApprovedSkillCatalog.search_for_agent(...)` first calls `list_for_agent(...)`.
That operation audits the complete enabled registry before any search result is
returned. Consequently:

- a tampered enabled skill fails the whole search closed even when it would not
  match the query;
- wrong-agent skills never enter the searchable set;
- disabled/unapproved skills never enter the searchable set;
- search cannot bypass review, provenance, integrity, E2 authority, or resource
  validation.

## Searchable metadata

Free-text query terms use deterministic AND matching across compact fields only:

- skill name;
- reviewed frontmatter description;
- optional registry category;
- optional registry domain;
- optional registry tags.

The following structured filters are exact, case-insensitive matches:

- `category`;
- `domain`;
- `risk_class`;
- `enterprise_tier`.

Requested tags use subset matching: every requested tag must be present.

Optional category/domain/tags are exposed only when present in the audited local
registry and pass catalog-side compact metadata validation. Their absence does not
cause a skill to fail admission; it simply cannot match the corresponding filter.

## Bounds

- maximum query length: 240 characters;
- maximum normalized query terms: 32;
- maximum returned results: 16;
- default returned results: 8;
- maximum caller-requested tags: 8;
- maximum registered tags exposed by one skill: 16.

Ordering is inherited from the canonical compact listing and is deterministic by
skill name. The result limit is applied only after all filters match.

## Privacy and prompt-size behavior

Search results are `ApprovedSkillSummary` metadata only. They do not contain:

- procedure body;
- reference text;
- evidence bytes;
- raw prompts or task requests;
- credentials or secrets;
- filesystem contents beyond existing reviewed identifiers.

Body-only text therefore cannot make a skill match a metadata query.

## Authority

Metadata search grants no:

- tool access;
- network access;
- credential access;
- filesystem write;
- production registry write;
- learning promotion;
- execution authority.

Explicit procedure disclosure still requires `view_for_agent`, which reuses
`ApprovedSkillLoader.load_for_agent` and all existing prompt-size limits.

## Fail-closed behavior

Reject:

- invalid/empty agent identity through the existing catalog list boundary;
- result limits outside `1..16`;
- overlong search query;
- non-sequence or excessive tag filters;
- duplicate requested tags;
- malformed optional registry category/domain/risk/tier/tag metadata;
- any registry/skill/reference condition already rejected by the canonical loader.

## Acceptance tests

V0.1 regression coverage proves:

1. query matching over name/description/reviewed metadata only;
2. procedure-body-only text is not searchable;
3. category/domain/risk/tier/tag filters work deterministically;
4. wrong-agent and disabled skills remain invisible;
5. result limit is deterministic;
6. malformed/unbounded caller filters fail closed;
7. malformed optional registry metadata fails closed;
8. existing list/view progressive disclosure remains backward compatible.
