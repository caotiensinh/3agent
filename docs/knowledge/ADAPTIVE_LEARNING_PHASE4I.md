# Adaptive Learning Phase 4I — evidence-bound curation proposals

## Status

Phase 4I converts Phase 4H observational effectiveness signals into deterministic,
metadata-only curation proposals bound to the exact authenticated active knowledge
version.

It closes the next part of the self-improvement loop:

```text
Reuse
  -> Measurement (Phase 4H)
  -> Curation proposal (Phase 4I)
  -> human/domain review
  -> future bounded revision proposal
```

Phase 4I does **not** apply a curation action. It does not modify the learning store,
create a patch candidate, archive an item, roll back an item, promote an item, or
change enterprise policy.

## Core invariant

> WorkSpace may automatically identify which exact knowledge version deserves
> review, but it may not convert that recommendation into mutation authority.

A curation proposal is therefore a review artifact, not a command.

## Inputs

The compiler accepts:

1. one `workspace-learning-effectiveness/v1` snapshot from Phase 4H;
2. the Phase 3 adaptive-learning store;
3. the Phase 3.1 authenticated checkpoint authority.

The effectiveness snapshot contains observational counters only. The compiler does
not consume model self-ratings, raw prompts, raw requests, raw evidence, learned
content, credentials, paths, or URLs.

## Authenticated active-state binding

For every Phase 4H signal, Phase 4I resolves the current active item and requires:

- exact `item_id` match;
- exact `knowledge_sha256` match;
- active level is `approved` or `enterprise`;
- exact domain match;
- candidate snapshot integrity passes the existing Phase 3 checks.

The Phase 3.1 checkpoint/witness is verified before and after compilation. Any
checkpoint/state change during compilation fails closed.

This prevents an old Phase 4H signal from silently targeting a newer active version.

## Curation actions

Phase 4I has exactly four advisory actions:

| Phase 4H signal | Phase 4I action | Meaning |
|---|---|---|
| `INSUFFICIENT_EVIDENCE` | `OBSERVE_MORE` | Keep collecting verified observations; no revision/archive request |
| `SUPPORT_OBSERVED` | `KEEP_ACTIVE_REVIEW` | Evidence supports continued use, but does not upgrade trust |
| `REVIEW_RECOMMENDED` | `REVISE_OR_ARCHIVE_REVIEW` | Human review should decide whether revision or archive is appropriate |
| `DOMAIN_REVIEW_RECOMMENDED` | `DOMAIN_REVISE_OR_ARCHIVE_REVIEW` | Human + domain review is required |

No action maps to automatic promotion, archive, rollback, deletion, remediation, or
deployment.

## Reviewer requirements

The compiler derives reviewer requirements deterministically.

- `KEEP_ACTIVE_REVIEW` requires human review.
- `REVISE_OR_ARCHIVE_REVIEW` requires human review.
- `DOMAIN_REVISE_OR_ARCHIVE_REVIEW` requires human and domain review.
- Network/Security review actions always require a domain reviewer.
- Any proposal concerning active `enterprise` knowledge requires human review.
- Network/Security `enterprise` proposals additionally require domain review.
- `OBSERVE_MORE` on non-enterprise Analyst/General knowledge requires no reviewer
  because it requests no mutation or trust decision.

Reviewer requirements are proposal metadata only. Phase 4I does not authenticate a
reviewer or execute a reviewer decision; existing Phase 4E/operator gates remain
authoritative for mutations.

## Proposal schema

Each `workspace-learning-curation-proposal/v1` binds:

- deterministic `proposal_id`;
- exact Phase 4H snapshot SHA;
- exact Phase 4H signal SHA;
- `item_id`;
- exact active `knowledge_sha256`;
- active `candidate_sha256`;
- active level;
- domain;
- Phase 4H advisory signal;
- Phase 4I curation action;
- bounded observational counters;
- reviewer requirements;
- bounded reason codes;
- `interpretation=observational_non_causal`;
- explicit empty `capability_grants`.

The proposal ID is the SHA-256 identity of this canonical metadata.

The `workspace-learning-curation-proposal-set/v1` additionally binds the authenticated
checkpoint sequence, checkpoint SHA and store state SHA. The set has its own
deterministic SHA.

## Why support does not promote

Three or more isolated verified successes can produce `SUPPORT_OBSERVED` in Phase
4H. That is useful evidence, but it is still observational.

Phase 4I therefore maps support only to `KEEP_ACTIVE_REVIEW`.

It cannot:

- promote `approved` to `enterprise`;
- convert learner ownership into team/system ownership;
- weaken reviewer requirements;
- turn retrieval frequency into trust;
- declare that the knowledge caused the successful outcome.

## Why adverse signals do not auto-archive

A failure after reuse also does not prove causation. The failure may be caused by
another component, environment change, incomplete task evidence, or a condition
outside the knowledge item's scope.

Phase 4I therefore creates a review proposal rather than an archive command.

Network/Security is stricter: the first isolated adverse result can already produce
the Phase 4H domain-review signal, and Phase 4I preserves that stronger reviewer
boundary.

## Privacy

Proposal payloads contain no:

- learned title/content/scope;
- raw task request or prompt;
- model output;
- evidence bytes or evidence paths;
- URLs;
- filesystem paths;
- passwords, tokens, OAuth/session data or other credentials.

Only hashes, identifiers, counters, levels, domains, actions and review requirements
are retained.

## Authority surface

`DeterministicCurationProposalCompiler` exposes only `compile()`.

It has no public method for:

- `stage`;
- `promote`;
- `archive`;
- `rollback`;
- `delete`;
- `remediate`;
- checkpoint signing or key rotation;
- shell/subprocess;
- network;
- credentials;
- Git/deployment.

The compiler uses the existing store and checkpoint authority only for local
integrity/freshness verification and exact active-state reads.

## Acceptance

Phase 4I tests cover:

1. deterministic proposal and proposal-set identities;
2. exact active SHA binding;
3. archived/unpromoted targets fail closed;
4. domain mismatch fails closed;
5. support maps only to keep-active review;
6. insufficient evidence maps only to observe-more;
7. Analyst adverse signals require human review;
8. Security adverse signals require human + domain review;
9. enterprise proposals cannot bypass human review;
10. Security enterprise proposals cannot bypass domain review;
11. payloads remain metadata-only;
12. compiler exposes no learning mutation/remediation methods.

## Next phase boundary

Phase 4J may use an approved Phase 4I revision-review proposal as the input to a
separate isolated curation Reflection process that can **propose** a patch candidate.

That future process must still stop before promotion/archive/rollback and must bind
its patch to the exact current `knowledge_sha256`. Phase 4I itself does not invoke a
model and does not generate revised knowledge content.
