# Adaptive Learning Phase 4E — Authenticated Operator Promotion Boundary

## Purpose

Phase 4E closes the authorization gap between deterministic learning validation and the existing checkpointed operator mutation path.

It does **not** create autonomous learning authority. A candidate can move from `validated` to `approved`, or from `approved` to `enterprise`, only through a local WorkSpace session plus explicit local reviewer authorization. The actual store mutation still runs through the existing `LearningOperatorGateway`, checkpoint journal and independent trusted-head witness.

## Trust boundary

```text
local / approved-external login
        |
        v
WorkSpace local session
(IP-bound, expiring, enabled-user checked)
        |
        v
stable local principal: workspace-user:<user_id>
        |
        +----> reviewer promotion-level grant
        |
        +----> explicit domain-review grant
        |
        v
Phase 4E ceremony
(candidate + receipt + exact checkpoint state)
        |
        v
PromotionBoundCheckpointAuthority
(expected state checked inside existing mutation lock)
        |
        v
existing LearningOperatorGateway
        |
        v
AdaptiveLearningStore.promote
        |
        v
checkpoint journal + independent head witness advance
```

External Google/GitHub/LINE identity is never promotion authorization. External login must first resolve to an operator-approved local WorkSpace user. Phase 4E then sees only the same local session/principal semantics as local password login.

## Reviewer authorization

`LearningReviewerAuthorizationPolicy` is an explicit local allowlist keyed by stable WorkSpace `user_id`.

A grant has two independent dimensions:

- `allowed_levels`: which promotion ceremonies this principal may conduct (`approved`, `enterprise`);
- `reviewer_domains`: domains for which this principal may satisfy domain-review requirements.

WorkSpace `admin` role is **not** converted into learning reviewer authority. The current account RBAC contract defines `admin` as account-management authority, so Phase 4E does not silently expand it.

Display name, department, title and OAuth provider are also never authorization inputs.

## Human and domain reviewer identity

The human reviewer identity written into the promotion receipt is derived server-side from the authenticated local principal:

```text
workspace-user:<user_id>
```

Caller-supplied reviewer IDs are assertions only. If an incoming receipt names a different `human_reviewer_id` or `domain_reviewer_id`, Phase 4E rejects it.

For a domain that the authenticated principal is explicitly entitled to review, Phase 4E binds `domain_reviewer_id` to the same authenticated local principal. Network/security promotion therefore cannot satisfy `AdaptiveLearningPolicy` with an arbitrary reviewer string.

The existing deterministic `AdaptiveLearningPolicy` remains authoritative for candidate/receipt lineage, validation checks, risk policy, human-review requirements and monotonic promotion level transitions.

## One-shot checkpoint binding

`LearningPromotionCeremony` captures only non-secret metadata:

- candidate ID and hash;
- candidate domain;
- target level;
- authenticated actor ID;
- exact checkpoint sequence;
- exact learning-store state hash.

The ceremony is not a bearer credential. `promote()` re-authenticates the WorkSpace session and re-runs reviewer authorization.

`PromotionBoundCheckpointAuthority` layers one narrow expected-state check on the existing checkpoint authority. The expected sequence/state is consumed by `_verify_store()` while the inherited mutation lock is held and **before** `AdaptiveLearningStore.promote()` runs. If another checkpointed operation changed learning state after preparation, promotion fails closed before the target mutation.

After a successful promotion the checkpoint advances, so replaying the same ceremony fails on the expected checkpoint sequence/state.

## Metadata-only result

The Phase 4E result contains only:

- result schema/status;
- candidate ID/hash;
- target level;
- stable local actor ID;
- validation-receipt hash;
- resulting checkpoint sequence/state hash.

It does not return candidate content, session tokens, passwords, OAuth subjects/tokens, checkpoint keys, database paths, journal paths or witness paths.

## Failure behavior

Promotion fails before learning mutation when any of these boundaries fail:

- missing/expired/wrong-IP/disabled-user session;
- no explicit reviewer grant;
- target level not granted;
- network/security domain review not explicitly granted;
- ceremony principal/candidate/state mismatch;
- receipt candidate/hash mismatch;
- reviewer identity mismatch;
- stale checkpoint sequence/state;
- existing checkpoint/witness/store integrity verification;
- existing deterministic promotion policy.

No failure is converted into an automatic retry with weaker authority.

## Production wiring

Phase 4E introduces the authenticated promotion authority primitive and its acceptance tests. It does **not** add a browser/API endpoint that exposes promotion automatically, and it does not alter Phase 4D read-only Research retrieval.

A future operator UI/API may call this service only if it preserves the same server-side session resolution, explicit reviewer policy, exact-state ceremony and checkpointed gateway boundary.

## Non-goals

Phase 4E does not add:

- a background learner or scheduler;
- automatic promotion/adoption;
- automatic remediation;
- model-weight training or fine-tuning;
- embeddings or vector DB;
- network, shell, subprocess, Git or deployment authority;
- checkpoint key generation/bootstrap/rotation changes;
- a Windows checkpoint key-file provider;
- a second operator gateway or alternate store mutation API;
- OAuth-provider authorization;
- implicit domain-review power for WorkSpace administrators.

## Acceptance

Tests must demonstrate:

1. explicitly granted local principals can conduct a valid checkpointed promotion;
2. `admin` alone has no learning reviewer authority;
3. domain review is explicit;
4. wrong-IP and disabled-user sessions fail without learning mutation;
5. forged receipt reviewer IDs fail without learning mutation;
6. stale ceremony state fails inside the checkpoint boundary before target mutation;
7. successful ceremony replay fails after checkpoint advancement;
8. an approved external-login session resolves to the same local principal/authorization semantics;
9. output remains metadata-only.

The same exact PR head must pass `harness-ci`, `installer-ci`, `portable-deploy-ci` and `windows-deploy-ci` before merge.