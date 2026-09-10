# Phase 4 rule compiler and work clustering evidence

Implementation scope: `feature/security-monitoring-phase1`, Phase 4.

## Purpose

Phase 4 adds a deterministic Detection-as-Code boundary without giving rule content execution authority. Rules describe event predicates and capability requirements. Existing WorkSpace inventory and `MonitoringPolicyEngine` remain the only authority for collection targets and read-only actions.

## Rule source boundary

Rule source is bounded strict JSON with duplicate-key rejection, exact known fields, explicit schema/version, deterministic predicates and a list of required capabilities from the existing monitoring capability vocabulary.

Rule source cannot contain or create:

- target host or port;
- credentials or credential references;
- shell text;
- packet-capture requests;
- firewall/remediation actions;
- authorization decisions.

Unknown fields and unknown capabilities fail closed.

## Compile before evaluation

The deterministic compiler validates all rules, rejects duplicate rule IDs and enforces a rule-count bound before producing immutable compiled plans. A compiled plan records source fingerprint and compiler version.

Matcher behavior reuses the existing `EventRule` / `DeterministicEventRuleEngine` semantics instead of creating a competing event matcher. The extractor returns normalized event metadata and durable evidence references only; raw log message content is not extracted.

Disabled rules may be compiled for deterministic configuration visibility but cannot match or request collection work.

## Capability requirements are not authorization

A compiled rule may state that a capability such as `local_net_read` is required. That statement does not enable the capability.

Correct boundary:

```text
RuleSource
   |
   v
validate + compile
   |
   v
required capability (declarative only)
   |
   v
inventory-derived CollectorWorkItem
   |
   v
MonitoringPolicyEngine authorize exact asset/capability/effect/host/port/credential-ref
   |
   +-- denied -> no authorized binding
   |
   v
AuthorizedRuleWorkBinding
```

A rule therefore cannot expand approved inventory or choose a new network target.

## Work clustering

Equivalent collection is eliminated before increasing concurrency. Multiple rules may bind to the same exact already-authorized `CollectorWorkItem`; those bindings are grouped into one `RuleWorkCluster`.

A cluster records:

- the exact work identity;
- all rule IDs using the work;
- compiled-rule fingerprints;
- binding fingerprints;
- policy fingerprint;
- approved-asset fingerprint.

The same `work_id` with conflicting work identity fails closed. Equivalent work cannot mix policy or asset fingerprints. A denied policy decision can never become an authorized binding or cluster.

This implements the WorkSpace constraint-first principle: **avoid duplicate work before parallelizing it**.

## Security boundary

Phase 4 does not add a scanner, shell executor, packet capture, remediation, firewall mutation or model-granted authority. Collection remains bounded by existing inventory and policy. Rule match receipts and work clusters are deterministic evidence/planning artifacts only.

## Acceptance evidence

Phase 4 requires strict parser fixtures, compile/matcher/extractor fixtures, policy-denial fixtures, deterministic clustering fixtures, duplicate/conflict/bound failures, stable public exports, the full unit-test matrix and EV-01..EV-10 on the exact validation tree before atomic promotion.
