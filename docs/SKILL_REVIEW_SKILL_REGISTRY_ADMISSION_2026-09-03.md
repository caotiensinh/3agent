# Skill Security Review — skill-registry-admission

Date: 2026-09-03
Lane: 10
Status: candidate-ready-for-CI

## Purpose

Create the single controlled release gate that promotes WorkSpace-native candidates into the approved skill registry after deterministic evidence is green.

## Reviewed project sources

- WorkSpace `skills/registry.json` at main `33974b8203974fe8533579be2949d793ca403dd9`.
  - retained policy: instruction-only skills, deny-by-default network/credentials/persistence/external vendored code, bounded skill bytes/count/load bytes, explicit agent scope and SHA-256 integrity.
- Existing WorkSpace skill security-review records and registry tests remain authoritative.

## Clean-room boundary

This is a project-internal governance skill. It vendors no external skill, package, code, prompt, plugin, or dependency.

## Quarantine boundary

The governance candidate itself is stored under `skill_candidates/`, outside the approved loader root. It cannot promote itself and introduces no registry mutation in this PR.

## Removed / denied capabilities

- candidate self-approval
- registry mutation before CI
- submitted-digest trust
- mutable/ambiguous provenance
- unknown agent scope
- automatic package/plugin installation
- network/credential/process authority
- bypass of full regression testing

## Safety invariants

- exact repository bytes determine SHA-256
- policy/provenance/integrity gates are mandatory
- candidates remain quarantined while any gate fails
- registry admission is centralized to avoid multi-lane trust conflicts
- exact candidate commit and CI evidence are recorded

## Admission gates

1. This governance candidate passes its own size/front matter/hash checks.
2. It introduces no runtime authority.
3. Exact-head CI and regression suite pass.
4. Only then may a later integration commit use this policy to add already-green candidates to `skills/registry.json`.
