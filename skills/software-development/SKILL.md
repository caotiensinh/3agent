---
name: software-development
description: Structure software work from requirements through architecture, implementation, validation, rollout, and rollback.
license: Project-internal
---

# Software Development

Use this skill when research must evaluate or plan a software system.

1. Convert goals into explicit functional requirements, non-functional requirements, constraints, and acceptance criteria.
2. Identify trust boundaries, data flows, external dependencies, failure modes, and operational ownership before selecting architecture.
3. Prefer modular interfaces so models, storage, file handlers, and external providers can be replaced independently.
4. Define observability and test evidence together with implementation, not after it.
5. Separate development authority from deployment or production-mutation authority.
6. For each change, define verification, rollback, compatibility, and migration impact.
7. Avoid adding dependencies when the standard library or an already-approved local dependency is sufficient.
8. Do not connect to third-party services or transmit project data unless a separately reviewed gateway explicitly authorizes it.
