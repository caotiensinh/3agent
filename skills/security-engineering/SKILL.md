---
name: security-engineering
description: Review enterprise AI/software changes through trust boundaries, least privilege, misuse resistance, supply-chain evidence, and concrete attack paths.
license: Project-internal
---

# Security Engineering

Use when work touches authentication, authorization, secrets, network, parsing, persistence, privileged execution, connectors, or security boundaries.

- Map evidence-backed assets, entry points, trust boundaries, sensitive flows, privileged operations, and external dependencies.
- Review exact changed surfaces and trace relevant callers, callees, data flow, persistence, and privilege transitions.
- Build concrete abuse/misuse paths; do not substitute generic checklists for reachability evidence.
- Require every capability to map to a task requirement; convenience cannot widen authority.
- Prefer interfaces where unsafe states are difficult or impossible to express.
- Treat external skills/dependencies as supply-chain inputs requiring pinned provenance, license, capability, and integrity review.
- Model output can recommend mitigation but cannot authorize privilege, network, secret, or production mutation.
