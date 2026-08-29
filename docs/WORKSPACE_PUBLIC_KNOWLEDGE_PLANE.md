# WorkSpace One-Way Public Knowledge Plane

## Problem

A confidentiality-preserving local AI must avoid two opposite failure modes:

1. **unsafe freshness** — confidential prompts/documents are sent to the Internet to obtain current information;
2. **safe stagnation** — the system never imports new knowledge and becomes increasingly stale.

WorkSpace resolves this by separating knowledge **acquisition** from confidential **reasoning**.

## Trust zones

```text
                     Public Internet
                           ▲
                           │ HTTPS through constrained broker
                           │
                 ┌─────────┴──────────┐
                 │ Public Research    │
                 │ workspace-public   │
                 │ no confidential FS │
                 └─────────┬──────────┘
                           │
                  PUBLIC evidence bundle
                           │
                   /var/spool/workspace-public-export
                           │
                           ▼
                 ┌────────────────────┐
                 │ Inbound Importer   │
                 │ workspace-import   │
                 │ IP network: DENY   │
                 └─────────┬──────────┘
                           │ hash/schema validation
                           ▼
             /var/lib/workspace-knowledge-public
                           │ read only to Core
                           ▼
                 ┌────────────────────┐
                 │ Confidential Core  │
                 │ workspace-core     │
                 │ Internet: DENY     │
                 └────────────────────┘
```

The importer is a software-enforced one-way transfer process, not a physical data diode.

## Why this is stronger than DLP-only egress

DLP asks: "does this outgoing payload look secret?"

The knowledge plane asks: "why does the confidential process have an outgoing channel at all?"

The Core still has none. Public facts move inward instead.

## Evidence bundle contract

A bundle:

- has schema `workspace-public-evidence/v1`;
- is explicitly `classification=public`;
- is explicitly `direction=inbound_only`;
- uses `trust_domain=system:public`;
- contains only HTTP(S) public source provenance;
- contains chunk hashes and source content hashes;
- is content-addressed (`kb_<digest>`);
- contains no executable files;
- contains no symlinks;
- marks every source `untrusted_external`;
- carries a prompt-injection risk tag.

Any mismatch fails closed.

## RAG / prompt-injection boundary

Imported web content can be malicious even when it is public. Therefore:

- zero-width characters are normalized/removed;
- common injection markers are detected and tagged;
- retrieved chunks remain `untrusted_external`;
- Context Engine wraps them as DATA ONLY;
- context volume is bounded;
- source/hash/time provenance travels with the context;
- model output still has no authority to grant itself tools;
- the Capability/Policy layer must authorize any later action.

A high injection-risk source is not automatically "false"; it is evidence that requires stricter handling. Rejecting every page containing instruction-like text would also destroy useful technical documentation.

## Operator commands

```bash
workspace-knowledge-export <PUBLIC_RESEARCH_JSON>
workspace-knowledge-import <BUNDLE_DIRECTORY>
workspace-knowledge-search --query "..."
workspace-knowledge-pack --query "..." --sensitivity confidential
```

The secure installer adds:

- `workspace-import` OS identity;
- explicit export and knowledge groups;
- public export spool;
- Core-readable public mirror;
- a separate nftables rule denying all IP networking to the importer;
- sudo wrappers that constrain source/destination paths.

## Freshness policy

V1 deliberately requires approval before import. Later automation may support curated feeds, but only when a source policy defines:

- owner;
- source/domain allowlist;
- update cadence;
- maximum bytes/chunks;
- retention/TTL;
- poisoning tests;
- expected content type;
- approval mode;
- rollback/invalidation behavior.

## Security statement

This design reduces software attack surface and creates a strong logical direction of flow. It does not protect against a malicious root administrator, kernel compromise, physical disk attacks, or other failures outside the documented threat model. Hardware-enforced one-way assurance requires a real unidirectional gateway/data diode.
