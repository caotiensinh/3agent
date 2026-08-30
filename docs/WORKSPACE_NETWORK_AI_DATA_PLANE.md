# WorkSpace Network AI Data Plane

## Status

Design and control-plane contract for Network AI datasets. This document defines the trust boundaries that must exist before any remote dataset adapter is enabled.

## Objective

WorkSpace needs large, realistic network/security/operations corpora without mirroring hundreds of gigabytes or terabytes onto the confidential AI server. The system therefore treats public datasets as remotely retrievable source material, keeps only a bounded scratch cache, and promotes only verified, license-approved, normalized artifacts into a local read-only knowledge/training store.

This is **not** a runtime bridge from Confidential Core to the Internet.

## Non-negotiable invariants

1. `workspace-core` never receives Internet or LAN egress authority.
2. A process with public Internet access can never read `/var/lib/workspace` or the approved dataset store.
3. Raw remote data is untrusted and cannot grant authority through text, packets, metadata, filenames or embedded instructions.
4. License status is a deterministic registry decision, never an LLM inference.
5. Whole-corpus sync is denied by default.
6. Every promoted artifact is bound to source SHA-256, registry fingerprint, policy fingerprint, parser/schema version and license source.
7. Research-only data can never silently enter the enterprise training/evaluation corpus.
8. Fetch and parse/normalize run under different OS identities.

## Trust-zone design

```text
                          PUBLIC INTERNET
                                |
                         HTTPS GET/HEAD only
                                |
                    +-----------v-----------+
                    | Zone D1: FETCH        |
                    | workspace-dataset-fetch|
                    |                       |
                    | - no Core access      |
                    | - no approved access  |
                    | - host/path allowlist |
                    +-----------+-----------+
                                |
                                | raw public objects only
                                v
              /var/cache/workspace-datasets/incoming
                                |
                                | local filesystem handoff
                                v
                    +-----------+-----------+
                    | Zone D2: PROCESS      |
                    | workspace-dataset     |
                    |                       |
                    | NO Internet           |
                    | license/checksum gate |
                    | parser/schema limits  |
                    | normalize/feature     |
                    +-----+-------------+---+
                          |             |
               research-only           | enterprise-approved
                          |             |
                          v             v
 /var/lib/workspace-datasets/research  /var/lib/workspace-datasets/approved
                                                |
                                                | read-only
                                                v
                                      +---------+---------+
                                      | Confidential Core |
                                      | workspace-core    |
                                      | NO Internet       |
                                      +-------------------+
```

`workspace-public` is not reused for dataset ingestion. Public research and dataset acquisition have different data volumes, parser risks and authority requirements.

## OS identities

| Identity | Read confidential | Internet | Incoming cache | Approved store | Research store |
| --- | --- | --- | --- | --- | --- |
| `workspace-core` | YES | NO | NO | READ ONLY | NO |
| `workspace-public` | NO | brokered research only | NO | NO | NO |
| `workspace-egress` | NO | HTTPS broker | NO | NO | NO |
| `workspace-dataset-fetch` | NO | allowlisted HTTPS | WRITE | NO | NO |
| `workspace-dataset` | NO | NO | READ/DELETE | WRITE | WRITE |

The future boundary installer must enforce these permissions with separate UIDs/groups, systemd hardening and nftables owner rules. Do not add `workspace-core` to a dataset-fetch group.

## Storage model

```text
/var/cache/workspace-datasets/incoming/
    bounded scratch data; safe to delete/re-fetch

/var/lib/workspace-datasets/approved/
    normalized artifacts approved for enterprise training/evaluation

/var/lib/workspace-datasets/research/
    research-only artifacts; never visible to enterprise training by default

/var/lib/workspace-datasets/provenance/
    immutable manifests, hashes, policy/registry fingerprints and lineage
```

Default V1 budgets:

- scratch cache: 80 GiB;
- one acquisition job: at most 20 GiB;
- one job: at most 32 objects;
- raw retention: ephemeral;
- eviction: least-recently-used, but never active or pinned;
- full remote sync: denied.

These are operational defaults, not dataset-size claims. Operators may change them only through reviewed policy.

## Admission lifecycle

```text
REQUEST
  |
  v
DATASET REGISTRY LOOKUP
  |
  +-- unknown ----------> DENY
  |
  v
LICENSE / STATUS GATE
  |
  +-- blocked ----------> DENY
  +-- review_required --> DENY
  +-- research_only ----> research purpose only
  |
  v
VARIANT / PURPOSE GATE
  |
  v
BYTE + OBJECT BUDGET
  |
  +-- over budget ------> DENY
  |
  v
BOUNDED ACQUISITION PLAN
  |
  v
FETCH WORKER
  |
  v
SHA-256 + SIZE + TYPE VERIFICATION
  |
  v
OFFLINE NORMALIZER
  |
  v
PROVENANCE MANIFEST
  |
  v
PROMOTION
  +--> research/
  +--> approved/
```

The `NetworkDatasetManager` performs the deterministic decision phase and intentionally performs **no network I/O**.

## License states

`enterprise_approved`
: Explicitly reviewed for the intended enterprise training/evaluation use.

`research_only`
: May be acquired only for research. Output stays in the research store.

`review_required`
: Fail closed until a human review updates the registry.

`blocked`
: Acquisition and promotion denied.

Changing a registry state is a security/compliance change and requires review.

## Initial registry

The V1 registry includes:

- LANL Comprehensive Multi-Source — enterprise-approved; operator enrollment/direct-link bootstrap may be required.
- CSE-CIC-IDS2018 — enterprise-approved; public unsigned S3 acquisition; prefer processed ML traffic for V1.
- Splunk BOTS v2 — enterprise-approved; prefer attack-only for the first incident-correlation experiments.
- MAWI — research-only in the WorkSpace registry.
- TON_IoT — research-only unless commercial permission is recorded.
- UGR'16 — review-required and fail-closed.

The registry is deliberately conservative. A dataset being publicly downloadable does not imply enterprise training rights.

## Provenance contract

Each normalized artifact must be traceable through a manifest containing at least:

```text
dataset_id
purpose
variant
destination_class
source_object
source_sha256
source_size_bytes
fetched_at
parser_version
normalized_schema_version
registry_fingerprint
policy_fingerprint
license_source
license_status
output_sha256          # required before promotion
parent_source_hashes   # when one output combines multiple inputs
transform_settings     # canonicalized
promotion_decision
```

V1 code creates the source-side provenance template. The normalizer/promotion phase must append output digest and transformation metadata before making an artifact visible to Core.

## Network policy for the future fetch worker

The fetch process must support only:

- HTTPS;
- `GET` and `HEAD`;
- reviewed hostnames and path prefixes from the registry;
- bounded redirects;
- no request body;
- no caller-provided cookies, Authorization header or arbitrary headers;
- no credentials in V1;
- no private, loopback, link-local, CGNAT, multicast or special-use destination after DNS resolution;
- bounded response/object size and bounded total job bytes.

The fetch worker receives an immutable acquisition plan. It does not accept arbitrary URLs from the LLM.

## Normalization strategy

Raw packet capture is evidence, not model context. Preferred pipeline:

```text
PCAP / NetFlow / CSV / host logs
              |
      deterministic parser
              |
    Flow / DNS / Auth / Host / IDS events
              |
       normalized schema
              |
      Parquet/Arrow shards
              |
     features/time windows
              |
        ML/DL/AI layers
```

Parquet/Arrow support is a later adapter because the current WorkSpace base package deliberately has a small dependency set. Do not add `pyarrow`, Zeek or other heavy dependencies to the Confidential Core package without a separate dependency/security review.

## Common network event schema

Target normalized fields should include, where available:

```text
timestamp
dataset_id
site
device_id
device_role
src_ip
dst_ip
src_port
dst_port
protocol
packets
bytes
duration
rtt
event_family
event_type
service
severity
user
host
process
label
attack_family
source_sha256
source_dataset
source_license
```

Not every source must populate every field. Missing values are explicit nulls, not fabricated values.

## Own-network data

Public datasets provide general experience. Enterprise accuracy must eventually be calibrated with local network observations such as switch/router syslog, SNMP, NetFlow/IPFIX, DNS, DHCP, VPN, Windows Event, Linux journal, RTSP/camera events, server/container logs, latency, loss and jitter.

Internal telemetry follows a separate path and **never enters Zone D1**. It is already confidential and must be ingested locally under Core-side policy.

## CLI V1

```bash
workspace-network-data list

workspace-network-data fingerprint

workspace-network-data plan cse-cic-ids2018 \
  --purpose training \
  --variant processed-ml \
  --estimated-bytes 1073741824 \
  --objects 2
```

The command emits an acquisition plan or a machine-readable deny reason. It never downloads data.

Examples of fail-closed reasons:

```text
DATASET_UNKNOWN
DATASET_STATUS_DENIED
ENTERPRISE_USE_NOT_ALLOWED
COMMERCIAL_LICENSE_NOT_APPROVED
FULL_SYNC_DENIED
JOB_BYTE_BUDGET_EXCEEDED
OBJECT_BUDGET_EXCEEDED
VARIANT_PURPOSE_DENIED
NO_NETWORK_ALLOWLIST
```

## Implementation phases

### V1 — control plane

Implemented in this branch:

- reviewed dataset registry;
- license/purpose/status admission;
- byte/object/full-sync budget enforcement;
- LRU eviction planning with active/pinned protection;
- stable policy/registry fingerprints;
- source provenance template;
- CLI for list/fingerprint/plan;
- unit tests.

### V2 — acquisition boundary

Add a separate `workspace-dataset-fetch` service and `workspace-dataset` processor, OS permissions, nftables rules, host/path enforcement, streamed SHA-256 and an append-only acquisition ledger.

### V3 — normalizers

Add source adapters and deterministic normalizers for CIC processed CSV, LANL gzip text and BOTS artifacts. Introduce Parquet/Arrow only after dependency review.

### V4 — Network AI integration

Expose approved normalized shards read-only through the WorkSpace knowledge/retrieval plane. Add network-specific evaluation sets, anomaly/failure taxonomy and model-training pipelines.

## Security review triggers

A fresh security review is mandatory if any of these change:

- a dataset registry status or license decision;
- acquisition hostname/path allowlists;
- credential support;
- HTTP methods/headers/redirect policy;
- dataset-fetch UID/group membership;
- access from fetch worker to approved/Core data;
- Core network rules;
- cache/approved-store filesystem permissions;
- parser execution model;
- auto-promotion behavior;
- new remote model/cloud processing;
- telemetry or upload behavior.

The architectural objective is simple: **public bytes may flow inward after deterministic verification; confidential bytes never gain an outward path.**
