# WorkSpace Security Analyst & Network Monitoring — Storage and Retention v1

## Design goal

Keep hot analysis cheap while preserving enough evidence for enterprise audit and later investigation.

## Hot metadata

SQLite WAL stores:

- approved assets;
- collection receipts;
- metric/hour aggregates;
- event/template metadata;
- findings;
- report index;
- archive receipts;
- baseline versions.

Do not put large PCAP or every raw message body into indexed SQLite rows.

## Evidence files

High-volume evidence is append-only, partitioned and compressed:

```text
<LOCAL_DATA>/evidence/YYYY/MM/DD/<source>/<asset>/<hour>.jsonl.gz
```

Each partition has metadata:

- source type;
- asset ID;
- start/end timestamp;
- event count;
- uncompressed/compressed bytes;
- SHA-256;
- parser/schema version.

## Report archive

Reports are separate from raw evidence and copied atomically to the NAS.

```text
<NAS_ROOT>/daily/YYYY/MM/DD/
<NAS_ROOT>/weekly/YYYY/Www/
<NAS_ROOT>/monthly/YYYY/MM/
```

## Suggested defaults

These are capacity defaults, not legal policy:

- hourly metric detail: 30 days local;
- normalized security events: 30 days local;
- raw syslog evidence: 7–14 days local;
- findings: 12+ months;
- reports: 24+ months on NAS;
- PCAP: disabled;
- incident PCAP: separately bounded short TTL.

## Local-to-NAS lifecycle

```text
collect locally
-> validate/close partition
-> aggregate metadata
-> report uses aggregates/references
-> archive report bundle
-> retention worker removes expired local evidence only after policy checks
```

Raw evidence need not be copied to NAS by default. This prevents the NAS from becoming a limitless raw-packet/log dump. Sites may enable selected evidence archival by policy.

## NAS failure

Use a bounded local spool:

```text
READY_FOR_ARCHIVE
-> NAS available? yes -> atomic publish -> ARCHIVED
                  no  -> PENDING_NAS
```

Pending archives are retried by the next hourly collection workflow with a bounded retry policy.

If local spool approaches its configured size limit, create a high-severity monitoring-health finding before evidence loss occurs.

## Integrity

Every report bundle has `manifest.sha256`.

Evidence partitions also store content hashes in SQLite metadata.

Hashing provides integrity/tamper evidence, not access control. NAS permissions and filesystem security remain mandatory.

## Indexing rule

Index only fields that materially improve deterministic retrieval.

Avoid high-cardinality indexes with little value. IP/MAC/interface identifiers may exist as query fields but should not automatically become label-style dimensions on every event.

## Scale-out decision

SQLite/gzip remains the baseline until measured workload proves it inadequate.

Possible later components:

- VictoriaMetrics single-node for high-volume time-series metrics;
- Loki for high-volume log retrieval with metadata-first indexing.

They are candidates, not default dependencies.
