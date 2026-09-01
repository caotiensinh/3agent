# Network Security Intelligence v0.0.4 — DNS behavior and rare-entity baseline intelligence

## Status

v0.0.4 extends the merged v0.0.3 exact-entity correlation layer with deterministic DNS behavior features, bounded categorical baselines and advisory risk scoring.

**No response authority is added.** This phase cannot block DNS, change firewall/account/process state, capture packets, scan hosts, execute shell/subprocesses, use credentials, deploy code or promote learned knowledge.

## Privacy boundary

Raw DNS query text is required to calculate lexical statistics such as length and entropy. v0.0.4 therefore performs those calculations only while the already-local structured Suricata/Zeek event is present at the parser boundary.

The returned/persisted feature retains only:

- `entity:dns:sha256:<64 hex>` query reference, using the same v0.0.3 DNS identity normalization;
- query length;
- label count and maximum label length;
- Shannon entropy and normalized entropy;
- digit and hyphen counts;
- bounded answer count;
- explicitly supported DNS response-code category;
- explicitly supported query-type category.

It does **not** retain the DNS cleartext name, arbitrary answer text, packet bytes, HTTP metadata, credentials or free-form log content.

## Source semantics

### Suricata EVE

Behavior v1 accepts only records whose `event_type` is `dns`. The v1 query source is the explicit `dns.rrname` field. Response/query type metadata is read only from explicitly supported DNS fields.

If a newer EVE layout does not supply the v1 query field, the behavior extractor fails closed instead of guessing from unrelated nested values.

### Zeek JSON

Behavior v1 accepts only DNS records identified by `_path`/`event_type`. Query identity is read from `query`; response code and query type use supported structured fields such as `rcode_name`/`rcode` and `qtype_name`/`qtype`.

NXDOMAIN is based only on exact supported response-code semantics. It is never inferred from free-form text.

## Storage

`DNSBehaviorFeatureStore` adds one metadata-only table to the existing `MonitoringStore` SQLite database.

A feature may be written only when all of these are true:

1. the exact canonical event already exists;
2. its source type and category identify a supported DNS event;
3. its `query_entity_ref` exactly matches the v0.0.3 persisted `event_entities` row with role `dns_query` for the same `event_id`.

Exact replay is idempotent. Conflicting replay, schema-version tamper or parser-version tamper fails closed.

`StructuredBehaviorIngestor` is an optional v0.0.4 extension; the existing `StructuredEntityIngestor` API and default behavior remain unchanged. DNS feature validation happens before a newly accepted canonical/entity write. Database-level partial failure can be repaired by exact replay because every involved persistence operation is idempotent and immutable.

## Behavior baseline

The analyzer uses exact opaque entity references. It never needs to recover the original DNS name, peer address or service string.

Initial rarity rules are:

- `RARE_DNS_QUERY_V1`;
- `RARE_DESTINATION_PEER_V1`;
- `RARE_DESTINATION_SERVICE_V1`.

A rarity baseline is warm only when the **same initiator and same target type** have enough historical events across enough distinct time buckets. DNS history cannot warm a peer baseline; unrelated Auth/Process history cannot warm DNS or Flow behavior.

If history is insufficient, the result is `data_gap` / `BASELINE_WARMING` semantics rather than a suspicious verdict. A new/rare entity by itself is only a low-severity advisory signal.

## DNS behavior rules

- `HIGH_ENTROPY_DNS_V1` — requires explicit minimum query length plus Shannon and normalized-entropy thresholds.
- `DNS_QUERY_CARDINALITY_BURST_V1` — bounded distinct hashed DNS query count for one exact initiator.
- `DNS_NXDOMAIN_RATIO_BURST_V1` — bounded exact NXDOMAIN ratio for one exact initiator.

These are behavioral indicators, not declarations of tunneling, malware or command-and-control.

## Store-backed analysis

`BehaviorStoreReader` reads only metadata from the existing SQLite store.

Bounds include:

- current analysis window: at most one hour;
- historical lookback: at most 30 days;
- event rows: `LIMIT+1` fail closed;
- entity rows: `LIMIT+1` fail closed;
- DNS feature rows: `LIMIT+1` fail closed.

History ends strictly before the current window, preventing the current event from becoming its own baseline evidence.

## Advisory risk score

`DeterministicBehaviorRiskScorer` combines deterministic behavior assessments and existing v0.0.3 `IncidentGraph` metadata.

Key rules:

- each risk receipt is isolated to one exact initiating asset/source entity scope;
- `score()` fails closed when scoped assessments from multiple initiators are mixed; `score_by_scope()` is the explicit multi-initiator API;
- unrelated incident graphs cannot add score merely because they exist in the same time window;
- duplicate assessment replay does not add points;
- multiple events from the same behavior rule contribute that rule's weight only once;
- graph contribution is bounded and deterministic;
- corroboration requires exact shared `event_id` or exact opaque entity reference;
- time proximity is not an input to risk corroboration;
- one rare peer/DNS/service cannot become `high` by itself;
- `high` requires either exact graph corroboration at the configured score threshold or at least three independent deterministic signal rules inside the same initiator scope;
- no `critical` level is manufactured by this scorer;
- every receipt has `authority=advisory`.

## Replay and output bounds

Behavior assessment public output is bounded to 256 event refs, 256 evidence refs and 64 entity refs. Deterministic IDs bind the complete input sets before output truncation, so bounded rendering does not make two different large input sets equivalent.

All sensitive entity references in risk receipts must match an exact typed SHA-256 reference or an approved explicit asset reference.

## Non-goals

v0.0.4 does not implement:

- DNS blocking, sinkholing or active resolution;
- active scanning or packet injection;
- model-based domain classification;
- autonomous allow/block-list learning;
- automatic firewall/account/process mutation;
- endpoint isolation;
- PCAP execution;
- automatic fine-tuning, promotion or remediation.

## Acceptance

The phase is accepted only when:

1. raw DNS query text never appears in persisted/public feature, assessment or risk serialization;
2. feature replay is deterministic and immutable;
3. persisted feature identity exactly matches v0.0.3 DNS entity identity;
4. cold baselines return data gaps rather than novelty alerts;
5. baseline warmth is scoped by exact initiator and target type;
6. current-window observations cannot self-baseline;
7. rare-entity, entropy, cardinality and NXDOMAIN rules are bounded and deterministic;
8. duplicate replay cannot inflate counts or scores;
9. risk scoring is isolated per exact initiator and never aggregates unrelated hosts into one high score;
10. risk corroboration requires exact event/entity evidence rather than time proximity;
11. all outputs remain advisory and metadata-only;
12. v0.0.2 truth separation and v0.0.3 exact correlation remain unchanged;
13. exact-head harness, installer, portable-deploy and Windows-deploy gates pass before merge.
