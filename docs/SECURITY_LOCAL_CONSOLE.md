# WorkSpace Security Local Console v0.1

## Purpose

`workspace-security-ui` is the first user-facing adapter for the existing WorkSpace security monitoring backend. It exposes monitoring summary, readiness, privacy-safe asset intelligence, bounded evidence/result-history aggregates, bounded incident posture aggregates, and an explicitly confirmed read-only monitoring run through a local browser UI without creating a second execution authority.

The console is intentionally narrow. It is a local operator surface, not a remote administration plane or a forensic evidence browser.

## Security model

The console preserves the existing monitoring backend gates:

- configuration is selected once when the console starts;
- HTTP requests cannot supply a filesystem path, network target, credential, collector selector, shell command, argv, executable, or remediation action;
- binding is restricted to `127.0.0.1` or `localhost`;
- non-loopback `Host` headers are rejected;
- state-changing browser requests require an anti-CSRF token generated at server startup;
- the only POST operation requires the exact body `{"confirm_readonly": true}`;
- monitoring still requires backend readiness, `enabled=true`, `allow_real_network=true`, approved assets, policy authorization, and the existing collector boundaries;
- asset intelligence is delegated to `SecurityMonitoringService.asset_intelligence()` and exposes aggregate counts only;
- asset intelligence never exposes asset identifiers, management hosts, credential references, or concrete TCP port values;
- evidence/result history is delegated to `SecurityMonitoringService.evidence_summary()` and uses the existing `SecurityMonitoringUIReadModel` query-only SQLite boundary;
- evidence/result history is server-bounded to at most 100 recent rows per internal stream before reduction to aggregate counts;
- detailed read-model identifiers and references are reduced inside the canonical service and are never returned by the evidence-summary HTTP endpoint;
- evidence/result history never exposes asset IDs, source IDs, finding IDs, evidence references, bundle references, manifest hashes, or raw observation values;
- incident posture is delegated to `SecurityMonitoringService.incident_posture()` and uses the same query-only read model;
- incident posture is server-bounded to at most 100 recent findings and reduces severity/status to fixed buckets before returning data;
- incident posture never exposes finding IDs, asset references, evidence references, rule IDs, category values, raw evidence, credentials, or browser-controlled filters;
- no CORS response is provided;
- responses are `no-store`, framing is denied, and the HTML uses a restrictive Content Security Policy;
- browser rendering uses `textContent` for monitoring-derived values;
- the console does not expose remediation or write authority.

The CLI and UI share `SecurityMonitoringService`, so readiness, asset intelligence, evidence projection, incident posture, and execution policy are not reimplemented independently by each user interface.

## Start the console

Install/update WorkSpace so the new console entrypoint is available, then run:

```bash
workspace-security-ui \
  --config config/security_monitoring.example.json \
  --host 127.0.0.1 \
  --port 8765
```

Open:

```text
http://127.0.0.1:8765/
```

The command prints the local URL at startup. No browser is opened automatically.

## HTTP surface

### `GET /api/v1/health`

Returns console health and explicitly reports that the surface is local-only and has no write authority.

### `GET /api/v1/security/monitoring/summary`

Returns the existing safe monitoring configuration summary. Raw credentials are never included.

### `GET /api/v1/security/monitoring/readiness`

Runs the existing metadata-only readiness evaluation. This does not probe the network, read secret values, capture packets, or execute remediation.

### `GET /api/v1/security/monitoring/asset-intelligence`

Returns the canonical privacy-safe asset intelligence summary from `SecurityMonitoringService.asset_intelligence()`.

The response is intentionally aggregate-only. It may contain:

- total, enabled, and disabled asset counts;
- enabled-asset role cardinality;
- counts by approved collector capability;
- counts by approved data class;
- count of enabled assets that have a credential reference;
- count of explicit TCP port bindings;
- explicit authority flags proving that the summary has no database-write, network-execution, collector-execution, packet-capture, or remediation authority.

The endpoint does **not** expose:

- asset IDs;
- management IP addresses or hostnames;
- credential-reference values;
- role labels;
- concrete TCP port values;
- disabled-asset capability or data-class details.

The endpoint accepts no request body or user-supplied target. It therefore adds an observation surface only and does not expand execution authority.

### `GET /api/v1/security/monitoring/evidence-summary`

Returns a privacy-safe, bounded recent-evidence projection from `SecurityMonitoringService.evidence_summary()`.

The service reuses `SecurityMonitoringUIReadModel`, whose database connection is opened with SQLite `mode=ro` and `PRAGMA query_only=ON`. The browser does not receive or control the read-model pagination parameters. The service always requests at most 100 recent rows from each of these internal streams:

- observations;
- canonical events;
- findings;
- archive/report receipts.

Those detailed rows are reduced to aggregate metadata before the HTTP response is built. The response may contain:

- whether the monitoring database is available;
- bounded sample counts for observations, events, findings, and reports;
- counts of sampled observations, events, and findings that have evidence linkage;
- open finding and high/critical finding counts from the existing UI summary;
- a safe latest-hourly projection containing status, coverage, expected/observed asset counts, observation time, and age;
- bounded monitoring health/reason codes;
- explicit authority flags proving the projection is aggregate-only and database-read-only.

The endpoint does **not** expose:

- run IDs;
- asset IDs;
- source IDs;
- event IDs;
- finding IDs;
- evidence-reference values;
- bundle references;
- manifest hashes;
- raw observation values;
- credentials or secret values.

Query-string values are not forwarded to the service and cannot select an asset, source, evidence reference, path, target, or page size. This endpoint performs no database writes, network execution, collector execution, packet capture, or remediation.

### `GET /api/v1/security/monitoring/incident-posture`

Returns a privacy-safe bounded incident posture projection from `SecurityMonitoringService.incident_posture()`.

The service requests at most 100 recent findings from the existing query-only `SecurityMonitoringUIReadModel`. Detailed rows are reduced before the HTTP response is constructed. Severity and status values are normalized into fixed approved buckets; any unrecognized value collapses to `other` instead of being reflected to the browser.

The response may contain:

- bounded finding sample count;
- open and closed sample counts;
- fixed-bucket severity counts;
- fixed-bucket status counts;
- a derived attention level (`clear`, `low`, `medium`, `high`, or `critical`);
- explicit authority flags proving the projection is aggregate-only and database-read-only.

The endpoint does **not** expose:

- finding IDs;
- asset references;
- evidence references;
- rule IDs;
- category values;
- arbitrary stored severity/status strings;
- raw evidence;
- credentials or secret values.

Query-string values are ignored by the handler and are not forwarded to the service. The browser therefore cannot select a finding, asset, evidence reference, page size, path, target, or execution option. This endpoint performs no database writes, network execution, collector execution, packet capture, or remediation.

### `POST /api/v1/security/monitoring/run-hourly`

Requires:

```json
{
  "confirm_readonly": true
}
```

and the per-process `X-Workspace-CSRF` token used by the locally served page. The operation delegates to the same backend service used by `workspace-security-monitor run-hourly --execute-readonly`.

## Deliberate non-goals for v0.1

This version does not expose:

- arbitrary diagnostic targets;
- shell or command execution;
- packet-capture paths;
- credential entry;
- firewall or network configuration changes;
- remote/LAN binding;
- remediation actions;
- generic operation invocation;
- raw evidence downloads;
- identifier-addressable evidence browsing;
- browser-controlled evidence or incident filters or pagination.

Those capabilities must remain behind reviewed capability, permission, typed-input, privacy, and physical/user-confirmation boundaries before any future UI exposure.

## Next UI slices

After the bounded incident-posture slice is accepted, the safest next additions are:

1. privacy-reviewed structured flow-analysis evidence visualization;
2. correlation and asset-health/risk posture summaries;
3. incident timeline/read-only reporting only after identifier minimization and time-bucketing are reviewed;
4. explicit permission-request UI for any future active diagnostic operation.
