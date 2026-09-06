# WorkSpace Security Local Console

## Purpose

`workspace-security-ui` is the local browser surface for the existing WorkSpace security, network, monitoring, and operator-posture backend. The console does not create a second monitoring or execution authority: canonical reads and operations continue to flow through `SecurityMonitoringService`, the existing query-only UI read model, the monitoring store, and existing readiness/policy gates.

The UI now has four operator surfaces:

- **Overview** — privacy-safe monitoring, asset intelligence, evidence, incident, and operator-posture aggregates;
- **Analyst Workspace** — bounded read-only rows for assets, network observations, canonical security events, findings, reports, and admin/safety state;
- **Operations** — bounded local SQLite initialization and explicitly confirmed read-only monitoring;
- **Readiness** — current blocking reasons and safety state.

## Fastest safe test: Demo Mode

After installing the repository package, run:

```bash
workspace-security-ui --demo
```

Then open:

```text
http://127.0.0.1:8765/
```

Demo Mode creates an isolated temporary monitoring configuration and SQLite database containing synthetic data only. It uses the real monitoring storage, canonical event, entity-context, finding, correlation, flow, timeline, and operator-posture code paths.

The demo dataset contains four synthetic assets and a bounded DNS -> FLOW -> AUTH -> PROCESS -> IDS event chain so the Analyst Workspace and Operator Posture are visibly non-empty. Demo Mode sets `allow_real_network=false` and the HTTP handler rejects `run-hourly`; it does not execute collectors, packet capture, remediation, or any real-network operation.

## Normal local startup

The normal portable start no longer requires a hand-written config path:

```bash
workspace-security-ui
```

If the default user configuration does not exist, the console creates a safe disabled configuration under the current user's WorkSpace config directory. The default database and secret-directory paths are derived from that user directory, so the first launch is portable across supported operating systems instead of depending on the Linux-only example paths.

You may still pin an explicit reviewed configuration:

```bash
workspace-security-ui --config /absolute/path/to/security-monitoring.json --host 127.0.0.1 --port 8765
```

On Windows PowerShell, pass an absolute Windows path when using `--config`.

## First-run flow

1. Start `workspace-security-ui`.
2. Open `http://127.0.0.1:8765/`.
3. Review **Readiness**. A new safe-default configuration is expected to be blocked because monitoring and real-network access are disabled.
4. Use **Operations -> Initialize local monitoring DB** to create the local SQLite schema and synchronize only the approved inventory already present in the fixed startup configuration. This operation performs no network communication.
5. Configure approved assets and policy outside the browser using the canonical monitoring configuration boundary.
6. Restart the console with that reviewed configuration.
7. Only when readiness is `READY`, explicitly confirm **Run read-only monitoring**.

Real-network execution remains fail-closed. The service requires `enabled=true`, `allow_real_network=true`, an approved inventory, policy authorization, readiness success, and explicit read-only confirmation.

## Analyst Workspace boundary

`GET /api/v1/security/monitoring/analyst-snapshot` is a bounded projection over `SecurityMonitoringUIReadModel`.

The server fixes the maximum to 50 rows per stream and does not forward browser query strings as selectors or pagination. The response can show:

- anonymized asset aliases such as `Asset 01`;
- enabled state, approved data-class bucket, approved collector bucket, last-status bucket, and recency bucket;
- network observation collector/status/recency plus boolean value/evidence presence;
- canonical event source bucket, stage (`DNS`, `FLOW`, `AUTH`, `PROCESS`, `IDS`, `OTHER`), severity, recency, and evidence-presence boolean;
- finding severity/status, bounded asset/evidence link counts, and recency bucket;
- report period/status/recency;
- database/schema and safety-policy state.

It does **not** return raw asset IDs, management hosts/IP addresses, credential references, evidence references, event IDs, finding IDs, rule IDs, arbitrary raw observation values, or browser-controlled targets.

## Existing aggregate endpoints

The Local Console preserves these existing safe endpoints:

- `GET /api/v1/health`
- `GET /api/v1/security/monitoring/summary`
- `GET /api/v1/security/monitoring/readiness`
- `GET /api/v1/security/monitoring/asset-intelligence`
- `GET /api/v1/security/monitoring/evidence-summary`
- `GET /api/v1/security/monitoring/incident-posture`
- `GET /api/v1/security/monitoring/operator-posture`

The operator-posture projection integrates bounded risk, asset-health, correlation, flow, and incident-timeline summaries. Exact timestamps and raw identifiers remain hidden from that aggregate surface.

## Local state-changing endpoints

### `POST /api/v1/security/monitoring/initialize`

Requires the per-process CSRF token and the exact body:

```json
{
  "confirm_initialize": true
}
```

It delegates to `SecurityMonitoringService.initialize()`, creating/synchronizing the local monitoring SQLite state only. It does not execute collectors or network probes.

### `POST /api/v1/security/monitoring/run-hourly`

Requires the per-process CSRF token and the exact body:

```json
{
  "confirm_readonly": true
}
```

It delegates to the same canonical service used by `workspace-security-monitor run-hourly --execute-readonly`. Demo Mode blocks this endpoint regardless of the submitted confirmation.

## Security invariants

- bind is restricted to `127.0.0.1` or `localhost`;
- non-loopback `Host` headers are rejected;
- no CORS response is provided;
- responses are `no-store`, framing is denied, and CSP is restrictive;
- monitoring-derived browser values are rendered with `textContent`, never `innerHTML`;
- browser requests cannot submit a filesystem path, network target, credential, collector selector, shell command, argv, executable, packet-capture path, or remediation action;
- query strings are ignored as execution or identity selectors;
- state-changing operations require CSRF plus exact typed confirmation bodies;
- no remediation, firewall change, arbitrary shell execution, raw evidence download, generic operation invocation, or remote/LAN administration authority is exposed.

## What "activated" means

The Local Console activates the existing **safe observation and test surfaces** so they are visible and testable from the browser. It does not silently activate higher-risk capabilities. Packet capture, remediation, active diagnostics, credential use, and any future disruptive operation remain behind their existing reviewed capability, permission, policy, and explicit-user-confirmation boundaries.
