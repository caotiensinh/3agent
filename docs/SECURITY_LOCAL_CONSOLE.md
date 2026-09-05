# WorkSpace Security Local Console v0.1

## Purpose

`workspace-security-ui` is the first user-facing adapter for the existing WorkSpace security monitoring backend. It exposes monitoring summary, readiness, privacy-safe asset intelligence, and an explicitly confirmed read-only monitoring run through a local browser UI without creating a second execution authority.

The console is intentionally narrow. It is a local operator surface, not a remote administration plane.

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
- no CORS response is provided;
- responses are `no-store`, framing is denied, and the HTML uses a restrictive Content Security Policy;
- the console does not expose remediation or write authority.

The CLI and UI share `SecurityMonitoringService`, so readiness, asset intelligence, and execution policy are not reimplemented independently by each user interface.

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
- generic operation invocation.

Those capabilities must remain behind reviewed capability, permission, typed-input, and physical/user-confirmation boundaries before any future UI exposure.

## Next UI slices

After v0.1 is accepted, the safest next additions are:

1. evidence/result history from the monitoring store;
2. structured flow-analysis evidence display and invocation receipt visualization;
3. incident timeline/read-only reporting;
4. explicit permission-request UI for any future active diagnostic operation.
