# WorkSpace Security Analyst — Operations Runbook v1

## 1. Scope and authority

This runbook is the authoritative operator procedure for **Security Analyst & Network Monitoring `ver.0.0.1`**.

The monitored LAN is production. Routine operation is **non-disruptive, read-only and fail-closed**. WorkSpace is allowed to observe approved state and existing telemetry; it is not allowed to change router, switch, firewall, VLAN, QoS, route, interface, firmware, users, credentials or endpoint state.

Routine bandwidth analysis is `counter_only`. Routine packet analysis is `passive_only`. Active ICMP/TCP liveness is disabled by default and is never a throughput test. Model output never authorizes a network action.

The safety contract in `docs/SECURITY_ANALYST_PRODUCTION_LAN_SAFETY_V1.md` overrides convenience. If this runbook and a local deployment practice disagree, choose the safer behavior and keep collection disabled until the conflict is reviewed.

## 2. Components and privilege separation

| Component | Identity | Network authority | Purpose |
| --- | --- | --- | --- |
| WorkSpace chat/UI | normal WorkSpace service | no monitoring mutation authority | read Security Analyst aggregates; admin may create PCAP approval metadata only |
| Hourly monitor | `workspace-monitor` | denied by systemd until operator-reviewed LAN allowlist is added | bounded read-only collection from approved inventory |
| Daily report | `workspace-monitor` | no socket authority | deterministic 17:30 report and archive of an already-mounted NAS path |
| Incident capture | `workspace-pcap` | `AF_PACKET`, bounded `CAP_NET_RAW/CAP_NET_ADMIN` only | one approved, bounded, passive PCAP exception |

The chat/web process must never receive packet-capture capabilities. There is no HTTP route that executes a capture.

## 3. Safe installation state

Installation does **not** authorize LAN contact. The shipped monitoring example is deliberately disabled:

```text
enabled=false
allow_real_network=false
allow_active_liveness=false
production_safety_profile=non_disruptive_v1
bandwidth_measurement_mode=counter_only
packet_analysis_mode=passive_only
```

Before enabling anything, create the dedicated service identities and directories using the deployment mechanism approved for the host. Keep monitoring state under `/var/lib/workspace-monitor`, configuration under `/etc/workspace`, and SNMP secret files under the configured locked secret directory.

Do not reuse a WorkSpace chat/web account for the monitor or PCAP runner.

## 4. Configuration validation — offline first

Start from `config/security_monitoring.example.json`. Replace documentation-range example assets only with assets that have been explicitly approved for monitoring. Inventory is authoritative; discovery must never automatically create trusted assets.

The normal baseline should contain only `snmpv3_read` and/or `local_net_read` capabilities. Keep `allow_active_liveness=false` unless an operator has documented why passive state is insufficient.

Validate configuration before enabling collection:

```sh
workspace-security-monitor --config /etc/workspace/security-monitoring.json validate-config
workspace-security-monitor --config /etc/workspace/security-monitoring.json init-db
```

`validate-config` and `init-db` are offline operations. Their output must not print management hosts or raw credentials.

### SNMPv3 secret boundary

Use only opaque `secret-ref:*` handles in inventory. The referenced secret file is read in-process by the optional SNMP backend; secrets must never be placed in argv or logs. On POSIX, secret files must be locked down and must not be symlinks. Weak SHA-1/MD5/DES SNMP credential profiles are rejected; use the supported SHA-2/AES policy.

Windows intentionally fails closed for the POSIX file-secret backend. Do not emulate POSIX permissions with an unreviewed Windows workaround.

## 5. Enabling routine hourly collection

Routine collection requires **all** of these gates:

1. `enabled=true` in the reviewed monitoring config.
2. `allow_real_network=true` in that config.
3. `non_disruptive_v1` policy remains active.
4. Exact approved assets/capabilities are present in inventory.
5. The systemd service has an operator-reviewed local egress allowlist for only the approved LAN scope; `IPAddressDeny=any` remains the base rule.
6. The systemd timer is explicitly enabled by the operator/deployment process.

The shipped timer runs at minute `:05` and is persistent. The service is one-shot, bounded, and has a 15-minute runtime cap. A stale hourly lock is reclaimable only after the separately bounded 20-minute recovery threshold.

A finalized hourly slot is idempotent: replay returns the durable receipt and does not recollect the same slot.

### Safe status checks

These commands inspect local service state only:

```sh
systemctl status workspace-security-monitor-hourly.service --no-pager
systemctl status workspace-security-monitor-hourly.timer --no-pager
journalctl -u workspace-security-monitor-hourly.service -n 200 --no-pager
```

Do not diagnose a monitoring problem by starting a network scanner or a throughput generator.

## 6. Normal hourly evidence

Normal hourly evidence is derived from existing state:

- SNMPv3 read-only counters from exact approved assets;
- local OS counters such as `/proc/net/dev`;
- passive syslog;
- existing Zeek/Suricata JSON metadata;
- existing normalized NetFlow/sFlow/IPFIX telemetry when available;
- counter-derived bandwidth/utilization/errors/discards.

A healthy hourly cycle uses **0 LLM calls**.

If a counter resets, wraps ambiguously, follows a reboot, lacks a prior sample, has an invalid interval or changes interface speed, record `DISCONTINUITY`/`DATA_GAP`. Never fabricate a bandwidth rate.

## 7. DATA_GAP and degraded visibility

`DATA_GAP` is a first-class operational condition, not a healthy state.

When a sensor or source is stale/missing:

1. confirm the local collector/service is running;
2. confirm the asset remains in approved inventory;
3. confirm the configured source file/telemetry path exists if the source is passive;
4. inspect bounded local logs/receipts;
5. fix only the monitoring-side issue that is under operator authority;
6. do **not** compensate by scanning the LAN or generating traffic.

If visibility cannot be restored safely, keep the source degraded and let the daily report state the data gap.

## 8. Daily 17:30 reporting

The daily reporting service has no socket authority. It reads validated local evidence and writes a local bundle, then archives only to a path that the OS/operator has already mounted.

Validate reporting configuration:

```sh
workspace-security-report --config /etc/workspace/security-reporting.json validate-config
```

The canonical timer runs at **17:30 Asia/Tokyo**. A persistent activation after downtime selects the latest already-occurring 17:30 cutoff and never fabricates a future measurement.

Safe local status checks:

```sh
systemctl status workspace-security-report-daily.service --no-pager
systemctl status workspace-security-report-daily.timer --no-pager
journalctl -u workspace-security-report-daily.service -n 200 --no-pager
```

The deterministic report is the source of truth. Local AI analysis is an optional advisory sidecar and cannot change severity, inventory, authority or remediation state.

## 9. NAS archive and recovery

WorkSpace does not mount SMB/NFS and stores no NAS username/password. `nas_root` must already be an operator-managed mountpoint.

Before relying on archive delivery, verify locally that the expected path is an actual mountpoint:

```sh
mountpoint -q /mnt/workspace-security-archive
```

If the NAS is missing/unmounted, WorkSpace must keep the validated local bundle and record `PENDING_NAS`. It must not regenerate the report and must not rerun AI or network collection just to retry storage.

When the mount is safely restored, retry only the existing validated bundle using the metadata from the pending archive receipt:

```sh
workspace-security-report --config /etc/workspace/security-reporting.json retry-nas --report-id REPORT_ID --period-kind daily --period-key PERIOD_KEY --attempt ATTEMPT
```

The archiver writes to a temporary path, verifies SHA-256 and atomically renames the verified bundle.

## 10. Restart and catch-up behavior

After an unexpected host/service restart:

1. inspect timer/service state;
2. inspect the latest durable hourly/report receipts;
3. allow the persistent timer to perform at most the bounded catch-up behavior;
4. verify a finalized hourly slot is replayed rather than recollected;
5. treat an active lock as valid until the hard stale-lock threshold is exceeded;
6. do not manually create repeated runs for the same slot to force a green status.

The system must fail closed instead of producing duplicate evidence or fabricated historical measurements.

## 11. Incident PCAP exception

Full PCAP is **disabled by default** and is not part of routine monitoring.

Use it only for a specific incident when passive metadata is insufficient. Required sequence:

1. an authenticated WorkSpace admin reviews the incident;
2. the admin creates bounded approval metadata using the exact UI/API contract and literal approval confirmation `APPROVE_PCAP`;
3. the approval binds exact interface, approved literal-IP targets, allowed ports/filter semantics, duration, maximum bytes, TTL and purpose;
4. the dedicated POSIX capture runner consumes that approval exactly once using `AUTHORIZE_PCAP`;
5. capture output receives a SHA-256 receipt and bounded retention expiry;
6. a retry requires a new approval.

The operator may invoke the already-reviewed systemd unit for the exact approval ID:

```sh
systemctl start workspace-security-pcap@approval-0123456789abcdef01234567.service
systemctl status workspace-security-pcap@approval-0123456789abcdef01234567.service --no-pager
```

Do not call a packet-capture binary directly, do not supply arbitrary BPF, and do not grant packet capabilities to the chat/web process. AI suspicion alone can never create or execute approval.

## 12. Rollback / emergency stop

If the monitoring feature behaves unexpectedly, stop its future scheduled work at the host/service layer. Do not alter network devices to stop WorkSpace.

```sh
systemctl stop workspace-security-monitor-hourly.timer
systemctl stop workspace-security-report-daily.timer
systemctl stop workspace-security-monitor-hourly.service
systemctl stop workspace-security-report-daily.service
```

Then preserve `/var/lib/workspace-monitor` evidence and receipts for investigation. Do not delete the monitoring database or report spool during first response.

PCAP is one-shot and has no restart loop. If an approved capture must be stopped, stop only that exact systemd instance and retain its audit metadata.

Rollback must not silently broaden authority. Re-enabling collection requires the same reviewed config/policy/allowlist gates as initial enablement.

## 13. Prohibited operator shortcuts

Never use WorkSpace troubleshooting as justification for:

- network/service scanners or port-range discovery;
- throughput/load generators;
- packet injection/replay/fuzzing;
- ARP spoofing/poisoning or flooding;
- router/switch/firewall/VLAN/ACL/routing/QoS changes;
- interface flap, reboot/reset or firmware update;
- credential/user/key changes;
- autonomous host blocking/quarantine;
- model-generated shell/network commands.

If a requested diagnostic would violate this list, record a blocker/data gap and escalate to a human operator rather than executing it.

## 14. Release evidence and incident handoff

For `ver.0.0.1`, release evidence must include exact-head CI for harness, installer, portable Linux and Windows plus EV-01 through EV-10 receipts. EV receipts are metadata-only and synthetic/offline; they do not claim real-LAN acceptance.

`NS1-18` real-LAN acceptance remains optional and must be separately authorized. If performed later, it is limited to approved read-only observation and may not introduce load-generating or state-changing tests.

For an incident handoff, preserve:

- exact WorkSpace version/source SHA;
- affected monitoring run/report IDs;
- finding/evidence IDs rather than raw sensitive content in tickets;
- sensor freshness/data-gap state;
- archive receipt status and digest;
- PCAP approval/capture receipt IDs if an approved exception was used;
- operator actions taken and their timestamps.

## 15. Definition of operationally safe

The feature is operationally safe only while all of the following remain true:

```text
approved inventory only
+ read-only / passive routine monitoring
+ counter-only bandwidth
+ explicit DATA_GAP semantics
+ bounded retries/concurrency/timeouts/retention
+ 0 LLM calls in healthy hourly collection
+ deterministic 17:30 source-of-truth report
+ pre-mounted NAS with PENDING_NAS recovery
+ model authority separated from monitoring/capture authority
+ full PCAP disabled except one-shot admin-approved incident exception
```
