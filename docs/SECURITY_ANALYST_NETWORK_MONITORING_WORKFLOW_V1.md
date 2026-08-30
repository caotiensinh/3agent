# WorkSpace Security Analyst & Network Monitoring — Workflow Blueprint v1

## Continuous stream

```text
syslog / Zeek / Suricata / WorkSpace audit
  -> local spool
  -> parser
  -> canonical event
  -> template/rule checks
  -> finding
  -> immediate correlation if high/critical
```

## Hourly snapshot

```text
systemd timer
  -> load approved inventory
  -> bounded read-only collector pool
      -> availability
      -> SNMP counters/state
      -> local host network state
      -> optional approved device read-only adapters
  -> normalize
  -> calculate deltas/rates
  -> baseline comparison
  -> deterministic detections
  -> update findings/correlation
  -> write hourly receipt
  -> retry pending NAS archives
```

The expected default AI call count for an uneventful hourly snapshot is **zero**.

## 17:30 daily report

```text
17:30 timer
  -> freeze report cutoff
  -> evidence completeness gate
  -> 24h aggregate
  -> rolling 7d aggregate
  -> rolling 30d aggregate
  -> deterministic report skeleton
  -> compact finding/timeline pack
  -> one local AI analyst call
  -> evidence-reference validation
  -> report bundle
  -> SHA-256 manifest
  -> atomic NAS archive
  -> report/archive receipt
```

## Weekly archive

Sunday 17:30:

```text
reuse daily/hourly aggregates
  -> week snapshot
  -> weekly report
  -> atomic NAS archive
```

## Monthly archive

Last calendar day at 17:30:

```text
reuse daily/hourly aggregates
  -> month snapshot
  -> monthly report
  -> atomic NAS archive
```

## High/critical finding path

```text
incoming event/hourly detector
  -> deterministic severity
  -> high/critical?
      yes -> correlation pack
           -> optional local AI triage
           -> immediate internal alert
           -> preserve finding for 17:30 report
```

Critical detections do not wait for the daily report.

## Incident packet capture path

```text
finding / operator investigation
  -> explicit approval
  -> exact interface/segment + duration + bytes + TTL
  -> bounded capture
  -> hash/receipt
  -> incident-only evidence store
```

There is no autonomous transition from "AI suspects problem" to "capture payload".

## Failure behavior

### Device unavailable

Record unreachable evidence and continue other assets.

### Collector timeout

At most one bounded retry by default, then mark the source incomplete.

### AI unavailable

Generate deterministic report with `AI_ANALYSIS_UNAVAILABLE` status.

### NAS unavailable

Keep validated bundle in local spool and mark `PENDING_NAS`.

### Sensor stale

Generate `DATA_GAP` finding rather than interpreting absence of alerts as a healthy network.

### Database write failure

Fail the hourly receipt and preserve raw collector result in bounded local recovery spool; never claim completed monitoring.
