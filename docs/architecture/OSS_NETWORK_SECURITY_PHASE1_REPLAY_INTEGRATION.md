# Phase 1 replay integration evidence

Implementation scope: `feature/security-monitoring-phase1`, Phase 1d.

## Runtime boundary

`DeterministicByteReplay.replay_and_parse()` accepts only caller-supplied bytes and an opaque `SourceDescriptor`. It does not open files, sockets, network devices, packet captures, databases, or secret stores, and it performs no remediation or inventory mutation.

The method reuses the existing WorkSpace parsers:

- `syslog-rfc5424` -> `parse_syslog_line()`
- `suricata-eve-jsonl` -> `parse_json_sensor_event(..., source_type="suricata_eve")`
- `zeek-jsonl` -> `parse_json_sensor_event(..., source_type="zeek_json")`

Unknown format IDs fail closed before parsing.

## Determinism and checkpoint semantics

Only complete newline-terminated records are consumed. A trailing partial record never advances the byte cursor. The replay receipt remains hash-only and does not serialize raw log lines.

Parser quarantine records normally obtain a wall-clock timestamp. In replay integration that timestamp is replaced with the validated caller-supplied `checkpointed_at`, so identical bytes, source state and checkpoint time produce identical replay/checkpoint evidence.

The emitted `SourceCheckpoint` advances exactly to the replay receipt's next byte offset. `last_event_at` is updated from accepted events. If a same-source resume produces only quarantined records, the previous `last_event_at` is preserved. A rotation/reset never carries the previous source's `last_event_at` into the new source.

## Preserved existing boundaries

This integration does not modify the existing bounded spool, evidence partition writer, retention worker, freshness evaluator, policy engine, approved inventory rules, collectors, or storage mutation paths.

## Acceptance evidence

Phase 1d requires targeted checkpoint/replay/integration tests plus the existing security-monitoring regression suite to pass before the validated commit is promoted to the implementation branch.
