---
name: office-it-diagnostics
description: Guide bounded read-only Windows and office-network diagnosis using the minimum sufficient evidence and evidence-driven escalation.
license: Project-internal
---

# Office IT Diagnostics

Use for bounded Windows and office-network troubleshooting: Event Viewer evidence, SSH or SMB reachability, and printer reachability or queue state.

## Doctrine

Start with the cheapest micro-tools that directly test the current hypothesis. Stop when evidence is sufficient. Add tools only when a result leaves a concrete uncertainty. Do not run broad collection merely because it exists.

Full or deep acquisition is allowed only when the user explicitly requests it or when bounded evidence documents why wider collection is necessary.

## Approved v0.1 micro-tools

Local Windows reads:
- `windows.event.system`
- `windows.event.application`
- `windows.event.security`
- `windows.printer.queue`

Internal network probes:
- `network.ssh.probe` — TCP/22
- `network.smb.probe` — TCP/445
- `network.printer.ipp_probe` — TCP/631
- `network.printer.raw_probe` — TCP/9100

Network probes accept one explicit private or internal IP literal only. No DNS expansion, public targets, ranges, scanning, authentication, brute force, or credential use. Raw printer probing is connect-only; never send print data. SSH may passively read a bounded server banner.

## Evidence and safety

Treat output as evidence, not diagnosis. Preserve the tool id, observed result, bounded target or channel, time window, and error type. Security Event Log output is sensitive and may require administrative access; keep it local or confidential by default.

For Windows Event Log, use fixed channels and bounded time and event counts. Never clear logs, enable disabled channels, restart services, change registry or firewall settings, install software, kill processes, modify permissions, or perform remediation.

For an unreachable SSH server, start with `network.ssh.probe`. For a printer that does not print, inspect `windows.printer.queue` and only the relevant printer protocol at the known IP. For an unexpected Windows reboot, start with `windows.event.system` and add other channels only when evidence requires them.

Any future repair or control capability must be a separate tool with explicit authority and approval.
