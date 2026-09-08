# Office IT Diagnostics

Use this skill for bounded Windows and office-network troubleshooting: Event Viewer evidence, SSH reachability, SMB reachability, and printer reachability/queue state.

## Operating doctrine

Start with the minimum sufficient evidence. Select only the cheapest micro-tools that directly test the current hypothesis. Stop when evidence is sufficient. Escalate to additional tools only when the result leaves a concrete uncertainty. Do not run a full collection merely because it is available.

Full/deep acquisition is allowed only when the user explicitly requests broad investigation or when a bounded investigation has documented why wider evidence is necessary.

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

Network probes accept one explicit private/internal IP literal only. No DNS expansion, public targets, ranges, scanning, authentication, brute force, or credential use. Raw printer probing is connect-only; never send print data. SSH may passively read a bounded server banner.

## Evidence rules

Treat tool output as evidence, not a diagnosis by itself. Preserve the observed result, tool id, bounded target/channel, time window, and any error type. Security Event Log output is sensitive and may require administrative access; keep it local/confidential by default.

For Windows Event Log, query fixed channels and bounded time/event counts. Never clear logs, enable disabled channels, restart services, change registry/firewall settings, install software, kill processes, or modify permissions.

## Adaptive examples

For "SSH server is unreachable", run `network.ssh.probe` first. If TCP/22 succeeds, stop network reachability testing and investigate SSH service/authentication evidence only if the question requires it.

For "printer is not printing", inspect `windows.printer.queue` on the Windows host and probe only the printer protocols relevant to the known printer IP. Do not run unrelated Event Viewer/security/network-wide collection.

For "Windows rebooted unexpectedly", start with `windows.event.system`. Add Application or Security only when the evidence or user question makes them relevant.

## Boundary

This skill is diagnostic and non-remediating. Any future repair/control capability must be a separate tool with explicit authority and approval; never reinterpret these read-only tools as permission to remediate.
