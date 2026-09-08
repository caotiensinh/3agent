# Office IT Micro-Tools v0.1

## Scope

This pack adds eight deterministic diagnostic capabilities for Windows Event Log, local Windows printer state, SSH, SMB, IPP and raw printer reachability. It is intentionally smaller than a full host/network workflow.

## Security boundary

All v0.1 capabilities are non-remediating. Local collectors use fixed PowerShell commands with bounded event windows/counts and `shell=False`. Network probes use one fixed protocol port and one explicit private/internal IP literal. DNS expansion, public targets, port ranges, scanning, authentication, brute force, credential access and configuration changes are rejected.

TCP/9100 is connect-only because transmitting application bytes can trigger printer output. SMB and IPP are connect-only in v0.1. SSH may passively read at most a bounded server banner after the server accepts the connection.

Task authority remains deny-by-default. The four network probes require `network_scope=internal_only`, the exact capability in `allowed_tools`, `effect=network_read`, and `resource_kind=network_endpoint`. Local tools require the exact capability and `effect=read`.

## Adaptive selection

The selector ranks only matching tools and prefers lower cost. It does not automatically expand to all eight capabilities. The instruction skill requires minimum-sufficient evidence and explicit/evidence-driven escalation before broader acquisition.

## Sensitive evidence

`windows.event.security` is marked `requires_admin=true` and `sensitive_outputs=true`. Authentication/account evidence should remain local/confidential by default and should not be logged raw outside an approved evidence destination.

## Non-goals

v0.1 does not clear logs, enable channels, restart services, change registry/firewall/permissions, install packages, send print jobs, enumerate SMB shares, authenticate to SSH/SMB, scan networks, or repair devices. Any future remediation capability must be separately registered and approval-gated.

## Compatibility

`network_skills/host-log-forensics.json` is intentionally left unchanged. The new Office IT pack complements existing host-log forensic guidance rather than replacing or reducing it.
