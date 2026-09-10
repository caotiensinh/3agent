# Command Safety Rules

## S0 Read-only
Allowed automatically when local authorization exists:
- event/log queries
- hardware/software inventory
- process/counter queries
- dump file listing/copy
- SMART information read
- network status/counters

## S1 Temporary observation
May create capture/log files but should not persistently modify configuration:
- pktmon/tcpdump targeted capture
- perf tracing
- short process tracing

## S2 State-changing repair/isolation
Ask approval:
- DISM RestoreHealth / SFC repair
- clean boot/service disable
- network stack reset
- package repair/reinstall
- restarting production-impacting services

## S3 Disruptive
Explicit approval and rollback/recovery:
- reboot
- offline filesystem check/repair
- driver rollback/removal
- disabling hardware
- stress testing
- BIOS setting changes

## S4 High risk
Never automatic:
- Driver Verifier
- forced kernel crash / SysRq crash
- firmware flash
- destructive SMART/storage tests
- disk partition/write operations

## Security / privacy
- Do not exfiltrate complete logs blindly.
- Redact credentials, tokens, private keys, browser secrets, personal paths when sharing externally.
- Packet captures may contain sensitive payload/metadata; use narrow filters and minimal duration.
- Evidence collection should be auditable and non-persistent unless explicitly requested.
