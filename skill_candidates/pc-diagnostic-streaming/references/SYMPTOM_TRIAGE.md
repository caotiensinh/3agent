# Symptom Triage Matrix

## 1. Freeze / Hang
First separate:
A. App-only hang
B. Desktop/GUI hang
C. GPU/display hang
D. OS scheduler/kernel hang
E. I/O stall
F. Memory pressure / swap thrash
G. Thermal/power instability

High-information questions:
- Mouse moves?
- Audio continues or loops?
- CapsLock LED toggles?
- Ctrl+Alt+Del works (Windows) / Ctrl+Alt+F3 works (Linux)?
- Ping/SSH/RDP still works?
- Disk activity LED continues?
- Does screen recover after seconds/minutes?

Interpretation examples:
- GUI frozen, SSH alive -> GPU/display/session/compositor more likely.
- Everything dead, no ping, no keyboard LED, abrupt log cutoff -> kernel/hardware/power more likely.
- Long stalls + high disk queue / I/O timeout -> storage path more likely.
- Stalls with swap exhaustion/OOM evidence -> memory pressure more likely.

## 2. Random restart / shutdown
Separate:
A. Controlled restart
B. OS bugcheck/kernel panic
C. Watchdog reset
D. Power loss / PSU / VRM / battery
E. Thermal shutdown
F. Firmware reset

Questions:
- BSOD/panic visible?
- Instant black/off then boot, or shutdown animation?
- Happens only under CPU/GPU load?
- Event/dump exists?
- UPS/PSU/battery involved?
- Any WHEA/MCE/EDAC errors?

## 3. Black screen
Separate:
A. Monitor/cable/input
B. GPU driver reset
C. Desktop compositor/session crash
D. GPU hardware/power
E. System-wide hang

Ask whether audio/network remain alive and whether remote access works.

## 4. Slow PC
Separate:
A. CPU saturation
B. memory pressure
C. storage latency
D. thermal throttling
E. background services/startup
F. antivirus/security scan
G. network-bound delay
H. filesystem corruption
I. failing storage

Always measure before cleanup.

## 5. Boot failure
Separate:
A. no power
B. POST/firmware
C. bootloader
D. kernel/driver
E. filesystem/root volume
F. service/session login
G. update/upgrade regression

## 6. Network failure
Separate layer-by-layer:
Link -> NIC/driver -> VLAN -> IP -> route -> ARP/NDP -> DNS -> transport -> TLS/app.
Never begin with a blanket network reset.

## 7. Storage / filesystem
Separate:
Media health -> controller/link -> driver -> filesystem -> application I/O.
SMART alone is not sufficient to prove a drive is healthy; correlate controller resets/timeouts and filesystem errors.

## 8. Application crash
Separate:
App bug -> library/dependency -> permissions -> memory -> GPU/driver -> corrupt profile/data -> OS fault.
Collect crash dump/core dump and logs before reinstalling.
