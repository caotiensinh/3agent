# Cause Taxonomy

C01 Power delivery: PSU, adapter, battery, cable, socket, VRM
C02 Thermal: CPU/GPU/VRM/SSD overheating or throttling
C03 CPU: machine check, microcode, instability, overclock
C04 RAM: DIMM errors, memory controller, XMP/EXPO instability
C05 GPU: driver, VRAM, power, PCIe, compositor/display stack
C06 Storage media: SSD/HDD/NVMe wear/failure
C07 Storage path: SATA/NVMe controller, cable, PCIe, driver, timeout
C08 Filesystem: NTFS/ext4/XFS/Btrfs corruption
C09 OS kernel: bug, regression, panic/bugcheck
C10 Driver/module: bad, incompatible, unsigned/out-of-tree, regression
C11 Firmware/BIOS/UEFI: bug, bad settings, ACPI, outdated firmware
C12 Update/upgrade: partial install, regression, dependency mismatch
C13 Service/startup: third-party interference, deadlock, resource leak
C14 Application: crash, hang, corrupt profile/data
C15 Memory pressure: leak, OOM, swap thrash
C16 CPU saturation / runaway process
C17 Disk saturation / excessive latency
C18 Network link/driver/VLAN/IP/route/DNS/transport
C19 Security/malware: only claim with corroborated indicators
C20 Peripheral/USB/Thunderbolt/device fault
C21 Clock/time/certificate issue
C22 Virtualization/hypervisor/container interaction
C23 User configuration/policy
C24 Environmental: unstable mains, dust, corrosion, vibration
C25 Unknown: insufficient evidence

Rule: keep Unknown available. A disciplined agent is allowed to say evidence is insufficient.
