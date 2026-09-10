# Office IT Support — Real-World Issue Catalog v0.3 Expansion

> Expansion of the WorkSpace office IT support corpus.
>
> Aggregate corpus after this file: **650 canonical issue/symptom patterns**, **32 domains**, **58 retained public sources**.
>
> This file adds `IT-0501` through `IT-0650` and source references `S45` through `S58`.

## Evidence posture

The records below are normalized support symptoms/failure states derived from public practitioner reports, vendor communities and official troubleshooting material. They are not prevalence statistics. A signature is a routing/evidence hint only; it is not root-cause proof and grants no remediation authority.

### AA. Active Directory, DNS, DHCP, Group Policy and hybrid identity core services

- IT-0501 — Active Directory replication is failing between one or more domain controllers.
- IT-0502 — One domain controller contains newer/different user or group data than another.
- IT-0503 — DNS zones/records are present on one domain controller but missing on another.
- IT-0504 — Domain controller replication reports access denied/authentication errors.
- IT-0505 — Domain controller replication reports RPC/server unavailable errors.
- IT-0506 — Domain controller replication is delayed because site/link topology is incorrect.
- IT-0507 — Domain controller cannot locate a replication partner because DNS is wrong.
- IT-0508 — SYSVOL/Group Policy content is not consistent across domain controllers.
- IT-0509 — Group Policy applies to some users/devices but not others in the same target scope.
- IT-0510 — Group Policy Result shows expected GPO but setting is not effective.
- IT-0511 — DNS server returns stale/wrong A or PTR record.
- IT-0512 — Static server/printer address overlaps the DHCP pool and creates an IP conflict.
- IT-0513 — DNS scavenging/dynamic-update behavior leaves stale records.
- IT-0514 — DNS forwarder/recursion failure breaks external name resolution.
- IT-0515 — DHCP scope is exhausted and new clients cannot obtain leases.
- IT-0516 — DHCP reservation/exclusion is missing or incorrect for a fixed-address device.
- IT-0517 — DHCP option provides the wrong gateway, DNS server or domain suffix.
- IT-0518 — DHCP failover/secondary server does not provide leases when primary is unavailable.
- IT-0519 — Domain controller outage also removes DNS/DHCP and causes a wider business outage.
- IT-0520 — Microsoft Entra Connect/cloud-sync agent is stopped, unhealthy or cannot reach the cloud service.
- IT-0521 — Directory synchronization works generally but one user/group/device object does not sync.
- IT-0522 — Password hash synchronization stops for all users or a subset of users.
- IT-0523 — Password writeback/SSPR changes cloud password but on-premises credentials remain stale, or vice versa.
- IT-0524 — Hybrid Microsoft Entra join remains pending/fails because device object, tenant ID, proxy or network state is wrong.
- IT-0525 — Authentication changes behave inconsistently because PHS/PTA/SSPR/password-expiry policies are misaligned.

### AB. Microsoft Office, Excel, Word, PowerPoint, OneNote and desktop productivity

- IT-0526 — Excel opens but immediately becomes Not Responding.
- IT-0527 — Excel hangs only when opening one workbook.
- IT-0528 — Excel hangs when automatic calculation runs on a complex workbook.
- IT-0529 — Excel COM/add-in causes crashes or severe slowness.
- IT-0530 — Excel opens a workbook blank/without expected content.
- IT-0531 — Excel file opens read-only although the user expects edit access.
- IT-0532 — Excel cannot save workbook to local/network/cloud location.
- IT-0533 — Excel workbook is corrupt and cannot be opened normally.
- IT-0534 — Excel VBA macro/project fails after Office/security update.
- IT-0535 — Excel printing layout/output differs from screen or expected print area.
- IT-0536 — Word will not open or crashes at startup.
- IT-0537 — One Word document is damaged/corrupt while other documents open normally.
- IT-0538 — Word template/add-in causes slow startup, crashes or unexpected formatting.
- IT-0539 — Word cannot create/open its work/temp file.
- IT-0540 — Word document fonts/layout change between PCs or after export/print.
- IT-0541 — PowerPoint presentation is damaged or cannot open.
- IT-0542 — PowerPoint embedded fonts/media do not render on another PC.
- IT-0543 — PowerPoint presentation/video playback is slow or stutters on meeting-room hardware.
- IT-0544 — Microsoft 365 desktop apps report Unlicensed Product/activation failure.
- IT-0545 — Microsoft 365 activation fails because TPM/credential/work-account state is inconsistent.
- IT-0546 — Office says another account is already signed in and blocks intended tenant/account use.
- IT-0547 — Office add-in is disabled/blocked by tenant policy or application protection.
- IT-0548 — Office add-in works in web app but not desktop app, or vice versa.
- IT-0549 — Office update/security patch introduces a regression in a business workflow.
- IT-0550 — Office shared-computer/VDI activation is not configured correctly and users repeatedly lose activation.

### AC. ERP, SQL, databases, ODBC and line-of-business systems

- IT-0551 — ERP/line-of-business client cannot connect to its database/server.
- IT-0552 — ERP works on LAN but is unusably slow over VPN/WAN.
- IT-0553 — Application reports SQL connection timeout before login completes.
- IT-0554 — Application connects to SQL Server but business query/report times out.
- IT-0555 — SQL Server service/instance is stopped or unavailable.
- IT-0556 — SQL instance moved/changed port and clients still use old connection details.
- IT-0557 — SQL Browser/UDP discovery is blocked and named instance cannot be located.
- IT-0558 — Firewall blocks SQL/ERP application port after network/security change.
- IT-0559 — ODBC DSN is missing on a replacement/new PC.
- IT-0560 — ODBC DSN points to the wrong server/database/driver architecture.
- IT-0561 — 32-bit vs 64-bit ODBC/provider mismatch breaks legacy business application.
- IT-0562 — Database login succeeds for some users but one user/role receives permission denied.
- IT-0563 — Application connection string contains stale hostname/IP/credentials.
- IT-0564 — Database disk/log volume fills and transactions/application writes fail.
- IT-0565 — Database transaction log grows unexpectedly and exhausts storage.
- IT-0566 — Database backup/maintenance job fails and application performance later degrades.
- IT-0567 — Slow/blocking query causes entire ERP screen/workflow to hang.
- IT-0568 — Database locking/deadlock causes intermittent save/update failures.
- IT-0569 — ERP client version is incompatible with server/schema version after upgrade.
- IT-0570 — ERP integration/API/service account password expires and synchronization stops.
- IT-0571 — ERP printing/export to PDF/Excel fails although core transaction entry works.
- IT-0572 — ERP file/share dependency is unavailable even though database is reachable.
- IT-0573 — Antivirus/EDR inspection introduces latency or blocks a legacy ERP component.
- IT-0574 — Vendor blames network while measured failure may be application/database-side; evidence is insufficient to assign ownership.
- IT-0575 — ERP/database problem is intermittent and disappears before engineer captures client/server/network evidence.

### AD. CCTV, NVR/VMS, access control, badges and attendance systems

- IT-0576 — IP camera is powered but offline/unreachable from VMS/NVR.
- IT-0577 — IP camera has no PoE power/link.
- IT-0578 — Camera IP changed/conflicts and NVR/VMS retains old address.
- IT-0579 — Camera can be pinged but RTSP/video stream will not open.
- IT-0580 — Camera stream is intermittent, freezes or reconnects repeatedly.
- IT-0581 — Camera video has severe packet loss/artifacts while management interface remains reachable.
- IT-0582 — Camera credentials changed/expired and VMS reports authentication failure.
- IT-0583 — ONVIF discovery/profile/control fails although RTSP video is available.
- IT-0584 — NVR/VMS cannot add camera because model/firmware/codec/profile is incompatible.
- IT-0585 — NVR/VMS records live video but playback/recorded footage is missing.
- IT-0586 — Recording retention is shorter than expected because storage capacity/bitrate changed.
- IT-0587 — NVR disk/RAID is degraded/full/failing.
- IT-0588 — Motion/event detection is unreliable or produces excessive false alerts.
- IT-0589 — Camera time/NTP mismatch makes recorded event timestamps incorrect.
- IT-0590 — VMS/NVR desktop/web client requires plugin/admin rights or fails after browser/OS update.
- IT-0591 — Remote/mobile CCTV access fails while local viewing works.
- IT-0592 — Door/card reader is offline or not communicating with controller.
- IT-0593 — Door controller loses network/power and doors/readers stop reporting state.
- IT-0594 — Badge/card is valid in system but does not unlock expected door.
- IT-0595 — Badge works on one reader/door but not another.
- IT-0596 — Access-control schedule/time zone/holiday rule denies access unexpectedly.
- IT-0597 — Newly enrolled/deactivated badge state has not propagated to all controllers/readers.
- IT-0598 — Time-attendance terminal cannot upload punches/events to server/cloud.
- IT-0599 — Biometric/badge time clock accepts user locally but attendance record is missing upstream.
- IT-0600 — Security-system fault crosses vendor/IT boundary and requires strict scoped access plus physical evidence rather than broad third-party network access.

### AE. Certificates, PKI, TLS, SMTP relays and machine/application identity

- IT-0601 — Public/internal TLS certificate has expired and service becomes unavailable/untrusted.
- IT-0602 — Certificate is renewed but service still presents the old certificate.
- IT-0603 — Certificate chain/intermediate CA is missing and only some clients trust the service.
- IT-0604 — Certificate hostname/SAN does not match the service name.
- IT-0605 — Client clock/time drift makes a valid certificate appear expired/not-yet-valid.
- IT-0606 — CRL/OCSP/revocation endpoint is unreachable and authentication/TLS validation fails or stalls.
- IT-0607 — AD CS/enterprise CA is offline/unreachable and certificate enrollment stops.
- IT-0608 — Certificate auto-enrollment GPO does not issue/renew expected certificate.
- IT-0609 — Machine/user certificate exists but private key is missing/unusable.
- IT-0610 — Certificate template permissions prevent intended user/device enrollment.
- IT-0611 — Wi-Fi/VPN/802.1X certificate expired and previously working device cannot authenticate.
- IT-0612 — Smart-card/client certificate maps to wrong/missing identity.
- IT-0613 — Reverse proxy/load balancer certificate differs from backend/server certificate and troubleshooting ownership is unclear.
- IT-0614 — Certificate renewal automation/ACME fails silently until service outage.
- IT-0615 — Firewall/proxy blocks ACME validation or certificate renewal endpoint.
- IT-0616 — SMTP relay is unreachable or connection is rejected.
- IT-0617 — Printer/scanner scan-to-email stops because SMTP AUTH/basic authentication policy changed.
- IT-0618 — SMTP sender/service account is blocked by MFA/security defaults/Conditional Access design.
- IT-0619 — Printer supports OAuth but OAuth device-code/token setup or refresh fails.
- IT-0620 — SMTP connector/relay accepts internal mail but external recipients fail.
- IT-0621 — SMTP relay IP/certificate authentication no longer matches connector configuration.
- IT-0622 — TLS/cipher/protocol mismatch prevents legacy printer/application from sending mail.
- IT-0623 — SPF/DKIM/DMARC or sender reputation causes automated application mail to be rejected/quarantined.
- IT-0624 — Shared certificate is unknowingly used by multiple services, so one expiry causes several outages at once.
- IT-0625 — Certificate inventory/expiry monitoring is absent, so engineer discovers dependency only after outage.

### AF. Remote sites, WAN, ISP, SD-WAN and home-office edge cases

- IT-0626 — Entire branch/remote site loses Internet and corporate connectivity.
- IT-0627 — Branch router/firewall is unreachable so central team has no remote telemetry.
- IT-0628 — ISP reports circuit healthy but branch router WAN interface is down.
- IT-0629 — WAN cable is unplugged/moved to the wrong physical port.
- IT-0630 — Dual-WAN failover shows both circuits up but traffic blackholes through one path.
- IT-0631 — Backup WAN circuit works but inbound hosted-service DNS still points to failed primary path.
- IT-0632 — Branch VPN/site-to-site tunnel is down while local Internet remains available.
- IT-0633 — Site-to-site VPN tunnel is up but one subnet/VLAN is not routed.
- IT-0634 — SD-WAN policy sends application traffic over the wrong/degraded circuit.
- IT-0635 — WAN packet loss/jitter affects voice/video/ERP before basic ping appears fully down.
- IT-0636 — MTU/MSS/fragmentation problem makes ERP/VPN/web application extremely slow or partially functional.
- IT-0637 — NAT/firewall state causes one direction/session type to fail intermittently.
- IT-0638 — Public IP/CGNAT/carrier change breaks inbound remote-management expectation.
- IT-0639 — Dynamic/public DNS record does not update after WAN address changes.
- IT-0640 — Branch DNS/DHCP dependency is hosted centrally and WAN loss prevents local users from working normally.
- IT-0641 — Local branch switch/AP remains powered but upstream WAN/router is unavailable.
- IT-0642 — Remote office loses power and all network telemetry disappears simultaneously.
- IT-0643 — Home worker reports “VPN is broken” but local ISP/Wi-Fi is unstable before VPN starts.
- IT-0644 — Home router/DNS/filtering blocks VPN or corporate service ports/domains.
- IT-0645 — Home/hotel Wi-Fi captive portal prevents VPN until browser authentication completes.
- IT-0646 — Mobile hotspot works while home broadband does not, isolating issue toward local ISP/router path.
- IT-0647 — Remote user bandwidth is adequate for web but upload/jitter is insufficient for meetings/remote desktop.
- IT-0648 — Remote support cannot distinguish powered-off equipment from failed WAN because no out-of-band/physical evidence exists.
- IT-0649 — Site outage is extended because local staff perform untracked cable/power changes during troubleshooting.
- IT-0650 — Restoring service requires onsite hands/console/physical inspection; software agent must return `PHYSICAL_EVIDENCE_REQUIRED` instead of guessing.

## Added public-source registry

- **S45 — Microsoft Learn — Active Directory replication troubleshooting guidance**: replication can fail due to network, DNS, authentication/authorization, topology, engine/database and hardware conditions. https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/troubleshoot-adreplication-guidance
- **S46 — Microsoft Learn — DNS troubleshooting guidance**: server/client IP configuration, authoritative data, recursion, zone transfer and name-resolution evidence. https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/troubleshoot-dns-guidance
- **S47 — Microsoft Learn — Applying Group Policy troubleshooting guidance**: GPO event logs, scope and diagnostic data collection. https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/applying-group-policy-troubleshooting-guidance
- **S48 — Microsoft Learn — Microsoft Entra Connect password-hash sync troubleshooting**: no-password-sync, single-object sync, connector permissions, heartbeat and reachability failures. https://learn.microsoft.com/en-us/azure/active-directory/hybrid/connect/tshoot-connect-password-hash-synchronization
- **S49 — Microsoft Learn — Microsoft Entra hybrid join troubleshooting**: join phases, device object sync, proxy/network and authentication failures. https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-hybrid-join-windows-current
- **S50 — Microsoft Support — Excel troubleshooting and top issues**: activation, hangs/freezes, corrupted workbook, printing, edit/read-only and recent regressions. https://support.microsoft.com/en-us/Excel/troubleshooting-and-support
- **S51 — Microsoft Learn — Microsoft 365 Apps troubleshooting**: Word damaged files, Office sign-in/work-file problems, Excel save/blank-opening and PowerPoint presentation/font issues. https://learn.microsoft.com/en-us/troubleshoot/microsoft-365-apps/office-client-welcome
- **S52 — Microsoft Learn — SQL Server timeout/connectivity troubleshooting**: connection vs query timeout, service/port/protocol/firewall/name-resolution causes. https://learn.microsoft.com/en-us/troubleshoot/sql/database-engine/connect/timeout-expired-error
- **S53 — Reddit r/sysadmin — ERP unusably slow via VPN**: SQL-backed ERP performance over VPN/WAN and MTU/network/application boundary discussion. https://www.reddit.com/r/sysadmin/comments/1szr0ih/erp_software_unusable_slow_via_vpn/
- **S54 — Reddit r/sysadmin — security camera support boundary**: real-world division of responsibility between internal IT, MSP and surveillance/security vendors. https://www.reddit.com/r/sysadmin/comments/1iteitt/do_you_support_security_cameras/
- **S55 — Reddit r/sysadmin — business NVR pain**: plugins, local-admin requirements, ONVIF compatibility, motion recording and NVR replacement concerns. https://www.reddit.com/r/sysadmin/comments/12ksp2n/any_nvrs_out_there_people_like_rather_than_tolerate/
- **S56 — Reddit r/sysadmin — access-control systems**: door/card-reader controller deployment and operational support in small organizations. https://www.reddit.com/r/sysadmin/comments/1hmq9ou/access_control_systems/
- **S57 — Reddit r/sysadmin — scan-to-email outage**: Microsoft 365 authentication/security changes causing printer scan-to-email failures across sites. https://www.reddit.com/r/sysadmin/comments/1gv0tjb/all_of_our_network_printers_scan_to_email_across/
- **S58 — Reddit r/sysadmin — remote-site outage caused by physical WAN cabling**: central team lost visibility until onsite physical inspection revealed WAN cable moved to wrong router port. https://www.reddit.com/r/sysadmin/comments/146izfc/user_inflicted_outage/

## WorkSpace engineering guidance

- Keep AD/DNS/DHCP dependencies explicit: a “network outage” can actually be a domain-service outage and vice versa.
- Capture client **and** server evidence for SQL/ERP, DNS and identity failures instead of assigning blame based on symptom wording.
- Treat CCTV/access control as security-sensitive infrastructure: evidence collection and vendor access must be scoped and auditable.
- Certificate/SMTP failures often affect many unrelated-looking applications simultaneously; inventory dependency and expiry data.
- Remote-site loss of telemetry must not be interpreted as a specific router/switch/power failure. Require physical/out-of-band evidence when the boundary is unknowable.
