# Office IT Support — Real-World Issue Catalog v0.1

> Purpose: seed the WorkSpace diagnostics / support knowledge base with real-world employee complaints and recurring engineer-observed failure modes collected from public IT support communities, vendor forums, official troubleshooting libraries, and managed-service providers.

## Status

- Canonical symptom patterns: **380**
- Domains: **20**
- Public sources reviewed and retained in source registry: **30**
- Collection date: **2026-09-08**
- Collection scope: public sources only; no private Facebook/Slack/Discord/group content was accessed.
- Evidence posture: this is a symptom/problem catalog, not a statistical prevalence study. Community reports are anecdotal unless backed by vendor documentation.

## Evidence and normalization policy

This catalog intentionally separates what a user reports from what an engineer may eventually prove. A symptom such as “Internet is slow” does **not** authorize a root-cause claim such as “the switch is faulty.” WorkSpace should collect evidence first, correlate signals, and only then raise a bounded diagnosis.

The source set combines four evidence families:

1. Public practitioner communities where support engineers describe actual tickets and recurring complaints.
2. Public vendor communities where fleet/device-specific failures and regressions are discussed.
3. Official vendor troubleshooting documentation that describes supported failure states and diagnostic paths.
4. MSP/help-desk providers publishing recurring service-desk issue categories.

Duplicate wording was normalized into canonical symptom signatures. Wording below is deliberately operational: it should be usable later for routing, test prompts, evidence plans, and runbook selection.

## Cross-source recurring themes

Across the reviewed sources, the strongest recurring families are:

- password reset, account lockout, MFA/2SV and identity problems;
- printers, print queues, drivers, GPO deployment and scan-to-email;
- Outlook/email delivery, profile corruption and mailbox access;
- Teams/Zoom/meeting-room audio, camera, sign-in and display problems;
- OneDrive/SharePoint sync, permission and collaboration failures;
- Wi-Fi, DNS, DHCP, roaming, intermittent Internet and slow networking;
- VPN connection, split-DNS, stale DNS, MFA and remote-access problems;
- Windows Update, login/profile, BitLocker and post-update regression;
- docking station, USB-C, monitor, charging and peripheral failures;
- mapped drives, SMB/file-server permission, GPO and domain-trust issues;
- software install/activation/browser/business-app problems;
- security/phishing/EDR/certificate/policy alerts;
- backup/storage/server/virtualization failures;
- onboarding, offboarding, access requests and licensing;
- physical-layer, switch, PoE, cabling and WAN problems.

## Canonical issue catalog

### A. Identity, authentication, MFA and account access

- IT-0001 — User forgot password / requests password reset.
- IT-0002 — Account is locked after repeated failed sign-in attempts.
- IT-0003 — Password changed but old password still appears to be required on one device.
- IT-0004 — User can sign in to Windows but not Microsoft 365/SaaS.
- IT-0005 — User can sign in to web apps but not the desktop client.
- IT-0006 — MFA prompt never arrives.
- IT-0007 — MFA push arrives but approval does not complete sign-in.
- IT-0008 — Authenticator app was replaced/lost and user cannot enroll again.
- IT-0009 — SMS/phone MFA is not received.
- IT-0010 — MFA/2SV loops repeatedly after successful verification.
- IT-0011 — New phone/device cannot complete MFA registration.
- IT-0012 — Conditional Access blocks a user unexpectedly.
- IT-0013 — Sign-in says device is not compliant although user believes it is managed.
- IT-0014 — User is denied because required group/role membership is missing.
- IT-0015 — Privileged/admin account cannot elevate when needed.
- IT-0016 — SSO repeatedly asks for credentials.
- IT-0017 — Kerberos/domain authentication fails only when remote/VPN-connected.
- IT-0018 — Service account password expired or credentials no longer work.
- IT-0019 — User cannot recover account because recovery methods are unavailable.
- IT-0020 — Administrator is locked out by MFA/2SV policy and cannot administer tenant.

### B. Windows boot, login, profile, update and crash

- IT-0021 — PC will not boot into Windows.
- IT-0022 — PC boots to automatic repair/recovery repeatedly.
- IT-0023 — Black screen after Windows sign-in.
- IT-0024 — Windows sign-in hangs on Welcome/Preparing Windows.
- IT-0025 — Temporary profile is loaded instead of the normal profile.
- IT-0026 — User profile is corrupt or desktop/settings disappear.
- IT-0027 — Windows Update fails to download or install.
- IT-0028 — Windows Update is stuck at a percentage for a long time.
- IT-0029 — PC repeatedly asks to restart to finish updates.
- IT-0030 — Device becomes unstable after a Windows feature/quality update.
- IT-0031 — Blue screen/BSOD occurs intermittently.
- IT-0032 — PC unexpectedly restarts without an obvious cause.
- IT-0033 — BitLocker recovery key is requested unexpectedly.
- IT-0034 — BitLocker recovery key cannot be located/retrieved.
- IT-0035 — Windows Hello PIN/fingerprint/face sign-in no longer works.
- IT-0036 — Domain trust relationship fails at logon.
- IT-0037 — Login works in office but fails when remote/offline.
- IT-0038 — Group Policy appears not to apply after sign-in.
- IT-0039 — Start menu/taskbar/File Explorer fails or becomes unresponsive.
- IT-0040 — Windows activation reports not activated or license error.

### C. Endpoint performance, storage and application responsiveness

- IT-0041 — “My computer is slow.”
- IT-0042 — PC is slow only after login/startup.
- IT-0043 — PC becomes slow after running for several hours/days.
- IT-0044 — CPU usage remains abnormally high.
- IT-0045 — Memory/RAM usage remains abnormally high.
- IT-0046 — Disk usage stays at or near 100%.
- IT-0047 — System drive is almost/full and applications stop working correctly.
- IT-0048 — User profile consumes unexpectedly large disk space.
- IT-0049 — Browser becomes slow or consumes excessive memory.
- IT-0050 — Office application freezes or shows “Not Responding.”
- IT-0051 — File Explorer is extremely slow opening folders.
- IT-0052 — Search/indexing no longer returns expected files/mail.
- IT-0053 — PC freezes randomly and requires forced restart.
- IT-0054 — Application takes unusually long to start.
- IT-0055 — Application is fast locally but slow when opening network/cloud files.
- IT-0056 — Large files fail or take excessive time to copy.
- IT-0057 — SSD/HDD reports health, SMART or I/O errors.
- IT-0058 — Disk space suddenly drops without an obvious user action.
- IT-0059 — User reports performance degradation after antivirus/EDR update.
- IT-0060 — Performance problem occurs only while docked/on external displays.

### D. Hardware, power, battery and thermal

- IT-0061 — Desktop/laptop does not power on.
- IT-0062 — Device powers on but shows no display/POST.
- IT-0063 — Laptop battery will not charge.
- IT-0064 — Battery drains unusually fast.
- IT-0065 — Battery percentage is stuck or inaccurate.
- IT-0066 — Laptop shuts down when unplugged.
- IT-0067 — AC adapter is not detected or charges intermittently.
- IT-0068 — PC shuts down under load.
- IT-0069 — Fan runs constantly at high speed.
- IT-0070 — Device becomes unusually hot/thermal throttles.
- IT-0071 — RAM/memory hardware errors are reported.
- IT-0072 — SSD/HDD disappears intermittently from BIOS/OS.
- IT-0073 — Keyboard keys fail/intermittently repeat.
- IT-0074 — Touchpad stops working or behaves erratically.
- IT-0075 — Webcam is not detected.
- IT-0076 — Built-in microphone/speakers are not detected.
- IT-0077 — Bluetooth disappears or cannot discover devices.
- IT-0078 — BIOS/firmware update fails or leaves device unstable.
- IT-0079 — Device clock resets or BIOS settings are lost.
- IT-0080 — Physical damage/liquid/spill/drop causes intermittent operation.

### E. Docking stations, USB-C, displays and peripherals

- IT-0081 — USB-C dock is not detected.
- IT-0082 — Dock powers/charges laptop but peripherals are not detected.
- IT-0083 — Dock peripherals work but laptop does not charge.
- IT-0084 — External monitor is not detected through dock.
- IT-0085 — One of two/multiple external monitors is missing.
- IT-0086 — External monitors intermittently blank/flicker.
- IT-0087 — Monitor works over direct HDMI/USB-C but not through dock.
- IT-0088 — Dock Ethernet adapter is missing/intermittent.
- IT-0089 — Dock USB keyboard/mouse disconnects randomly.
- IT-0090 — Dock audio device disappears or changes unexpectedly.
- IT-0091 — USB-C port supplies power but no data/video.
- IT-0092 — USB-C port works on one side/port but not another.
- IT-0093 — Dock stopped working after BIOS/firmware/driver update.
- IT-0094 — Dock works after power-cycle only, then fails again later.
- IT-0095 — External display resolution/refresh rate is incorrect.
- IT-0096 — Display arrangement resets after docking/undocking.
- IT-0097 — USB storage device is not recognized.
- IT-0098 — USB device repeatedly connects/disconnects.
- IT-0099 — KVM/display adapter works with another PC but not this one.
- IT-0100 — Peripheral driver appears installed but device remains unusable.

### F. Printing, label printers and scanning

- IT-0101 — Printer shows offline although it is powered on.
- IT-0102 — Print job remains stuck in queue.
- IT-0103 — Print spooler repeatedly crashes/stops.
- IT-0104 — User can print to one printer but not another.
- IT-0105 — Network printer cannot be discovered/added.
- IT-0106 — Printer deployed by GPO does not appear.
- IT-0107 — GPO printer appears for some users but not others.
- IT-0108 — Printer driver installation fails/requires unexpected admin rights.
- IT-0109 — Printing stopped after Windows/driver update.
- IT-0110 — Printer prints blank/garbled/wrong characters.
- IT-0111 — Wrong tray, paper size, duplex or finishing option is used.
- IT-0112 — Default printer changes unexpectedly.
- IT-0113 — Print output is extremely slow.
- IT-0114 — Printer IP changed and clients still use old address/port.
- IT-0115 — Secure/PIN printing does not release job.
- IT-0116 — Scan-to-email fails.
- IT-0117 — Scan-to-folder/SMB fails.
- IT-0118 — Scanner/TWAIN/WIA device not detected by application.
- IT-0119 — Label printer prints shifted/misaligned/wrong label size.
- IT-0120 — Multifunction printer authentication/address-book access fails.

### G. LAN, Wi-Fi, DHCP, DNS and general connectivity

- IT-0121 — “Internet is down.”
- IT-0122 — “Internet/network is slow.”
- IT-0123 — Only one user/device has no network connectivity.
- IT-0124 — Multiple users in the same area lose network connectivity.
- IT-0125 — Wired Ethernet shows connected but has no Internet.
- IT-0126 — Ethernet link repeatedly drops/reconnects.
- IT-0127 — Device receives APIPA/169.254.x.x instead of DHCP address.
- IT-0128 — DHCP lease is not obtained/renewed.
- IT-0129 — Duplicate IP address/IP conflict is reported.
- IT-0130 — Device can ping IP addresses but cannot resolve DNS names.
- IT-0131 — Some websites/services resolve while others do not.
- IT-0132 — DNS lookup is intermittently slow/timeouts.
- IT-0133 — Wi-Fi network/SSID is not visible.
- IT-0134 — Wi-Fi password is accepted but connection fails.
- IT-0135 — Wi-Fi repeatedly disconnects and reconnects.
- IT-0136 — Wi-Fi signal is strong but throughput is poor.
- IT-0137 — Wi-Fi works in one area but fails in another.
- IT-0138 — Client roams poorly/sticks to a distant access point.
- IT-0139 — Client loops between APs or disconnects during roaming.
- IT-0140 — 2.4 GHz works but 5/6 GHz does not, or vice versa.
- IT-0141 — Corporate Wi-Fi authentication/RADIUS/802.1X fails.
- IT-0142 — Guest Wi-Fi works but corporate Wi-Fi does not.
- IT-0143 — Network access works until Teams/video traffic starts.
- IT-0144 — Packet loss/jitter causes intermittent application failures.
- IT-0145 — Network issue appears only after switch/AP/router firmware update.

### H. VPN and remote access

- IT-0146 — VPN client will not connect.
- IT-0147 — VPN credentials are accepted but tunnel never establishes.
- IT-0148 — VPN MFA prompt is not received/completed.
- IT-0149 — VPN connects but internal resources are unreachable.
- IT-0150 — VPN connects but Internet access disappears.
- IT-0151 — VPN connects but DNS/name resolution fails.
- IT-0152 — Internal DNS names fail while public Internet works over VPN.
- IT-0153 — Split-DNS/split-tunnel behavior is incorrect.
- IT-0154 — DNS remains broken after disconnecting from VPN.
- IT-0155 — VPN drops repeatedly/intermittently.
- IT-0156 — VPN is connected but performance is extremely slow.
- IT-0157 — VPN works on home Wi-Fi but not mobile hotspot/hotel network.
- IT-0158 — VPN works for some users but not one account/device.
- IT-0159 — VPN client update breaks previously working configuration.
- IT-0160 — VPN certificate is expired/missing/untrusted.
- IT-0161 — Remote Desktop/RDP works on LAN but not through VPN.
- IT-0162 — RDP session connects then immediately disconnects/freezes.
- IT-0163 — Remote support tool cannot reach device behind firewall/NAT.
- IT-0164 — Always On VPN does not establish before user logon.
- IT-0165 — Remote device cannot reach domain controllers/GPO after VPN connection.

### I. Outlook, email and Exchange

- IT-0166 — Outlook will not open.
- IT-0167 — Outlook opens in safe mode only.
- IT-0168 — Outlook repeatedly asks for password.
- IT-0169 — Outlook profile appears corrupt and needs recreation/reprofile.
- IT-0170 — Outlook is connected but new mail is not arriving.
- IT-0171 — User can send mail but cannot receive.
- IT-0172 — User can receive but cannot send.
- IT-0173 — Mail is delayed for minutes/hours.
- IT-0174 — Sender says message was sent but recipient cannot find it.
- IT-0175 — Message is quarantined/flagged as spam unexpectedly.
- IT-0176 — Legitimate sender/domain is blocked.
- IT-0177 — User cannot open/download attachments.
- IT-0178 — Outlook crashes when opening/previewing attachments.
- IT-0179 — Shared mailbox does not appear or cannot be opened.
- IT-0180 — Shared mailbox permissions are missing/delayed.
- IT-0181 — Calendar invites/updates do not synchronize correctly.
- IT-0182 — Free/busy information is wrong/unavailable.
- IT-0183 — Search in Outlook returns incomplete/no results.
- IT-0184 — OST/cache grows excessively or synchronization remains stuck.
- IT-0185 — Outlook works in web browser but desktop client fails.

### J. Teams, Zoom, conferencing and meeting rooms

- IT-0186 — Teams will not start/load.
- IT-0187 — Teams sign-in fails or loops.
- IT-0188 — Teams presence/status is wrong or not updating.
- IT-0189 — Teams messages/chats fail to send or load.
- IT-0190 — Teams files/tab cannot be opened.
- IT-0191 — User cannot join a Teams/Zoom meeting.
- IT-0192 — Meeting connects but microphone is unavailable.
- IT-0193 — Meeting connects but speakers/audio output is unavailable.
- IT-0194 — Camera is unavailable/black/not detected in meeting app.
- IT-0195 — Other participants report echo/feedback.
- IT-0196 — Audio is robotic/choppy/dropouts occur.
- IT-0197 — Video freezes or quality is poor despite apparent connectivity.
- IT-0198 — Screen sharing fails or shows black screen.
- IT-0199 — Meeting recording is missing/unavailable.
- IT-0200 — Teams/Zoom works on one network but not another.
- IT-0201 — Meeting-room console is offline/unhealthy.
- IT-0202 — Meeting-room display is not detected/unhealthy.
- IT-0203 — Meeting-room microphone/speaker/camera health is unhealthy.
- IT-0204 — Room resource/calendar/sign-in account does not load meetings.
- IT-0205 — HDMI ingest/content sharing in room does not work.

### K. OneDrive, SharePoint and cloud file collaboration

- IT-0206 — OneDrive will not sign in.
- IT-0207 — OneDrive reports sync paused/stuck.
- IT-0208 — OneDrive shows red X/sync errors on files/folders.
- IT-0209 — Files appear on web but not on local PC.
- IT-0210 — Files appear locally but changes are not uploaded.
- IT-0211 — OneDrive reports storage quota/full account.
- IT-0212 — OneDrive sign-in/license/credential mismatch error occurs.
- IT-0213 — Known Folder Move/Desktop/Documents backup fails.
- IT-0214 — Duplicate/conflicted copies are created.
- IT-0215 — File is locked for editing unexpectedly.
- IT-0216 — SharePoint site/library is missing for a user.
- IT-0217 — SharePoint access is denied despite expected membership.
- IT-0218 — SharePoint permission inheritance/unique permissions cause unexpected access.
- IT-0219 — User can view but cannot edit/upload/delete files.
- IT-0220 — Syncing a SharePoint library to OneDrive fails.
- IT-0221 — SharePoint/OneDrive file path/name is too long/invalid.
- IT-0222 — Files On-Demand placeholder will not download/open.
- IT-0223 — Offline/online status causes cloud file to be unavailable.
- IT-0224 — Recently deleted cloud file/folder must be recovered.
- IT-0225 — User sees stale/old version of a collaboratively edited file.

### L. File servers, SMB, mapped drives, permissions and GPO

- IT-0226 — Mapped drive is missing after login.
- IT-0227 — Mapped drive shows disconnected/red X but may still open.
- IT-0228 — Mapped drive does not reconnect after VPN/network change.
- IT-0229 — File Explorer hangs/slow when opening mapped drive.
- IT-0230 — SMB share is reachable by IP but not hostname.
- IT-0231 — SMB share is reachable by hostname but access is denied.
- IT-0232 — User suddenly loses access to folder previously accessible.
- IT-0233 — NTFS/share permissions are wrong or unexpectedly changed.
- IT-0234 — Group membership changed but file permissions do not update immediately.
- IT-0235 — User can read files but cannot create/modify/delete them.
- IT-0236 — File is locked/open by another user/process.
- IT-0237 — Network file disappears/deleted and actor is unknown.
- IT-0238 — Copying files to/from file server is unusually slow.
- IT-0239 — Large file copy fails/interrupted over network/VPN.
- IT-0240 — Offline Files/CSC causes stale/conflicting content.
- IT-0241 — DFS namespace/referral fails or points to wrong target.
- IT-0242 — GPO drive mapping fails for one/some users.
- IT-0243 — GPO update/`gpupdate` does not produce expected policy state.
- IT-0244 — Domain trust relationship breaks intermittently on laptops.
- IT-0245 — Login script/network resource mapping fails when network is not ready.

### M. Software installation, activation, browser and business apps

- IT-0246 — User cannot install approved software because admin rights are required.
- IT-0247 — Software installation fails with generic MSI/setup error.
- IT-0248 — Application update fails or repeatedly retries.
- IT-0249 — Application stopped launching after update.
- IT-0250 — Application crashes only for one user profile.
- IT-0251 — Application license/activation is missing/expired.
- IT-0252 — User is licensed but application says no license/subscription.
- IT-0253 — Browser cannot open an internal site.
- IT-0254 — Browser certificate warning appears for internal/external site.
- IT-0255 — Browser extension required by organization is missing/disabled.
- IT-0256 — Browser proxy/PAC settings prevent access.
- IT-0257 — Browser SSO works in one browser but not another.
- IT-0258 — Java/.NET/runtime dependency is missing or incompatible.
- IT-0259 — Line-of-business application cannot connect to backend/database.
- IT-0260 — Application works on LAN but not VPN/remote network.
- IT-0261 — Application cannot open file association/default app type.
- IT-0262 — Software is blocked by application control/security policy.
- IT-0263 — Macro/add-in/plugin fails or is disabled.
- IT-0264 — Office application activation/update/channel mismatch occurs.
- IT-0265 — Application configuration was reset/lost after reinstall/update.

### N. Security, phishing, EDR, certificates and policy

- IT-0266 — User reports suspected phishing email.
- IT-0267 — User clicked a suspicious link/attachment and asks what to do.
- IT-0268 — User reports unexpected MFA prompts/push fatigue.
- IT-0269 — Endpoint antivirus/EDR detects/quarantines a file.
- IT-0270 — EDR blocks legitimate business software/process.
- IT-0271 — Endpoint appears isolated from network by security tooling.
- IT-0272 — Firewall blocks expected application/service traffic.
- IT-0273 — Web filtering blocks a legitimate business URL.
- IT-0274 — User requests URL/domain allowlisting.
- IT-0275 — Suspicious pop-up/browser redirect/adware is reported.
- IT-0276 — Ransomware/mass file-encryption symptoms are reported.
- IT-0277 — Account shows suspicious login/new-location activity.
- IT-0278 — Certificate expired and service/app stops working.
- IT-0279 — Certificate chain is untrusted on some/all devices.
- IT-0280 — Client certificate is missing/expired and authentication fails.
- IT-0281 — TLS inspection/proxy causes application certificate errors.
- IT-0282 — Device compliance/security baseline marks endpoint non-compliant.
- IT-0283 — USB/removable media is blocked by policy.
- IT-0284 — BitLocker/encryption compliance is not reported correctly.
- IT-0285 — User needs spam/quarantine release or false-positive review.

### O. Mobile devices, MDM and BYOD

- IT-0286 — Mobile device cannot enroll in MDM/Intune.
- IT-0287 — Device is enrolled but remains non-compliant.
- IT-0288 — Company Portal enrollment loops/fails.
- IT-0289 — Work email profile will not install/synchronize on phone.
- IT-0290 — Mobile Outlook/Teams cannot sign in while desktop works.
- IT-0291 — Required managed application will not install/update.
- IT-0292 — Wi-Fi profile/certificate deployed by MDM does not connect.
- IT-0293 — VPN profile deployed to mobile does not connect.
- IT-0294 — Device passcode/encryption policy is not accepted.
- IT-0295 — User replaced phone and old device registration blocks new setup.
- IT-0296 — BYOD app protection prevents copy/paste/open-in unexpectedly.
- IT-0297 — Remote wipe/retire operation is pending/not reflected.
- IT-0298 — Mobile device storage is full and work apps stop syncing.
- IT-0299 — Phone cannot receive MFA push due notification/background restrictions.
- IT-0300 — Lost/stolen managed device needs secure containment workflow.

### P. Server, virtualization, storage and backup

- IT-0301 — Server is unreachable/ping/management unavailable.
- IT-0302 — Server unexpectedly rebooted/shut down.
- IT-0303 — Windows/Linux service is stopped and application is unavailable.
- IT-0304 — Server CPU remains saturated.
- IT-0305 — Server memory/swap pressure is high.
- IT-0306 — Server filesystem/volume is full.
- IT-0307 — RAID/storage array reports degraded disk.
- IT-0308 — SAN/NAS/storage latency is unusually high.
- IT-0309 — Virtual machine will not start.
- IT-0310 — VM is slow although guest metrics appear normal.
- IT-0311 — Hypervisor host is overloaded/unhealthy.
- IT-0312 — Snapshot/checkpoint cannot be created/removed/consolidated.
- IT-0313 — Backup job fails.
- IT-0314 — Backup succeeds but verification/restore test fails.
- IT-0315 — Backup repository/storage is full.
- IT-0316 — Backup agent cannot contact server/repository.
- IT-0317 — Restore request cannot find required recovery point/file.
- IT-0318 — Scheduled task/automation/maintenance job stops running.
- IT-0319 — Monitoring reports service down while users report it works, or vice versa.
- IT-0320 — Time/NTP drift causes authentication/certificate/application failures.

### Q. VoIP, softphones, phones and headsets

- IT-0321 — Desk phone/softphone cannot register/sign in.
- IT-0322 — User can hear remote party but remote party cannot hear user (one-way audio).
- IT-0323 — User cannot hear remote party but remote party hears user.
- IT-0324 — Calls drop unexpectedly.
- IT-0325 — Call audio is choppy/robotic/delayed.
- IT-0326 — Incoming calls do not ring.
- IT-0327 — Outgoing calls fail to connect.
- IT-0328 — Wrong caller ID/extension is presented.
- IT-0329 — Voicemail is unavailable/not synchronized.
- IT-0330 — Headset is not detected by phone/PC.
- IT-0331 — Headset microphone/speaker selects wrong audio device.
- IT-0332 — Bluetooth headset repeatedly disconnects.
- IT-0333 — Phone obtains no IP address/PoE power.
- IT-0334 — Phone registers only after rebooting switch/port/device.
- IT-0335 — Softphone works off VPN but not through VPN/firewall path.

### R. User lifecycle, access requests and service operations

- IT-0336 — New starter account/device is not ready on first day.
- IT-0337 — New starter lacks required groups/app permissions.
- IT-0338 — New starter lacks mailbox/license/Teams/OneDrive provisioning.
- IT-0339 — Employee transfer/role change retains wrong old permissions.
- IT-0340 — Employee transfer needs new department share/app access.
- IT-0341 — Leaver/offboarding account remains active longer than intended.
- IT-0342 — Offboarding needs mailbox/file ownership delegation/transfer.
- IT-0343 — Access request is approved but entitlement is not effective.
- IT-0344 — Access request lacks an identifiable owner/approver.
- IT-0345 — User requests local administrator rights.
- IT-0346 — User requests software installation/deployment.
- IT-0347 — User requests shared mailbox/distribution list membership.
- IT-0348 — User requests shared folder/SharePoint permission.
- IT-0349 — User requests new/replacement device/peripheral.
- IT-0350 — Repeated ticket has no durable knowledge article/runbook and recurs.

### S. Cloud, SaaS, licensing and service health

- IT-0351 — SaaS service is unreachable for multiple users.
- IT-0352 — SaaS works for some users but not one tenant/account/group.
- IT-0353 — Service status page reports incident matching user symptoms.
- IT-0354 — SaaS SSO/SAML/OIDC login fails.
- IT-0355 — User account exists but SaaS provisioning/SCIM did not create/update it.
- IT-0356 — SaaS license/seat is unavailable/exhausted.
- IT-0357 — License was assigned but entitlement is delayed/not recognized.
- IT-0358 — API/integration token expired/revoked.
- IT-0359 — Third-party integration stops synchronizing data.
- IT-0360 — Cloud service works in browser but local sync/client does not.
- IT-0361 — Cloud application reports region/tenant/policy access restriction.
- IT-0362 — Cloud storage quota is exceeded.
- IT-0363 — SaaS audit/logging information is insufficient to explain reported event.
- IT-0364 — Vendor-side change/update causes client regression.
- IT-0365 — User cannot determine whether incident is local, network, identity or SaaS-side.

### T. Network infrastructure, PoE and physical-layer operations

- IT-0366 — Switch port is down/no link for a connected endpoint.
- IT-0367 — Switch port flaps up/down intermittently.
- IT-0368 — PoE endpoint/phone/AP/camera has no power.
- IT-0369 — PoE budget is exhausted/insufficient for endpoints.
- IT-0370 — Interface reports excessive CRC/errors/drops.
- IT-0371 — Speed/duplex negotiation is incorrect.
- IT-0372 — VLAN assignment is wrong and endpoint reaches wrong/no network.
- IT-0373 — Trunk/native/tagging configuration breaks connectivity.
- IT-0374 — Spanning-tree/loop event causes broadcast storm or intermittent outage.
- IT-0375 — Uplink is saturated/congested.
- IT-0376 — WAN/ISP circuit is down or unstable.
- IT-0377 — Firewall/NAT rule change breaks a business service.
- IT-0378 — Access point is online but clients cannot pass traffic.
- IT-0379 — Cabling/patch-panel/connector fault causes intermittent link.
- IT-0380 — Remote evidence disappears because endpoint/network/power is physically unavailable; physical verification is required.

## Recommended WorkSpace normalization schema

Each incoming complaint should eventually be normalized into a bounded record such as:

```yaml
issue_signature: IT-xxxx
reported_symptom: "verbatim or localized user statement"
normalized_symptom: "canonical symptom"
domain: "identity|endpoint|network|email|..."
scope: "single_user|single_device|site|multi_site|unknown"
onset: "time first observed if known"
reproducibility: "always|intermittent|unknown"
network_context: "LAN|WiFi|VPN|Internet|offline|unknown"
authority_required: "none|read_only|admin|human_physical_action"
evidence_required:
  - "bounded evidence type(s)"
safety_gate: "fail_closed"
```

The normalized symptom is a routing input, **not** proof of root cause.

## Recommended first evidence families

Use the least-privileged, read-only evidence source that can discriminate hypotheses. Examples:

- Identity: sign-in/audit events, account lock state, MFA method/registration status, policy result.
- Windows endpoint: Event Viewer/System/Application, reliability/crash/update history, device/driver state, storage/SMART, performance counters.
- Network: interface/link state, IP configuration, DHCP lease, DNS query result, route table, packet loss/latency, AP/switch-port telemetry.
- VPN: client state/logs, adapter/DNS/routes before/during/after connection, gateway-side session result when authorized.
- Microsoft 365/SaaS: service health, client state, license/entitlement, sign-in evidence, sync status.
- File/SMB: name resolution, reachability, SMB error, share/NTFS effective access, GPO mapping evidence, server audit logs.
- Printing: device reachability, queue/spooler, port/driver, deployment policy, device-side error state.
- Hardware/dock: physical power/link evidence, Device Manager/USB-C/Thunderbolt state, firmware/BIOS/driver versions, known-good cable/dock/display comparison.
- Security: alert/quarantine/audit evidence first; do not auto-disable controls to “make it work.”
- Server/backup: service status, event logs, resource/storage health, job logs, restore verification state.

## Source registry

The URLs below are retained for provenance and future refresh. They are public sources; availability/content can change.

- **S01 — Reddit r/msp — Top 10 common tickets**: recurring MSP tickets including password resets, onboarding/offboarding, OneDrive sync, URL whitelist, software install, email restore, SharePoint permissions and backup failures. https://www.reddit.com/r/msp/comments/1bl1lqe/top_10_common_tickets/
- **S02 — Reddit r/it — Corporate IT help-desk tickets**: practitioner discussion including account lockout, printers, Intune/RADIUS, BitLocker, peripherals and external displays. https://www.reddit.com/r/it/comments/1m0nvju/what_are_your_most_common_tickets_in_corporate_it/
- **S03 — Reddit r/helpdesk — Basic Troubleshooting**: frontline diagnostic patterns including power, cable and basic endpoint checks. https://www.reddit.com/r/helpdesk/comments/1kvz0iw/basic_troubleshooting/
- **S04 — Reddit r/sysadmin — user complaints/slow computer**: practitioner examples of vague performance tickets and support triage. https://www.reddit.com/r/sysadmin/comments/1bk6zo9/users_complaining_their_computer_is_slow/
- **S05 — Reddit r/sysadmin — Windows 11 24H2 problems**: reports including Teams/WebView2, SMB, SSO, Outlook, BSOD and printing regressions. https://www.reddit.com/r/sysadmin/comments/1h0grnf/windows_11_24h2_problems/
- **S06 — Microsoft Learn — Windows Update troubleshooting**: official Windows Update failure troubleshooting. https://learn.microsoft.com/troubleshoot/windows-client/installing-updates-features-roles/common-issues
- **S07 — Microsoft Learn — BitLocker troubleshooting**: official BitLocker/recovery troubleshooting. https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/recovery-overview
- **S08 — Microsoft Learn — Teams troubleshooting**: official Teams sign-in, loading, update, presence, meeting, recording and file problem categories. https://learn.microsoft.com/microsoftteams/troubleshoot/teams-welcome
- **S09 — Microsoft Learn — Teams Rooms health controls**: room sign-in, network, console, display, microphone, speaker and camera health categories. https://learn.microsoft.com/microsoftteams/rooms/rooms-pro-management
- **S10 — Microsoft Learn — Teams Rooms microphone/speaker health**: official room audio health and troubleshooting. https://learn.microsoft.com/microsoftteams/rooms/mtr-device-health
- **S11 — Microsoft Support/Learn — OneDrive 0x8004def7**: account/storage/synchronization-related sign-in state. https://support.microsoft.com/office/what-do-the-onedrive-error-codes-mean-f7a68338-e540-4ebf-ad5d-56c5633acded
- **S12 — Microsoft Support/Learn — OneDrive 0x8004deef**: account/license/credential-oriented OneDrive sign-in failure. https://support.microsoft.com/office/what-do-the-onedrive-error-codes-mean-f7a68338-e540-4ebf-ad5d-56c5633acded
- **S13 — Google Workspace Admin Community — administrator locked by 2SV**: administrator recovery/2-step-verification lockout pattern. https://support.google.com/a/community
- **S14 — Dell Community — Latitude/WD19S external display**: dock/external monitor issues on business laptops. https://www.dell.com/community/
- **S15 — Dell Community — USB-C charges but dock not recognized**: power without expected dock data/peripheral function. https://www.dell.com/community/
- **S16 — HP Support Community — EliteBook USB-C/docking**: fleet/business-laptop USB-C, monitor, peripheral and BIOS/firmware regression reports. https://h30434.www3.hp.com/
- **S17 — Cisco Community — wireless/Teams/internet/DNS**: Wi-Fi, roaming and collaboration traffic symptoms. https://community.cisco.com/
- **S18 — Cisco Community — AnyConnect loses Internet**: VPN connected while public connectivity is lost. https://community.cisco.com/
- **S19 — Cisco Community — VPN DNS after transition**: stale/split DNS and adapter transition patterns. https://community.cisco.com/
- **S20 — Fortinet Community — FortiClient VPN/DNS**: VPN DNS and connectivity failure patterns. https://community.fortinet.com/
- **S21 — Ubiquiti Community — AP firmware connectivity regressions**: roaming, 2.4 GHz and no-throughput/firmware-related patterns. https://community.ui.com/
- **S22 — Reddit r/sysadmin — file server lost permissions**: share/NTFS access and permission changes. https://www.reddit.com/r/sysadmin/search/?q=file%20server%20permissions
- **S23 — Reddit r/sysadmin — mapped-drive/File Explorer slowness**: SMB/mapped-drive browsing performance complaints. https://www.reddit.com/r/sysadmin/search/?q=mapped%20drive%20slow
- **S24 — Reddit r/sysadmin — domain trust instability**: mobile/laptop domain trust, VPN and DNS-adjacent problems. https://www.reddit.com/r/sysadmin/search/?q=trust%20relationship%20laptop
- **S25 — Reddit r/sysadmin — files deleted from network drive**: audit/evidence problem around unexplained SMB deletion. https://www.reddit.com/r/sysadmin/search/?q=files%20deleted%20network%20drive
- **S26 — Reddit r/sysadmin — GPO printer deployment**: printer deployment/group-policy problem patterns. https://www.reddit.com/r/sysadmin/search/?q=GPO%20printer%20deployment
- **S27 — InvGate — common help-desk tickets**: service-desk issue categories and recurring support requests. https://blog.invgate.com/common-help-desk-tickets
- **S28 — ITSM.tools — common IT help-desk issues**: recurring service-desk problem families. https://itsm.tools/common-it-help-desk-issues/
- **S29 — Satmz — common IT support issues**: business IT support/service issue categories. https://satmz.com/common-it-support-issues/
- **S30 — Get Support IT Services — common IT support issues**: recurring business IT support complaints. https://www.getsupport.co.uk/blog/common-it-support-issues/

## Engineering notes for WorkSpace

1. **Symptom ≠ root cause.** Never let a catalog match directly authorize remediation.
2. **Collect evidence before changing state.** The initial tool path should prefer read-only evidence collectors.
3. **Use scope as a discriminating signal.** One-user vs one-device vs whole-site symptoms materially change hypothesis ordering.
4. **Treat update/firmware regression as cross-domain.** Windows, driver, dock, AP and VPN updates all appear in real-world reports.
5. **Preserve physical-boundary truth.** No power, unplugged cable, failed PoE, damaged dock, disconnected WAN, or powered-off switch cannot be disproved by software telemetry alone. Return `PHYSICAL_EVIDENCE_REQUIRED` when remote evidence is insufficient.
6. **Fail closed on missing authority.** Admin-only or security-sensitive evidence must not be silently substituted with a more invasive action.
7. **Do not disable security controls as a diagnostic shortcut.** EDR, firewall, MFA, encryption and policy problems need evidence and explicit authority.
8. **No fabricated certainty.** “No telemetry” is not “device healthy” and “host unreachable” is not proof of a specific network component failure.
9. **Keep provenance.** A future machine-readable signature should retain which evidence/source family led to the routing rule.
10. **Use this as a seed corpus.** Future WorkSpace telemetry and resolved tickets should add organization-specific signatures without overwriting public-source provenance.
