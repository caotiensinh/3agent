# Office IT Support — Real-World Issue Catalog v0.2 Expansion

> Expansion of `OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_1.md`.
>
> Aggregate corpus after this expansion: **500 canonical issue/symptom patterns**, **26 domains**, **44 public sources**.
>
> This file adds `IT-0381` through `IT-0500`. The v0.1 file remains immutable for audit/history rather than being silently rewritten.

## Evidence posture

These are normalized real-world complaint/failure signatures collected from public practitioner communities, vendor communities, official vendor troubleshooting material, and public IT support/MSP sources. They are **not** prevalence statistics. A matched symptom is a routing hint only and must never be treated as proof of root cause or authority to remediate.

### U. Intune, Autopilot, MDM provisioning and endpoint management

- IT-0381 — Intune/MDM enrollment fails because the user has no valid management license.
- IT-0382 — Device enrollment is blocked because the tenant/device enrollment limit was reached.
- IT-0383 — Device is already enrolled with another MDM provider or has a stale management profile.
- IT-0384 — Company Portal reports that the service is temporarily unavailable.
- IT-0385 — MDM authority is missing/misconfigured and devices cannot enroll.
- IT-0386 — Enrollment profile installation fails.
- IT-0387 — Enrollment fails because a required management/profile certificate is expired or invalid.
- IT-0388 — Windows automatic MDM enrollment through Group Policy does not start.
- IT-0389 — Auto-enrollment scheduled task exists but never completes successfully.
- IT-0390 — Device enrolls but required configuration profiles do not arrive.
- IT-0391 — Device enrolls but required applications do not install.
- IT-0392 — Intune Win32 application remains pending/failed on one or more endpoints.
- IT-0393 — Device compliance status remains unknown/not evaluated.
- IT-0394 — Device is marked non-compliant even after the user corrected the reported setting.
- IT-0395 — Conditional Access blocks the device because compliance state is stale.
- IT-0396 — Windows Autopilot profile does not download during OOBE.
- IT-0397 — Autopilot device is registered to the wrong tenant/profile.
- IT-0398 — Autopilot Enrollment Status Page is stuck on device preparation.
- IT-0399 — Autopilot Enrollment Status Page is stuck on device setup.
- IT-0400 — Autopilot Enrollment Status Page is stuck on account setup.
- IT-0401 — Autopilot provisioning times out while waiting for required applications.
- IT-0402 — Autopilot reports “another installation is in progress” during application deployment.
- IT-0403 — TPM attestation/device identity step fails during Autopilot.
- IT-0404 — Microsoft Entra join succeeds but MDM enrollment does not complete.
- IT-0405 — Device provisioning unexpectedly reboots and returns to an incomplete/failed OOBE state.

### V. macOS, Jamf, FileVault and Apple enterprise management

- IT-0406 — Mac cannot enroll into MDM/Jamf.
- IT-0407 — Mac is enrolled but inventory/check-in stops updating.
- IT-0408 — Required configuration profile is missing/not applied.
- IT-0409 — MDM profile is present but a restriction/settings payload is ineffective.
- IT-0410 — FileVault enablement prompt never appears.
- IT-0411 — FileVault cannot be enabled because the user lacks Secure Token/volume-owner capability.
- IT-0412 — FileVault recovery key was not escrowed to management.
- IT-0413 — Escrowed FileVault recovery key is stale/does not unlock the current disk.
- IT-0414 — User cannot unlock Mac at preboot/FileVault screen.
- IT-0415 — Password changed but macOS login keychain still uses old password.
- IT-0416 — Login keychain repeatedly prompts or cannot be unlocked.
- IT-0417 — macOS update is blocked, stuck, or fails to install.
- IT-0418 — macOS update breaks VPN/security/network extension behavior.
- IT-0419 — Wi-Fi profile/certificate deployed by MDM fails to authenticate.
- IT-0420 — macOS printer queue/driver stops working after update.
- IT-0421 — USB-C dock/external monitor is not detected by Mac.
- IT-0422 — External monitor wakes to black screen/flickers after sleep or docking.
- IT-0423 — Managed application install/update from MDM remains pending or fails.
- IT-0424 — Privacy/TCC permission prevents camera, microphone, screen recording or accessibility function.
- IT-0425 — Apple silicon bootstrap/secure-token/volume-ownership state prevents expected administrative workflow.

### W. UPS, power, environmental monitoring and server-room facilities

- IT-0426 — Building power outage takes office/network/server services offline.
- IT-0427 — UPS battery runtime is much shorter than expected.
- IT-0428 — UPS battery reports failed/replace battery.
- IT-0429 — UPS is overloaded or load exceeds designed capacity.
- IT-0430 — UPS bypass/fault state leaves equipment without expected protection.
- IT-0431 — UPS is powered off accidentally during facilities/electrical work.
- IT-0432 — Generator fails to start or transfer before UPS runtime is exhausted.
- IT-0433 — Automatic transfer switch does not transfer correctly.
- IT-0434 — UPS network-management card is unreachable or stops reporting telemetry.
- IT-0435 — UPS alert emails/SNMP traps are lost in alert noise and not acted upon.
- IT-0436 — Server-room air conditioning/cooling fails.
- IT-0437 — Rack/server-room temperature rises above safe threshold.
- IT-0438 — Humidity/environmental sensor reports unsafe condition or stops reporting.
- IT-0439 — Rack PDU outlet is off/tripped and one device loses power.
- IT-0440 — Circuit breaker trips under load and multiple devices lose power.
- IT-0441 — Redundant PSU has one failed/missing power feed.
- IT-0442 — Server/network device reports power-supply failure while still running on remaining PSU.
- IT-0443 — Power event causes unclean shutdown and storage/filesystem recovery is required.
- IT-0444 — Facilities maintenance occurs without IT coordination, creating avoidable outage risk.
- IT-0445 — Environmental/power telemetry is absent, so remote software evidence cannot determine the physical cause.

### X. Conference-room A/V, projectors, wireless presentation and BYOD

- IT-0446 — User enters conference room and does not know how to start/join the scheduled meeting.
- IT-0447 — Room calendar shows no meeting even though organizer invited the room.
- IT-0448 — Conference-room PC/account exposes prior users’ files, notes or presentations.
- IT-0449 — Guest/vendor laptop cannot display through the room HDMI connection.
- IT-0450 — Corporate laptop displays correctly but external/BYOD laptop does not.
- IT-0451 — HDMI cable/adapter/wall plate works intermittently or fails completely.
- IT-0452 — Projector/TV reports no signal although laptop detects a display.
- IT-0453 — Projector/TV resolution or aspect ratio is wrong/cropped.
- IT-0454 — Projector lamp/display panel is too dim or fails.
- IT-0455 — Wireless screen casting fails to connect.
- IT-0456 — Wireless screen casting connects but video is delayed/laggy/corrupted.
- IT-0457 — Wireless presentation works for slides but performs poorly for video/audio.
- IT-0458 — Guest cannot use wireless presentation because required app/driver/admin rights are unavailable.
- IT-0459 — Conference-room dock is not recognized by some laptop models.
- IT-0460 — Room USB camera/speakerphone is not detected by the presenter’s laptop.
- IT-0461 — Room selects laptop microphone/speaker instead of room audio device.
- IT-0462 — Two room microphones/speakers create echo/feedback.
- IT-0463 — Participants at far end of table cannot be heard clearly.
- IT-0464 — Camera framing/angle does not include expected participants.
- IT-0465 — Dual-display room shows wrong content/participants on wrong screen.
- IT-0466 — HDMI ingest/BYOD sharing into Teams/Zoom Room does not work.
- IT-0467 — Room appliance needs reboot/power-cycle before every important meeting.
- IT-0468 — Room appliance firmware/software update causes regression.
- IT-0469 — Meeting starts but audio/video quality collapses when network is congested.
- IT-0470 — Critical meeting requires immediate onsite A/V assistance because remote telemetry cannot verify cable/input/device state.

### Y. FIDO2/security keys, smart cards and virtual desktop access

- IT-0471 — FIDO2/security key is not recognized when inserted.
- IT-0472 — Security key works over USB but not NFC/contactless.
- IT-0473 — Security-key PIN is forgotten/blocked and must be reset/re-provisioned.
- IT-0474 — Passkey/security-key registration succeeds but sign-in later fails.
- IT-0475 — Orphaned passkey remains on hardware key after server-side registration was removed.
- IT-0476 — FIDO2 key sign-in is unavailable immediately after hybrid-join/provisioning.
- IT-0477 — User signs in with FIDO2 but cannot obtain SSO to an on-premises resource.
- IT-0478 — Smart-card reader is not detected.
- IT-0479 — Smart-card certificate is expired/missing and authentication fails.
- IT-0480 — Virtual desktop/Citrix/VDI session will not launch.
- IT-0481 — VDI session launches but freezes/disconnects on minor network interruption.
- IT-0482 — VDI user profile does not load or resets between sessions.
- IT-0483 — Local printer/USB/smart-card redirection does not work inside VDI.
- IT-0484 — Teams/audio/video inside VDI has poor performance or device redirection issues.
- IT-0485 — Central VDI service outage prevents users from accessing all work applications.

### Z. Warehouse, barcode, label, serial and specialized business peripherals

- IT-0486 — Barcode scanner intermittently fails although it works when IT tests it.
- IT-0487 — Barcode scanner does not read a specific barcode type/symbology.
- IT-0488 — Scanner reads code but sends wrong characters/prefix/suffix.
- IT-0489 — Wireless barcode scanner loses pairing/connection.
- IT-0490 — Scanner cradle/charging station does not charge device.
- IT-0491 — Label printer drops print jobs under large batch load.
- IT-0492 — Label printer queue shows successful job but no label is produced.
- IT-0493 — Label printer produces incorrect size/orientation/offset/calibration.
- IT-0494 — Label printer ribbon/media/printhead state causes blank/faded labels.
- IT-0495 — Warehouse user moves printer to another station and application binding/serial configuration breaks.
- IT-0496 — USB/serial/COM-port assignment changes and business application can no longer find peripheral.
- IT-0497 — Thin client sees peripheral but warehouse/ERP application does not.
- IT-0498 — Peripheral firmware/driver version differs across stations and behavior is inconsistent.
- IT-0499 — Specialized device works locally but cannot reach print/application server over network/VLAN.
- IT-0500 — Operational workaround (moving/replugging/swapping device) masks an intermittent hardware/software problem and destroys useful diagnostic evidence.

## Added public-source registry

- **S31 — Microsoft Learn — Troubleshoot Intune device enrollment**: device-cap, MDM authority, profile, certificate and license-related enrollment failures. https://learn.microsoft.com/en-us/troubleshoot/mem/intune/device-enrollment/troubleshoot-device-enrollment-in-intune
- **S32 — Microsoft Learn — Troubleshoot Enrollment Status Page**: Autopilot/ESP app tracking, timeout, unexpected reboot and provisioning diagnostics. https://learn.microsoft.com/en-us/troubleshoot/mem/intune/device-enrollment/understand-troubleshoot-esp
- **S33 — Microsoft Learn — Windows Autopilot troubleshooting FAQ**: profile download, Entra join, MDM enrollment, policy and app-install problems. https://learn.microsoft.com/en-us/autopilot/troubleshooting-faq
- **S34 — Microsoft Learn — FIDO2 security-key known issues**: Windows/hybrid-join, SSO and FIDO client troubleshooting. https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-troubleshoot
- **S35 — Apple Support — Manage FileVault with device management**: FileVault deferred enablement, recovery-key escrow, Secure Token and volume ownership. https://support.apple.com/guide/deployment/manage-filevault-with-device-management-dep0a2cb7686/1/web/1.0
- **S36 — Reddit r/macsysadmin — FileVault/Secure Token fleet pain**: practitioner report of M1/FileVault enablement and Secure Token failures. https://www.reddit.com/r/macsysadmin/comments/xdb7yu/am_i_stupid_or_is_apple_stupid/
- **S37 — Reddit r/sysadmin — server-room cooling failure**: real incident involving cooling loss, temperature spike and alerting gaps. https://www.reddit.com/r/sysadmin/comments/1j6a25t/
- **S38 — Reddit r/sysadmin — UPS powered off during facilities work**: real physical power/coordination failure affecting critical systems. https://www.reddit.com/r/sysadmin/comments/1f8sw84/
- **S39 — Reddit r/sysadmin — meeting-room user/support problems**: recurring room-operation and user-assistance burden. https://www.reddit.com/r/sysadmin/comments/1u3zwp6/meeting_rooms_should_not_be_so_difficult_for/
- **S40 — Reddit r/sysadmin — wireless display conference-room failures**: intermittent connection, lag and corrupted video reports. https://www.reddit.com/r/sysadmin/comments/18igqof/
- **S41 — Dell Community — WD19 dock network/USB/display dropout**: fleet reports of Ethernet, USB and monitor dropout across business laptop models. https://www.dell.com/community/en/conversations/latitude/wd19-docking-stations-network-dropout-usb-dropout-across-multiple-models/647f8357f4ccf8a8de22821b
- **S42 — Reddit r/sysadmin — Zebra label printer support burden**: real enterprise/ERP label-printer setup and support experience. https://www.reddit.com/r/sysadmin/comments/1vh6ajp/zebra_label_printer_are_a_nightmare/
- **S43 — Reddit r/sysadmin — warehouse label-printer station binding**: Zebra/thin-client/serial binding failures when devices move stations. https://www.reddit.com/r/sysadmin/comments/1gmzq4r/in_over_my_head_new_warehouse_sysadmin/
- **S44 — Reddit r/sysadmin — barcode scanner complaints**: intermittent scanner complaints that are difficult to reproduce during technician testing. https://www.reddit.com/r/sysadmin/comments/1jdn83c/im_sick_of_barcode_scanners/

## WorkSpace engineering guidance

1. **Symptom is not root cause.** A matched `IT-####` signature only selects an evidence plan.
2. **Read-only evidence first.** Prefer the smallest bounded collector capable of discriminating hypotheses.
3. **Fail closed on missing authority.** Do not substitute an invasive action when admin/security evidence is unavailable.
4. **Preserve physical-boundary truth.** Power, UPS, cable, PoE, display input, damaged peripherals and facilities faults can require human physical verification.
5. **No security-control bypass as a shortcut.** EDR, firewall, MFA, encryption and policy failures require evidence and explicit authority.
6. **Keep exact version/timestamp evidence.** Windows, firmware, dock, AP, VPN, MDM and meeting-room updates are recurrent regression triggers.
7. **No fabricated certainty.** Unreachable equipment or missing telemetry is an unknown/evidence-gap state, not proof of a particular component failure.
