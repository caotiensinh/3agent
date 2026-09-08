# Office IT Support — Canonical Real-World Issue Catalog

## Corpus status

- Canonical issue/symptom signatures: **500** (`IT-0001` … `IT-0500`)
- Domains: **26**
- Public sources reviewed/retained: **44**
- Collection date: **2026-09-08**
- Scope: public practitioner communities, public vendor communities, official vendor troubleshooting material, and public MSP/help-desk sources.
- Limitation: community reports are anecdotal and environment-specific; this catalog is not a statistical prevalence study.

## Catalog files

1. [`OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_1.md`](./OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_1.md) — `IT-0001` … `IT-0380`; first 20 domains; sources S01 … S30.
2. [`OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_2_EXPANSION.md`](./OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_2_EXPANSION.md) — `IT-0381` … `IT-0500`; 6 additional domains; sources S31 … S44.

## Domain map

| Range | Domain |
|---|---|
| IT-0001–0020 | Identity, authentication, MFA and account access |
| IT-0021–0040 | Windows boot, login, profile, update and crash |
| IT-0041–0060 | Endpoint performance, storage and application responsiveness |
| IT-0061–0080 | Hardware, power, battery and thermal |
| IT-0081–0100 | Docking stations, USB-C, displays and peripherals |
| IT-0101–0120 | Printing, label printers and scanning |
| IT-0121–0145 | LAN, Wi-Fi, DHCP, DNS and general connectivity |
| IT-0146–0165 | VPN and remote access |
| IT-0166–0185 | Outlook, email and Exchange |
| IT-0186–0205 | Teams, Zoom, conferencing and meeting rooms |
| IT-0206–0225 | OneDrive, SharePoint and cloud file collaboration |
| IT-0226–0245 | File servers, SMB, mapped drives, permissions and GPO |
| IT-0246–0265 | Software installation, activation, browser and business apps |
| IT-0266–0285 | Security, phishing, EDR, certificates and policy |
| IT-0286–0300 | Mobile devices, MDM and BYOD |
| IT-0301–0320 | Server, virtualization, storage and backup |
| IT-0321–0335 | VoIP, softphones, phones and headsets |
| IT-0336–0350 | User lifecycle, access requests and service operations |
| IT-0351–0365 | Cloud, SaaS, licensing and service health |
| IT-0366–0380 | Network infrastructure, PoE and physical layer |
| IT-0381–0405 | Intune, Autopilot, MDM provisioning and endpoint management |
| IT-0406–0425 | macOS, Jamf, FileVault and Apple enterprise management |
| IT-0426–0445 | UPS, power, environment and server-room facilities |
| IT-0446–0470 | Conference-room A/V, projectors, wireless presentation and BYOD |
| IT-0471–0485 | FIDO2/security keys, smart cards and VDI |
| IT-0486–0500 | Warehouse, barcode, label, serial and specialized peripherals |

## Diagnostic contract

This corpus is a **symptom routing corpus**, not an automatic-remediation catalog.

`user complaint -> canonical signature -> blast-radius/scope -> read-only evidence -> hypotheses -> authority gate -> bounded action -> verification -> audit`

Required invariants:

- symptom match must never be treated as proof of root cause;
- use least-privileged read-only collection first;
- fail closed when authority/evidence is unavailable;
- never disable MFA, EDR, firewall, encryption or other controls as a diagnostic shortcut;
- public/external targets remain outside local diagnostic authority unless explicitly authorized by policy;
- physical faults such as no power, failed PoE, disconnected cable, failed UPS/PDU, wrong display input or damaged hardware must return an explicit physical-evidence requirement when software telemetry cannot prove the state;
- keep exact timestamps, versions and source provenance for regression analysis.

## Recommended next implementation layer

Transform each `IT-####` record into machine-readable data with:

- localized complaint aliases (Vietnamese / Japanese / English);
- domain and sub-domain;
- likely evidence sources;
- safe micro-tools allowed for evidence collection;
- scope discriminators (one user / one device / VLAN / site / organization);
- dependency graph (endpoint -> Wi-Fi/AP -> switch -> router/firewall -> WAN -> SaaS);
- authority requirement;
- physical-verification boundary;
- evidence-confidence scoring;
- known vendor runbook links;
- regression/version markers;
- unit tests and E2E prompt cases.
