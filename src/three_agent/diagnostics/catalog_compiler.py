from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .complaint_intake import DOMAIN_PROFILE_BY_ID, QUESTION_BY_ID

PLANNED_DIAGNOSTIC_ROUTE_SCHEMA = "workspace-planned-diagnostic-route/v1"

_ISSUE_LINE_RE = re.compile(r"^\s*-\s+IT-(\d{4})\s+[—-]\s+(.+?)\s*$")

_DOMAIN_RANGES: tuple[tuple[int, int, str], ...] = (
    (1, 20, "identity_auth"),
    (21, 40, "windows_endpoint"),
    (41, 60, "endpoint_performance"),
    (61, 80, "hardware_power"),
    (81, 100, "dock_display"),
    (101, 120, "printing"),
    (121, 145, "lan_wifi"),
    (146, 165, "vpn_remote"),
    (166, 185, "mail_exchange"),
    (186, 205, "meeting_collaboration"),
    (206, 225, "cloud_files"),
    (226, 245, "file_share_gpo"),
    (246, 265, "business_apps"),
    (266, 285, "security"),
    (286, 300, "mobile_mdm"),
    (301, 320, "server_backup"),
    (321, 335, "voip"),
    (336, 350, "service_ops"),
    (351, 365, "saas"),
    (366, 380, "network_infra"),
    (381, 405, "intune_autopilot"),
    (406, 425, "macos"),
    (426, 445, "facilities"),
    (446, 470, "room_av"),
    (471, 485, "auth_vdi"),
    (486, 500, "warehouse"),
    (501, 525, "ad_core"),
    (526, 550, "office_productivity"),
    (551, 575, "erp_database"),
    (576, 600, "cctv_access"),
    (601, 625, "pki_smtp"),
    (626, 650, "wan_remote"),
)

_COMMON_QUESTIONS = (
    "scope.others_affected",
    "timeline.last_known_good",
    "timeline.recent_change",
    "error.exact_message",
)

_DOMAIN_QUESTIONS: dict[str, tuple[str, ...]] = {
    "identity_auth": ("identity.other_device_login",),
    "ad_core": ("identity.other_device_login",),
    "saas": ("identity.other_device_login", "context.location"),
    "lan_wifi": ("scope.same_area", "context.location", "alternate.other_device"),
    "vpn_remote": ("context.location", "alternate.other_device"),
    "wan_remote": ("context.location", "alternate.other_device"),
    "hardware_power": ("physical.power_link",),
    "network_infra": ("scope.same_area", "physical.power_link"),
    "cctv_access": ("scope.same_area", "physical.power_link"),
    "facilities": ("physical.power_link",),
    "warehouse": ("physical.power_link",),
    "room_av": ("physical.power_link",),
}

_CAPABILITY_TAGS: dict[str, tuple[str, ...]] = {
    "identity_auth": ("identity.session", "identity.account_state", "time.sync"),
    "windows_endpoint": ("windows.boot", "windows.events", "windows.update", "system.storage"),
    "endpoint_performance": ("system.resources", "process.top", "system.storage", "storage.io"),
    "hardware_power": ("hardware.power", "hardware.battery", "hardware.thermal", "hardware.storage_health"),
    "dock_display": ("hardware.usb", "hardware.display", "hardware.dock", "driver.inventory"),
    "printing": ("print.queue", "print.driver", "print.port", "network.reachability"),
    "lan_wifi": ("network.interface", "network.ip", "network.route", "network.dhcp", "network.dns", "network.reachability"),
    "vpn_remote": ("vpn.status", "network.route", "network.dns", "network.reachability"),
    "mail_exchange": ("mail.client", "mail.account", "network.dns", "service.health"),
    "meeting_collaboration": ("audio.devices", "camera.devices", "meeting.client", "network.quality"),
    "cloud_files": ("cloud.sync", "cloud.permissions", "network.reachability", "service.health"),
    "file_share_gpo": ("smb.mounts", "smb.permissions", "network.dns", "group_policy"),
    "business_apps": ("application.process", "application.events", "application.version", "license.state"),
    "security": ("security.alerts", "security.policy", "security.endpoint_state"),
    "mobile_mdm": ("mdm.enrollment", "mdm.compliance", "mobile.network"),
    "server_backup": ("server.resources", "service.status", "storage.capacity", "backup.status"),
    "voip": ("voip.registration", "audio.devices", "network.quality", "network.nat"),
    "service_ops": ("identity.directory", "access.entitlement", "asset.assignment"),
    "saas": ("service.health", "license.state", "identity.session", "network.reachability"),
    "network_infra": ("switch.port", "switch.vlan", "switch.poe", "network.link"),
    "intune_autopilot": ("mdm.enrollment", "autopilot.profile", "mdm.compliance", "application.install_state"),
    "macos": ("macos.profile", "macos.filevault", "macos.secure_token", "macos.events"),
    "facilities": ("ups.status", "power.environment", "temperature.telemetry"),
    "room_av": ("room.display", "room.audio", "room.camera", "room.presentation"),
    "auth_vdi": ("auth.security_key", "auth.smart_card", "vdi.session", "vdi.redirection"),
    "warehouse": ("barcode.device", "label.queue", "serial.port", "device.driver"),
    "ad_core": ("ad.replication", "ad.dns", "ad.dhcp", "group_policy", "time.sync"),
    "office_productivity": ("office.process", "office.addins", "office.events", "office.activation"),
    "erp_database": ("erp.client", "database.connectivity", "odbc.state", "network.latency"),
    "cctv_access": ("camera.reachability", "camera.rtsp", "camera.onvif", "nvr.channel", "switch.poe"),
    "pki_smtp": ("certificate.chain", "certificate.expiry", "tls.handshake", "smtp.relay"),
    "wan_remote": ("wan.interface", "wan.route", "wan.dns", "wan.latency", "isp.reachability"),
}

_PHYSICAL_DOMAINS = {
    "hardware_power",
    "dock_display",
    "printing",
    "network_infra",
    "facilities",
    "room_av",
    "warehouse",
    "cctv_access",
    "wan_remote",
}


@dataclass(frozen=True)
class CatalogIssue:
    issue_id: str
    number: int
    canonical_symptom: str
    domain_id: str
    source_file: str


@dataclass(frozen=True)
class PlannedDiagnosticRoute:
    route_id: str
    domain_id: str
    canonical_symptom: str
    clarification_question_ids: tuple[str, ...]
    evidence_capability_tags: tuple[str, ...]
    physical_verification_possible: bool
    status: str = "planned"
    execution_enabled: bool = False
    schema_version: str = PLANNED_DIAGNOSTIC_ROUTE_SCHEMA

    def validate(self) -> "PlannedDiagnosticRoute":
        if self.schema_version != PLANNED_DIAGNOSTIC_ROUTE_SCHEMA:
            raise ValueError(f"unsupported planned-route schema: {self.schema_version}")
        if self.status != "planned":
            raise ValueError("compiled complaint routes must remain planned until promoted")
        if self.execution_enabled is not False:
            raise ValueError("compiled complaint routes cannot enable execution")
        if self.domain_id not in DOMAIN_PROFILE_BY_ID:
            raise ValueError(f"unknown domain: {self.domain_id}")
        if not self.route_id.startswith("IT-"):
            raise ValueError(f"invalid route id: {self.route_id}")
        if not self.canonical_symptom.strip():
            raise ValueError("canonical symptom is required")
        for question_id in self.clarification_question_ids:
            if question_id not in QUESTION_BY_ID:
                raise ValueError(f"unknown clarification question: {question_id}")
        if not self.evidence_capability_tags:
            raise ValueError("planned route requires at least one evidence capability tag")
        return self


def domain_for_issue_number(number: int) -> str:
    number = int(number)
    for start, end, domain_id in _DOMAIN_RANGES:
        if start <= number <= end:
            return domain_id
    raise ValueError(f"issue number outside canonical range: {number}")


def parse_catalog_text(text: str, *, source_file: str) -> tuple[CatalogIssue, ...]:
    issues: list[CatalogIssue] = []
    for line in str(text).splitlines():
        match = _ISSUE_LINE_RE.match(line)
        if not match:
            continue
        number = int(match.group(1))
        issue_id = f"IT-{number:04d}"
        issues.append(
            CatalogIssue(
                issue_id=issue_id,
                number=number,
                canonical_symptom=match.group(2).strip(),
                domain_id=domain_for_issue_number(number),
                source_file=str(source_file),
            )
        )
    return tuple(issues)


def validate_catalog_issues(
    issues: Sequence[CatalogIssue],
    *,
    expected_first: int = 1,
    expected_last: int = 650,
) -> tuple[CatalogIssue, ...]:
    ordered = tuple(sorted(issues, key=lambda item: item.number))
    numbers = tuple(item.number for item in ordered)
    expected = tuple(range(int(expected_first), int(expected_last) + 1))
    if len(numbers) != len(set(numbers)):
        seen: set[int] = set()
        duplicates: list[int] = []
        for number in numbers:
            if number in seen:
                duplicates.append(number)
            seen.add(number)
        raise ValueError(f"duplicate issue ids: {sorted(set(duplicates))}")
    if numbers != expected:
        missing = sorted(set(expected) - set(numbers))
        unexpected = sorted(set(numbers) - set(expected))
        raise ValueError(
            f"catalog is not contiguous: missing={missing[:20]} unexpected={unexpected[:20]}"
        )
    for issue in ordered:
        if issue.domain_id not in DOMAIN_PROFILE_BY_ID:
            raise ValueError(f"unknown domain on {issue.issue_id}: {issue.domain_id}")
        if not issue.canonical_symptom.strip():
            raise ValueError(f"blank symptom on {issue.issue_id}")
    return ordered


def compile_catalog_files(paths: Iterable[str | Path]) -> tuple[CatalogIssue, ...]:
    collected: list[CatalogIssue] = []
    for raw_path in paths:
        path = Path(raw_path)
        collected.extend(parse_catalog_text(path.read_text(encoding="utf-8"), source_file=path.name))
    return validate_catalog_issues(collected)


def _question_ids_for_domain(domain_id: str) -> tuple[str, ...]:
    items = list(_COMMON_QUESTIONS)
    items.extend(_DOMAIN_QUESTIONS.get(domain_id, ()))
    return tuple(dict.fromkeys(items))


def planned_route_from_issue(issue: CatalogIssue) -> PlannedDiagnosticRoute:
    try:
        tags = _CAPABILITY_TAGS[issue.domain_id]
    except KeyError as exc:
        raise ValueError(f"missing capability tags for domain: {issue.domain_id}") from exc
    return PlannedDiagnosticRoute(
        route_id=issue.issue_id,
        domain_id=issue.domain_id,
        canonical_symptom=issue.canonical_symptom,
        clarification_question_ids=_question_ids_for_domain(issue.domain_id),
        evidence_capability_tags=tags,
        physical_verification_possible=issue.domain_id in _PHYSICAL_DOMAINS,
    ).validate()


def compile_planned_routes(paths: Iterable[str | Path]) -> tuple[PlannedDiagnosticRoute, ...]:
    issues = compile_catalog_files(paths)
    routes = tuple(planned_route_from_issue(issue) for issue in issues)
    if len(routes) != 650:
        raise ValueError(f"expected 650 planned routes, got {len(routes)}")
    if len({route.route_id for route in routes}) != len(routes):
        raise ValueError("compiled route ids must be unique")
    return routes


__all__ = [
    "PLANNED_DIAGNOSTIC_ROUTE_SCHEMA",
    "CatalogIssue",
    "PlannedDiagnosticRoute",
    "compile_catalog_files",
    "compile_planned_routes",
    "domain_for_issue_number",
    "parse_catalog_text",
    "planned_route_from_issue",
    "validate_catalog_issues",
]
