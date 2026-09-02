from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import asdict, dataclass
from typing import Iterable

from .capability_registry import (
    SecurityCapabilityDenied,
    SecurityCapabilityRegistry,
    SecurityCapabilityError,
    validate_security_taxonomy_id,
)

SECURITY_ROUTING_SCHEMA = "workspace-security-routing-decision/v1"
SECURITY_ROUTE_SELECTION_SCHEMA = "workspace-security-route-selection/v1"
MAX_SECURITY_REQUEST_CHARS = 4096
MAX_ROUTE_SELECTIONS = 6

ROUTING_STATUSES = frozenset({"routed", "no_route", "denied"})
_ACTIVE_OR_OFFENSIVE_MARKERS = (
    "active scan",
    "port scan",
    "scan ports",
    "scan subnet",
    "nmap",
    "masscan",
    "naabu",
    "exploit",
    "metasploit",
    "payload",
    "reverse shell",
    "bind shell",
    "brute force",
    "password crack",
    "crack password",
    "hashcat",
    "john the ripper",
    "phishing",
    "ddos",
    "denial of service",
    "sql injection",
    "sqlmap",
    "xss attack",
    "wireless attack",
    "wifi crack",
    "deauth",
    "credential attack",
    "rat ",
    "remote access trojan",
    "post exploitation",
    "post-exploitation",
    "ping ",
    "traceroute",
    "mtr ",
)
_PROMPT_INJECTION_MARKERS = (
    "ignore previous instructions",
    "ignore all previous",
    "system prompt",
    "developer message",
    "override policy",
    "bypass policy",
)


@dataclass(frozen=True)
class SecurityRouteSelection:
    taxonomy_id: str
    capability_id: str
    operation_id: str
    authority_level: str
    authority_domain: str
    evidence_required: bool
    schema_version: str = SECURITY_ROUTE_SELECTION_SCHEMA

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class SecurityRoutingDecision:
    request_sha256: str
    status: str
    selections: tuple[SecurityRouteSelection, ...]
    reason_codes: tuple[str, ...]
    registry_fingerprint: str
    authority: str = "advisory"
    schema_version: str = SECURITY_ROUTING_SCHEMA

    def validate(self) -> "SecurityRoutingDecision":
        if self.status not in ROUTING_STATUSES:
            raise SecurityCapabilityError(f"unsupported routing status: {self.status}")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.request_sha256):
            raise SecurityCapabilityError("request_sha256 must be a SHA-256 fingerprint")
        if self.authority != "advisory":
            raise SecurityCapabilityError("security routing must remain advisory")
        if len(self.selections) > MAX_ROUTE_SELECTIONS:
            raise SecurityCapabilityError("security route selection bound exceeded")
        if self.status == "routed" and not self.selections:
            raise SecurityCapabilityError("routed decisions require selections")
        if self.status != "routed" and self.selections:
            raise SecurityCapabilityError("non-routed decisions cannot carry selections")
        if not self.reason_codes:
            raise SecurityCapabilityError("routing decisions require reason_codes")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "request_sha256": self.request_sha256,
            "status": self.status,
            "selections": [row.to_dict() for row in self.selections],
            "reason_codes": list(self.reason_codes),
            "registry_fingerprint": self.registry_fingerprint,
            "authority": self.authority,
        }


@dataclass(frozen=True)
class SecurityRouteProposal:
    taxonomy_id: str
    capability_id: str
    operation_id: str


@dataclass(frozen=True)
class _RouteRule:
    reason_code: str
    markers: tuple[str, ...]
    selections: tuple[tuple[str, str], ...]


_ROUTE_RULES = (
    _RouteRule(
        "ROUTE_SAFE_NETWORK_MONITORING",
        (
            "network monitoring",
            "monitor network",
            "security monitoring",
            "cybersecurity monitoring",
            "giam sat mang",
            "giam sat an ninh",
        ),
        (
            ("network.flow.observe", "read_local_flow_evidence"),
            ("security.telemetry.observe", "read_fixed_telemetry"),
        ),
    ),
    _RouteRule(
        "ROUTE_SAFE_IDS_TELEMETRY",
        (
            "monitor ids",
            "collect ids telemetry",
            "read ids telemetry",
            "security telemetry",
            "ingest suricata",
        ),
        (("security.telemetry.observe", "read_fixed_telemetry"),),
    ),
    _RouteRule(
        "ROUTE_SAFE_FLOW_OBSERVATION",
        (
            "monitor flow",
            "collect flow",
            "read local flow",
            "flow telemetry",
        ),
        (("network.flow.observe", "read_local_flow_evidence"),),
    ),
    _RouteRule(
        "ROUTE_PCAP_EVIDENCE",
        ("pcap", "packet capture", "capture file", "goi tin", "packet trace"),
        (
            ("network.pcap.read", "read_capture"),
            ("network.flow.analyze", "analyze_flow_evidence"),
        ),
    ),
    _RouteRule(
        "ROUTE_DNS_ANALYSIS",
        ("dns", "name resolution", "domain lookup", "phan giai", "ten mien"),
        (("network.dns.analyze", "analyze_dns_evidence"),),
    ),
    _RouteRule(
        "ROUTE_FLOW_ANALYSIS",
        ("netflow", "ipfix", "network flow", "flow log", "luong mang"),
        (("network.flow.analyze", "analyze_flow_evidence"),),
    ),
    _RouteRule(
        "ROUTE_INTERFACE_COUNTERS",
        (
            "interface counter",
            "interface error",
            "port error",
            "snmp counter",
            "packet loss",
            "mat goi",
            "drop counter",
        ),
        (("network.interface.observe", "read_interface_counters"),),
    ),
    _RouteRule(
        "ROUTE_IDS_ANALYSIS",
        ("suricata", "zeek", "ids alert", "ids log", "intrusion alert", "canh bao ids"),
        (("security.ids.analyze", "triage_ids_evidence"),),
    ),
    _RouteRule(
        "ROUTE_AUTHENTICATION_ANALYSIS",
        (
            "authentication",
            "login event",
            "logon event",
            "failed login",
            "dang nhap",
            "xac thuc",
        ),
        (("security.authentication.analyze", "analyze_authentication_evidence"),),
    ),
    _RouteRule(
        "ROUTE_ENDPOINT_ANALYSIS",
        (
            "sysmon",
            "endpoint event",
            "process execution",
            "powershell event",
            "process tree",
            "tien trinh",
        ),
        (("security.endpoint.analyze", "analyze_endpoint_evidence"),),
    ),
    _RouteRule(
        "ROUTE_INCIDENT_TIMELINE",
        ("incident timeline", "attack timeline", "timeline su co", "chuoi su kien"),
        (("security.incident_triage.analyze", "build_incident_timeline"),),
    ),
    _RouteRule(
        "ROUTE_INCIDENT_TRIAGE",
        ("incident", "triage", "security event", "su co", "dieu tra su co"),
        (("security.incident_triage.analyze", "triage_findings"),),
    ),
    _RouteRule(
        "ROUTE_THREAT_HUNTING",
        ("threat hunt", "threat hunting", "hunt ioc", "ioc hunt", "san tim moi de doa"),
        (("security.threat_hunting.analyze", "hunt_reviewed_evidence"),),
    ),
    _RouteRule(
        "ROUTE_FORENSICS",
        (
            "forensic",
            "forensics",
            "memory dump",
            "disk image",
            "dieu tra so",
            "evidence reconstruction",
        ),
        (("security.forensics.analyze", "analyze_forensic_evidence"),),
    ),
    _RouteRule(
        "ROUTE_CONFIGURATION_REVIEW",
        (
            "configuration snapshot",
            "config snapshot",
            "configuration review",
            "firewall config",
            "router config",
            "cau hinh",
        ),
        (("security.configuration_review.read", "read_configuration_snapshot"),),
    ),
)


def _request_fingerprint(request: str) -> str:
    return "sha256:" + hashlib.sha256(request.encode("utf-8")).hexdigest()


def _fold_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value.casefold().replace("đ", "d"))
    without_marks = "".join(ch for ch in normalized if not unicodedata.combining(ch))
    return " ".join(re.findall(r"[a-z0-9]+", without_marks))


def _contains_marker(folded: str, marker: str) -> bool:
    wanted = _fold_text(marker)
    return f" {wanted} " in f" {folded} "


class SecurityCapabilityRouter:
    """Deterministic request -> closed taxonomy/capability/operation router.

    v0.2 is deliberately L0/L1 only. It emits advisory selections and never an
    executable command, target, credential or network destination. Any request
    carrying active/offensive markers is denied until a separately reviewed L2/L3
    authority path exists.
    """

    def __init__(
        self,
        registry: SecurityCapabilityRegistry | None = None,
        *,
        max_selections: int = MAX_ROUTE_SELECTIONS,
    ):
        if not 1 <= int(max_selections) <= MAX_ROUTE_SELECTIONS:
            raise SecurityCapabilityError(
                f"max_selections must be within 1..{MAX_ROUTE_SELECTIONS}"
            )
        self.registry = registry or SecurityCapabilityRegistry()
        self.max_selections = int(max_selections)

    def route(self, request: str) -> SecurityRoutingDecision:
        raw = str(request or "").strip()
        if not raw:
            raise SecurityCapabilityError("security routing request is required")
        if len(raw) > MAX_SECURITY_REQUEST_CHARS:
            raise SecurityCapabilityError(
                f"security routing request exceeds {MAX_SECURITY_REQUEST_CHARS} chars"
            )
        request_sha256 = _request_fingerprint(raw)
        folded = _fold_text(raw)

        if any(_contains_marker(folded, marker) for marker in _ACTIVE_OR_OFFENSIVE_MARKERS):
            return self._decision(
                request_sha256,
                status="denied",
                selections=(),
                reasons=("ACTIVE_OR_OFFENSIVE_INTENT_NOT_ADMITTED_V02",),
            )

        matched: list[tuple[str, str, str]] = []
        reasons: list[str] = []
        for rule in _ROUTE_RULES:
            if not any(_contains_marker(folded, marker) for marker in rule.markers):
                continue
            reasons.append(rule.reason_code)
            for capability_id, operation_id in rule.selections:
                cap, operation = self.registry.resolve(capability_id, operation_id)
                if cap.authority_level not in {"L0", "L1"}:
                    raise SecurityCapabilityDenied("ROUTER_AUTHORITY_LEVEL_NOT_ADMITTED_V02")
                matched.append((cap.capability_id, operation.operation_id, cap.taxonomy_id))

        selections = self._selections(matched)
        if not selections:
            reason = (
                "PROMPT_INJECTION_TEXT_TREATED_AS_DATA"
                if any(_contains_marker(folded, marker) for marker in _PROMPT_INJECTION_MARKERS)
                else "NO_APPROVED_SECURITY_ROUTE"
            )
            return self._decision(
                request_sha256,
                status="no_route",
                selections=(),
                reasons=(reason,),
            )

        if any(_contains_marker(folded, marker) for marker in _PROMPT_INJECTION_MARKERS):
            reasons.append("PROMPT_INJECTION_TEXT_IGNORED")
        return self._decision(
            request_sha256,
            status="routed",
            selections=selections,
            reasons=tuple(dict.fromkeys(reasons)),
        )

    def validate_proposals(
        self,
        request: str,
        proposals: Iterable[SecurityRouteProposal],
    ) -> SecurityRoutingDecision:
        """Validate externally/model-proposed routes against the closed registry.

        This method intentionally does not call a model. Invalid or non-v0.2
        proposals are rejected rather than partially trusted.
        """

        raw = str(request or "").strip()
        if not raw:
            raise SecurityCapabilityError("security routing request is required")
        if len(raw) > MAX_SECURITY_REQUEST_CHARS:
            raise SecurityCapabilityError(
                f"security routing request exceeds {MAX_SECURITY_REQUEST_CHARS} chars"
            )
        request_sha256 = _request_fingerprint(raw)
        folded = _fold_text(raw)
        if any(_contains_marker(folded, marker) for marker in _ACTIVE_OR_OFFENSIVE_MARKERS):
            return self._decision(
                request_sha256,
                status="denied",
                selections=(),
                reasons=("ACTIVE_OR_OFFENSIVE_INTENT_NOT_ADMITTED_V02",),
            )

        accepted: list[tuple[str, str, str]] = []
        for proposal in proposals:
            taxonomy_id = validate_security_taxonomy_id(proposal.taxonomy_id)
            cap, operation = self.registry.resolve(
                proposal.capability_id,
                proposal.operation_id,
            )
            if cap.taxonomy_id != taxonomy_id:
                raise SecurityCapabilityDenied("ROUTE_TAXONOMY_CAPABILITY_MISMATCH")
            if cap.authority_level not in {"L0", "L1"}:
                raise SecurityCapabilityDenied("ROUTER_AUTHORITY_LEVEL_NOT_ADMITTED_V02")
            accepted.append((cap.capability_id, operation.operation_id, cap.taxonomy_id))

        selections = self._selections(accepted)
        if not selections:
            return self._decision(
                request_sha256,
                status="no_route",
                selections=(),
                reasons=("NO_APPROVED_SECURITY_ROUTE",),
            )
        return self._decision(
            request_sha256,
            status="routed",
            selections=selections,
            reasons=("CLOSED_PROPOSAL_VALIDATED",),
        )

    def _selections(
        self,
        rows: Iterable[tuple[str, str, str]],
    ) -> tuple[SecurityRouteSelection, ...]:
        output: list[SecurityRouteSelection] = []
        seen: set[tuple[str, str]] = set()
        for capability_id, operation_id, taxonomy_id in rows:
            key = (capability_id, operation_id)
            if key in seen:
                continue
            seen.add(key)
            cap, operation = self.registry.resolve(capability_id, operation_id)
            if cap.taxonomy_id != taxonomy_id:
                raise SecurityCapabilityDenied("ROUTE_TAXONOMY_CAPABILITY_MISMATCH")
            output.append(
                SecurityRouteSelection(
                    taxonomy_id=cap.taxonomy_id,
                    capability_id=cap.capability_id,
                    operation_id=operation.operation_id,
                    authority_level=cap.authority_level,
                    authority_domain=cap.authority_domain,
                    evidence_required=cap.evidence_required,
                )
            )
            if len(output) >= self.max_selections:
                break
        return tuple(output)

    def _decision(
        self,
        request_sha256: str,
        *,
        status: str,
        selections: tuple[SecurityRouteSelection, ...],
        reasons: tuple[str, ...],
    ) -> SecurityRoutingDecision:
        return SecurityRoutingDecision(
            request_sha256=request_sha256,
            status=status,
            selections=selections,
            reason_codes=reasons,
            registry_fingerprint=self.registry.fingerprint,
        ).validate()
