from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .contracts import CanonicalEvent, MonitoringContractError, _compact
from .entity_context import EventEntityContext, EventEntityReference
from .parsers import JSON_SENSOR_PARSER_VERSION, QuarantinedRecord, parse_json_sensor_event

WORKSPACE_AUDIT_PARSER_VERSION = "workspace-audit/v1"
AUDIT_EVENT_TYPES = {"auth_success", "auth_failure", "process_start"}
AUDIT_ALLOWED_KEYS = {
    "timestamp",
    "event_type",
    "asset_id",
    "user",
    "source_ip",
    "destination_ip",
    "service",
    "process_image",
    "outcome",
}
SUPPORTED_AUTH_SERVICES = {
    "ssh": "tcp:22",
    "smb": "tcp:445",
    "rdp": "tcp:3389",
    "winrm": "tcp:5985",
    "winrm_tls": "tcp:5986",
}
_SURICATA_ENTITY_FIELDS = {"src_ip", "dest_ip", "src_port", "dest_port", "proto", "dns", "event_type"}
_ZEEK_ENTITY_FIELDS = {"id.orig_h", "id.resp_h", "id.orig_p", "id.resp_p", "proto", "query", "answers", "_path", "event_type"}


@dataclass(frozen=True)
class ParsedCanonicalEvent:
    event: CanonicalEvent
    entity_context: EventEntityContext

    def validate(self) -> "ParsedCanonicalEvent":
        self.event.validate()
        self.entity_context.validate()
        if self.entity_context.event_id != self.event.event_id:
            raise MonitoringContractError("entity context must bind the exact canonical event_id")
        return self


def _digest(raw_line: str) -> str:
    return "sha256:" + hashlib.sha256(str(raw_line).encode("utf-8", errors="replace")).hexdigest()


def _quarantine(*, source_id: str, source_type: str, parser_version: str, raw_line: str, reason: str) -> QuarantinedRecord:
    return QuarantinedRecord(
        source_id=source_id,
        source_type=source_type,
        parser_version=parser_version,
        reason_code=reason,
        payload_sha256=_digest(raw_line),
        observed_at=datetime.now(timezone.utc).isoformat(),
    )


def _entity_ip(refs: list[EventEntityReference], *, role: str, value: Any) -> None:
    if value in (None, ""):
        return
    refs.append(EventEntityReference.opaque(kind="ip", role=role, value=str(value)))


def _entity_dns(refs: list[EventEntityReference], *, role: str, value: Any) -> None:
    if value in (None, ""):
        return
    refs.append(EventEntityReference.opaque(kind="dns", role=role, value=str(value)))


def _service_value(protocol: Any, port: Any) -> str | None:
    if port in (None, ""):
        return None
    try:
        parsed_port = int(port)
    except (TypeError, ValueError) as exc:
        raise MonitoringContractError("sensor service port must be an integer") from exc
    if not 1 <= parsed_port <= 65535:
        raise MonitoringContractError("sensor service port out of range")
    proto = str(protocol or "tcp").strip().lower()
    if proto not in {"tcp", "udp"}:
        return None
    return f"{proto}:{parsed_port}"


def _add_service(refs: list[EventEntityReference], protocol: Any, port: Any) -> None:
    service = _service_value(protocol, port)
    if service:
        refs.append(EventEntityReference.opaque(kind="service", role="service", value=service))


def _approved_asset(refs: list[EventEntityReference], approved_asset_id: str | None) -> None:
    if approved_asset_id:
        refs.append(EventEntityReference.approved_asset(role="asset", asset_id=approved_asset_id))


def _suricata_refs(payload: dict[str, Any], *, approved_asset_id: str | None) -> tuple[EventEntityReference, ...]:
    # The explicit extraction allowlist above documents which EVE fields may
    # influence entity metadata. All other EVE fields remain raw evidence only.
    refs: list[EventEntityReference] = []
    _approved_asset(refs, approved_asset_id)
    _entity_ip(refs, role="source_ip", value=payload.get("src_ip"))
    _entity_ip(refs, role="destination_ip", value=payload.get("dest_ip"))
    _add_service(refs, payload.get("proto"), payload.get("dest_port"))
    dns = payload.get("dns")
    if isinstance(dns, dict):
        rrname = dns.get("rrname")
        if rrname is not None:
            _entity_dns(refs, role="dns_query", value=rrname)
        answers = dns.get("answers")
        if isinstance(answers, list):
            for answer in answers[:8]:
                candidate = answer.get("rdata") if isinstance(answer, dict) else answer
                if candidate in (None, ""):
                    continue
                try:
                    ipaddress.ip_address(str(candidate))
                except ValueError:
                    continue
                _entity_ip(refs, role="dns_answer", value=candidate)
        rdata = dns.get("rdata")
        if rdata not in (None, ""):
            try:
                ipaddress.ip_address(str(rdata))
            except ValueError:
                pass
            else:
                _entity_ip(refs, role="dns_answer", value=rdata)
    return tuple(refs)


def _zeek_refs(payload: dict[str, Any], *, approved_asset_id: str | None) -> tuple[EventEntityReference, ...]:
    refs: list[EventEntityReference] = []
    _approved_asset(refs, approved_asset_id)
    _entity_ip(refs, role="source_ip", value=payload.get("id.orig_h"))
    _entity_ip(refs, role="destination_ip", value=payload.get("id.resp_h"))
    _add_service(refs, payload.get("proto"), payload.get("id.resp_p"))
    if payload.get("query") is not None:
        _entity_dns(refs, role="dns_query", value=payload.get("query"))
    answers = payload.get("answers")
    if isinstance(answers, list):
        for answer in answers[:8]:
            try:
                ipaddress.ip_address(str(answer))
            except ValueError:
                continue
            _entity_ip(refs, role="dns_answer", value=answer)
    return tuple(refs)


def parse_json_sensor_event_enriched(
    *,
    source_id: str,
    source_type: str,
    raw_line: str,
    approved_asset_id: str | None = None,
) -> ParsedCanonicalEvent | QuarantinedRecord:
    """Parse a supported sensor event and derive privacy-preserving entity refs.

    Existing parse_json_sensor_event() remains the authoritative CanonicalEvent
    parser. This wrapper only adds deterministic metadata derived from an
    explicit field allowlist; it cannot broaden source or collection authority.
    Any explicit asset identity must already be approved by trusted caller/config.
    """

    base = parse_json_sensor_event(source_id=source_id, source_type=source_type, raw_line=raw_line)
    if isinstance(base, QuarantinedRecord):
        return base
    try:
        payload = json.loads(raw_line)
        if not isinstance(payload, dict):
            raise MonitoringContractError("sensor payload must be an object")
        if approved_asset_id is not None:
            approved_asset_id = _compact(approved_asset_id, "approved_asset_id", max_len=128)
        if source_type == "suricata_eve":
            selected = {key: payload.get(key) for key in _SURICATA_ENTITY_FIELDS if key in payload}
            refs = _suricata_refs(selected, approved_asset_id=approved_asset_id)
        elif source_type == "zeek_json":
            selected = {key: payload.get(key) for key in _ZEEK_ENTITY_FIELDS if key in payload}
            refs = _zeek_refs(selected, approved_asset_id=approved_asset_id)
        else:
            raise MonitoringContractError("unsupported enriched sensor source_type")
        context = EventEntityContext(event_id=base.event_id, references=refs).validate()
        return ParsedCanonicalEvent(event=base, entity_context=context).validate()
    except (json.JSONDecodeError, MonitoringContractError, TypeError, ValueError):
        return _quarantine(
            source_id=source_id,
            source_type=source_type,
            parser_version=JSON_SENSOR_PARSER_VERSION,
            raw_line=raw_line,
            reason="ENTITY_CONTEXT_INVALID",
        )


def _audit_timestamp(value: Any) -> str:
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError("workspace audit timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise MonitoringContractError("workspace audit timestamp requires timezone")
    return parsed.isoformat()


def _audit_service(value: Any) -> str:
    service = str(value or "").strip().lower()
    mapped = SUPPORTED_AUTH_SERVICES.get(service)
    if mapped is None:
        raise MonitoringContractError("workspace audit auth service is unsupported")
    return mapped


def parse_workspace_audit_event(
    *,
    source_id: str,
    raw_line: str,
    approved_asset_id: str,
) -> ParsedCanonicalEvent | QuarantinedRecord:
    """Strict structured local audit parser for auth/process correlation.

    The payload may name an asset only as a consistency assertion. The explicit
    entity identity comes from trusted caller/config and must match exactly.
    Free-form log inference is deliberately unsupported. Unknown fields fail
    closed, preventing credential/command-line material from entering context.
    """

    try:
        payload = json.loads(raw_line)
        if not isinstance(payload, dict):
            raise MonitoringContractError("workspace audit payload must be an object")
        unknown = set(payload) - AUDIT_ALLOWED_KEYS
        if unknown:
            raise MonitoringContractError("workspace audit contains unsupported fields")
        event_type = str(payload.get("event_type") or "").strip().lower()
        if event_type not in AUDIT_EVENT_TYPES:
            raise MonitoringContractError("unsupported workspace audit event_type")
        observed_at = _audit_timestamp(payload.get("timestamp"))
        payload_asset_id = _compact(str(payload.get("asset_id") or ""), "asset_id", max_len=128)
        trusted_asset_id = _compact(approved_asset_id, "approved_asset_id", max_len=128)
        if payload_asset_id != trusted_asset_id:
            raise MonitoringContractError("workspace audit asset_id does not match trusted approved asset")
        user = str(payload.get("user") or "").strip()
        if not user or len(user) > 256:
            raise MonitoringContractError("workspace audit user is required")

        refs: list[EventEntityReference] = [
            EventEntityReference.approved_asset(role="asset", asset_id=trusted_asset_id),
            EventEntityReference.opaque(kind="user", role="auth_user", value=user),
        ]
        _entity_ip(refs, role="source_ip", value=payload.get("source_ip"))
        _entity_ip(refs, role="destination_ip", value=payload.get("destination_ip"))

        if event_type in {"auth_success", "auth_failure"}:
            service = _audit_service(payload.get("service"))
            refs.append(EventEntityReference.opaque(kind="service", role="service", value=service))
            if payload.get("process_image") not in (None, ""):
                raise MonitoringContractError("auth events must not carry process_image")
            expected_outcome = "success" if event_type == "auth_success" else "failure"
            if str(payload.get("outcome") or "").strip().lower() != expected_outcome:
                raise MonitoringContractError("workspace audit outcome does not match event_type")
            severity = "info" if event_type == "auth_success" else "medium"
        else:
            process_image = str(payload.get("process_image") or "").strip()
            if not process_image or len(process_image) > 512:
                raise MonitoringContractError("process_start requires process_image")
            if payload.get("service") not in (None, "") or payload.get("outcome") not in (None, ""):
                raise MonitoringContractError("process_start must not carry auth service/outcome")
            refs.append(EventEntityReference.opaque(kind="process", role="process_image", value=process_image))
            severity = "info"

        digest = _digest(raw_line)
        event = CanonicalEvent(
            event_id="evt-" + digest.removeprefix("sha256:")[:24],
            source_id=_compact(source_id, "source_id", max_len=128),
            source_type="workspace_audit",
            observed_at=observed_at,
            category="workspace_audit." + event_type,
            severity=severity,
            message_sha256=digest,
            parser_version=WORKSPACE_AUDIT_PARSER_VERSION,
            evidence_ref="event:" + digest.removeprefix("sha256:")[:32],
        ).validate()
        context = EventEntityContext(event_id=event.event_id, references=tuple(refs)).validate()
        return ParsedCanonicalEvent(event=event, entity_context=context).validate()
    except (json.JSONDecodeError, MonitoringContractError, TypeError, ValueError):
        return _quarantine(
            source_id=source_id,
            source_type="workspace_audit",
            parser_version=WORKSPACE_AUDIT_PARSER_VERSION,
            raw_line=raw_line,
            reason="WORKSPACE_AUDIT_INVALID",
        )
