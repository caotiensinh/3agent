from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .contracts import CanonicalEvent, MonitoringContractError, _compact
from .enriched_parsers import ParsedCanonicalEvent
from .entity_context import EventEntityContext, EventEntityReference
from .parsers import QuarantinedRecord

WINDOWS_EVTX_ADAPTER_VERSION = "windows-security-evtx/v1"
SUPPORTED_WINDOWS_EVENT_IDS = frozenset({4624, 4625, 4672, 4688})
WINDOWS_EVENT_ALLOWED_KEYS = frozenset(
    {
        "timestamp",
        "event_id",
        "asset_id",
        "user",
        "source_ip",
        "logon_type",
        "process_image",
    }
)
_LOGON_TYPES = frozenset({2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13})


def _digest(raw_line: str) -> str:
    return "sha256:" + hashlib.sha256(raw_line.encode("utf-8", errors="replace")).hexdigest()


def _quarantine(*, source_id: str, raw_line: str, reason: str) -> QuarantinedRecord:
    return QuarantinedRecord(
        source_id=source_id,
        source_type="windows_security_evtx",
        parser_version=WINDOWS_EVTX_ADAPTER_VERSION,
        reason_code=reason,
        payload_sha256=_digest(raw_line),
        observed_at=datetime.now(timezone.utc).isoformat(),
    )


def _timestamp(value: Any) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError("Windows event timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MonitoringContractError("Windows event timestamp requires timezone")
    return parsed.isoformat()


def _user_ref(refs: list[EventEntityReference], value: Any) -> None:
    user = str(value or "").strip()
    if not user or len(user) > 256 or any(ord(ch) < 32 for ch in user):
        raise MonitoringContractError("Windows event user is invalid")
    refs.append(EventEntityReference.opaque(kind="user", role="auth_user", value=user))


def _source_ip_ref(refs: list[EventEntityReference], value: Any) -> None:
    if value in (None, "", "-"):
        return
    refs.append(EventEntityReference.opaque(kind="ip", role="source_ip", value=str(value)))


def parse_windows_security_event(
    *,
    source_id: str,
    raw_line: str,
    approved_asset_id: str,
) -> ParsedCanonicalEvent | QuarantinedRecord:
    """Normalize a strict Windows Security-event projection into existing audit semantics.

    Input must already be an authorized structured projection of an EVTX record.
    This adapter never opens an EVTX file, invokes PowerShell, contacts an endpoint,
    or retains raw usernames/IPs in entity context. Event IDs 4624/4625/4688 map
    onto the existing workspace audit AUTH/PROCESS categories so current exact
    correlation logic is reused. 4672 remains explicit privilege metadata and is
    deliberately not promoted to an authentication correlation stage.
    """

    try:
        payload = json.loads(raw_line)
        if not isinstance(payload, dict):
            raise MonitoringContractError("Windows event payload must be an object")
        if set(payload) - WINDOWS_EVENT_ALLOWED_KEYS:
            raise MonitoringContractError("Windows event projection contains unsupported fields")
        event_id = int(payload.get("event_id"))
        if event_id not in SUPPORTED_WINDOWS_EVENT_IDS:
            raise MonitoringContractError("unsupported Windows Security event_id")
        trusted_asset = _compact(approved_asset_id, "approved_asset_id", max_len=128)
        asserted_asset = _compact(str(payload.get("asset_id") or ""), "asset_id", max_len=128)
        if trusted_asset != asserted_asset:
            raise MonitoringContractError("Windows event asset does not match trusted approved asset")
        observed_at = _timestamp(payload.get("timestamp"))
        refs: list[EventEntityReference] = [
            EventEntityReference.approved_asset(role="asset", asset_id=trusted_asset),
        ]
        _user_ref(refs, payload.get("user"))
        _source_ip_ref(refs, payload.get("source_ip"))

        if event_id in {4624, 4625}:
            if payload.get("process_image") not in (None, ""):
                raise MonitoringContractError("Windows logon event must not carry process_image")
            try:
                logon_type = int(payload.get("logon_type"))
            except (TypeError, ValueError) as exc:
                raise MonitoringContractError("Windows logon_type is required") from exc
            if logon_type not in _LOGON_TYPES:
                raise MonitoringContractError("unsupported Windows logon_type")
            refs.append(
                EventEntityReference.opaque(
                    kind="service",
                    role="service",
                    value=f"windows-logon:{logon_type}",
                )
            )
            category = "workspace_audit.auth_success" if event_id == 4624 else "workspace_audit.auth_failure"
            severity = "info" if event_id == 4624 else "medium"
        elif event_id == 4688:
            if payload.get("logon_type") not in (None, ""):
                raise MonitoringContractError("Windows process event must not carry logon_type")
            process_image = str(payload.get("process_image") or "").strip()
            if not process_image or len(process_image) > 512:
                raise MonitoringContractError("Windows 4688 requires process_image")
            refs.append(EventEntityReference.opaque(kind="process", role="process_image", value=process_image))
            category = "workspace_audit.process_start"
            severity = "info"
        else:
            if payload.get("logon_type") not in (None, "") or payload.get("process_image") not in (None, ""):
                raise MonitoringContractError("Windows 4672 projection contains incompatible fields")
            category = "workspace_audit.auth_privilege"
            severity = "medium"

        digest = _digest(raw_line)
        canonical = CanonicalEvent(
            event_id="evt-" + digest.removeprefix("sha256:")[:24],
            source_id=_compact(source_id, "source_id", max_len=128),
            source_type="workspace_audit",
            observed_at=observed_at,
            category=category,
            severity=severity,
            message_sha256=digest,
            parser_version=WINDOWS_EVTX_ADAPTER_VERSION,
            evidence_ref="event:" + digest.removeprefix("sha256:")[:32],
        ).validate()
        context = EventEntityContext(event_id=canonical.event_id, references=tuple(refs)).validate()
        return ParsedCanonicalEvent(event=canonical, entity_context=context).validate()
    except (json.JSONDecodeError, MonitoringContractError, TypeError, ValueError):
        return _quarantine(source_id=source_id, raw_line=raw_line, reason="WINDOWS_EVTX_PROJECTION_INVALID")
