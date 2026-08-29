from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable

SECURITY_METADATA_SCHEMA = "workspace-handoff-security/v1"
_RISK_ORDER = {"low": 0, "medium": 1, "high": 2}


class HandoffSecurityValidationError(ValueError):
    """Typed handoff metadata is missing, inconsistent, or tampered."""


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _compact_findings(findings: Iterable[dict[str, Any]]) -> tuple[dict[str, Any], ...]:
    compact: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for finding in findings:
        path = str(finding.get("path", "$"))
        risk = str(finding.get("risk", "low"))
        if risk not in _RISK_ORDER:
            risk = "low"
        raw_signals = finding.get("signals", [])
        signals = tuple(sorted({str(item) for item in raw_signals})) if isinstance(
            raw_signals, (list, tuple, set)
        ) else ()
        key = (path, risk, signals)
        if key in seen:
            continue
        seen.add(key)
        compact.append({"path": path, "risk": risk, "signals": list(signals)})
    return tuple(compact)


@dataclass(frozen=True)
class HandoffSecurityMetadata:
    source_agent: str
    source_type: str
    target_agent: str
    task_id: str
    trust_domain: str
    content_hash: str
    sanitizer_version: str
    risk_level: str
    findings: tuple[dict[str, Any], ...]
    provenance_refs: tuple[str, ...]
    raw_content_logged: bool = False
    schema_version: str = SECURITY_METADATA_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "source_agent": self.source_agent,
            "source_type": self.source_type,
            "target_agent": self.target_agent,
            "task_id": self.task_id,
            "trust_domain": self.trust_domain,
            "content_hash": self.content_hash,
            "sanitizer_version": self.sanitizer_version,
            "risk_level": self.risk_level,
            "finding_count": len(self.findings),
            "findings": [dict(item) for item in self.findings],
            "provenance_refs": list(self.provenance_refs),
            "raw_content_logged": False,
        }


def build_handoff_security_metadata(
    sanitized_payload: Any,
    findings: Iterable[dict[str, Any]],
    *,
    source_agent: str,
    source_type: str,
    target_agent: str,
    task_id: str,
    trust_domain: str,
    sanitizer_version: str,
    provenance_refs: Iterable[str] = (),
) -> HandoffSecurityMetadata:
    compact = _compact_findings(findings)
    highest = "low"
    for finding in compact:
        risk = str(finding.get("risk", "low"))
        if _RISK_ORDER.get(risk, 0) > _RISK_ORDER[highest]:
            highest = risk

    refs = tuple(dict.fromkeys(str(ref) for ref in provenance_refs if str(ref)))
    return HandoffSecurityMetadata(
        source_agent=str(source_agent or "unknown"),
        source_type=str(source_type or "unknown"),
        target_agent=str(target_agent or "unknown"),
        task_id=str(task_id or ""),
        trust_domain=str(trust_domain or "untrusted"),
        content_hash=_canonical_hash(sanitized_payload),
        sanitizer_version=str(sanitizer_version or "unknown"),
        risk_level=highest,
        findings=compact,
        provenance_refs=refs,
    )


def verify_handoff_security_metadata(
    payload: dict[str, Any],
    *,
    expected_source_agent: str,
    expected_target_agent: str,
    expected_task_id: str,
) -> dict[str, Any]:
    """Verify the producer security envelope without trusting embedded content.

    The hash covers the complete handoff before the ``security`` field is attached.
    Identity expectations are supplied by trusted caller state rather than by model
    or retrieved text. This verifier never grants authority; it only rejects broken
    lineage/integrity metadata.
    """
    if not isinstance(payload, dict):
        raise HandoffSecurityValidationError("HANDOFF_PAYLOAD_NOT_OBJECT")
    raw_security = payload.get("security")
    if not isinstance(raw_security, dict):
        raise HandoffSecurityValidationError("HANDOFF_SECURITY_METADATA_MISSING")
    if raw_security.get("schema_version") != SECURITY_METADATA_SCHEMA:
        raise HandoffSecurityValidationError("HANDOFF_SECURITY_SCHEMA_UNSUPPORTED")
    if str(raw_security.get("source_agent") or "") != expected_source_agent:
        raise HandoffSecurityValidationError("HANDOFF_SECURITY_SOURCE_AGENT_MISMATCH")
    if str(raw_security.get("target_agent") or "") != expected_target_agent:
        raise HandoffSecurityValidationError("HANDOFF_SECURITY_TARGET_AGENT_MISMATCH")
    if str(raw_security.get("task_id") or "") != expected_task_id:
        raise HandoffSecurityValidationError("HANDOFF_SECURITY_TASK_ID_MISMATCH")
    if raw_security.get("raw_content_logged") is not False:
        raise HandoffSecurityValidationError("HANDOFF_SECURITY_RAW_LOG_POLICY_INVALID")

    hash_target = dict(payload)
    hash_target.pop("security", None)
    if str(raw_security.get("content_hash") or "") != _canonical_hash(hash_target):
        raise HandoffSecurityValidationError("HANDOFF_SECURITY_CONTENT_HASH_MISMATCH")

    risk = str(raw_security.get("risk_level") or "")
    if risk not in _RISK_ORDER:
        raise HandoffSecurityValidationError("HANDOFF_SECURITY_RISK_INVALID")
    findings = raw_security.get("findings")
    if not isinstance(findings, list):
        raise HandoffSecurityValidationError("HANDOFF_SECURITY_FINDINGS_INVALID")
    if int(raw_security.get("finding_count", -1)) != len(findings):
        raise HandoffSecurityValidationError("HANDOFF_SECURITY_FINDING_COUNT_MISMATCH")
    return raw_security
