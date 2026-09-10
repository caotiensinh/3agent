from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from .contracts import MonitoringContractError, _compact
from .entity_context import opaque_entity_ref

DNS_BEHAVIOR_SCHEMA = "workspace-security-monitoring/dns-behavior-feature-v1"
DNS_BEHAVIOR_PARSER_VERSION = "workspace-dns-behavior/v1"
SUPPORTED_DNS_SOURCES = {"suricata_eve", "zeek_json"}
MAX_DNS_QUERY_LENGTH = 253
MAX_DNS_LABELS = 127
MAX_DNS_ANSWERS = 256
_RESPONSE_CODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}
_RESPONSE_NAMES = set(_RESPONSE_CODES.values())
_QUERY_TYPE_RE = re.compile(r"^[A-Z0-9][A-Z0-9_-]{0,15}$")
_DNS_REF_RE = re.compile(r"^entity:dns:sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class DNSBehaviorFeatures:
    event_id: str
    source_type: str
    query_entity_ref: str
    query_length: int
    label_count: int
    max_label_length: int
    shannon_entropy: float
    normalized_entropy: float
    digit_count: int
    hyphen_count: int
    answer_count: int
    response_code: str | None
    query_type: str | None
    schema_version: str = DNS_BEHAVIOR_SCHEMA
    parser_version: str = DNS_BEHAVIOR_PARSER_VERSION

    def validate(self) -> "DNSBehaviorFeatures":
        object.__setattr__(self, "event_id", _compact(self.event_id, "event_id", max_len=128))
        source_type = str(self.source_type or "").strip()
        if source_type not in SUPPORTED_DNS_SOURCES:
            raise MonitoringContractError("unsupported DNS behavior source_type")
        object.__setattr__(self, "source_type", source_type)
        if not _DNS_REF_RE.fullmatch(str(self.query_entity_ref or "")):
            raise MonitoringContractError("DNS behavior query must use typed SHA-256 entity reference")
        if self.schema_version != DNS_BEHAVIOR_SCHEMA or self.parser_version != DNS_BEHAVIOR_PARSER_VERSION:
            raise MonitoringContractError("unsupported DNS behavior schema/parser version")
        if not 1 <= int(self.query_length) <= MAX_DNS_QUERY_LENGTH:
            raise MonitoringContractError("DNS query length is outside supported bounds")
        if not 1 <= int(self.label_count) <= MAX_DNS_LABELS:
            raise MonitoringContractError("DNS label count is outside supported bounds")
        if not 1 <= int(self.max_label_length) <= int(self.query_length):
            raise MonitoringContractError("DNS max label length is invalid")
        for field_name, value in (
            ("shannon_entropy", self.shannon_entropy),
            ("normalized_entropy", self.normalized_entropy),
        ):
            number = float(value)
            if not math.isfinite(number) or number < 0:
                raise MonitoringContractError(f"{field_name} must be finite and non-negative")
        if float(self.normalized_entropy) > 1.0:
            raise MonitoringContractError("normalized DNS entropy must be within 0..1")
        if not 0 <= int(self.digit_count) <= int(self.query_length):
            raise MonitoringContractError("DNS digit count is invalid")
        if not 0 <= int(self.hyphen_count) <= int(self.query_length):
            raise MonitoringContractError("DNS hyphen count is invalid")
        if not 0 <= int(self.answer_count) <= MAX_DNS_ANSWERS:
            raise MonitoringContractError("DNS answer count is outside supported bounds")
        if self.response_code is not None and self.response_code not in _RESPONSE_NAMES:
            raise MonitoringContractError("unsupported DNS response code")
        if self.query_type is not None and not _QUERY_TYPE_RE.fullmatch(self.query_type):
            raise MonitoringContractError("unsupported DNS query type")
        return self

    @property
    def is_nxdomain(self) -> bool:
        return self.response_code == "NXDOMAIN"

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "parser_version": self.parser_version,
            "event_id": self.event_id,
            "source_type": self.source_type,
            "query_entity_ref": self.query_entity_ref,
            "query_length": self.query_length,
            "label_count": self.label_count,
            "max_label_length": self.max_label_length,
            "shannon_entropy": self.shannon_entropy,
            "normalized_entropy": self.normalized_entropy,
            "digit_count": self.digit_count,
            "hyphen_count": self.hyphen_count,
            "answer_count": self.answer_count,
            "response_code": self.response_code,
            "query_type": self.query_type,
        }


def _normalized_query(value: Any) -> str:
    query = str(value or "").strip().rstrip(".").lower()
    if not query or len(query) > MAX_DNS_QUERY_LENGTH or any(ch.isspace() or ord(ch) < 32 for ch in query):
        raise MonitoringContractError("DNS behavior query is invalid")
    labels = query.split(".")
    if len(labels) > MAX_DNS_LABELS or any(not label for label in labels):
        raise MonitoringContractError("DNS behavior labels are invalid")
    # Reuse the v0.0.3 canonical DNS identity validation/hashing boundary.
    opaque_entity_ref("dns", query)
    return query


def _entropy(query: str) -> tuple[float, float]:
    counts = Counter(query)
    length = len(query)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    alphabet = len(counts)
    maximum = math.log2(alphabet) if alphabet > 1 else 0.0
    normalized = entropy / maximum if maximum > 0 else 0.0
    return round(entropy, 6), round(normalized, 6)


def _response_code(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        raise MonitoringContractError("DNS response code must not be boolean")
    if isinstance(value, int):
        if value not in _RESPONSE_CODES:
            return None
        return _RESPONSE_CODES[value]
    text = str(value).strip().upper()
    if text.isdigit():
        number = int(text)
        return _RESPONSE_CODES.get(number)
    return text if text in _RESPONSE_NAMES else None


def _query_type(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        raise MonitoringContractError("DNS query type must not be boolean")
    if isinstance(value, int):
        if not 0 <= value <= 65535:
            raise MonitoringContractError("DNS numeric query type out of range")
        return f"TYPE{value}"
    text = str(value).strip().upper()
    if not _QUERY_TYPE_RE.fullmatch(text):
        return None
    return text


def _answer_count(value: Any) -> int:
    if value in (None, ""):
        return 0
    if isinstance(value, list):
        if len(value) > MAX_DNS_ANSWERS:
            raise MonitoringContractError("DNS answer list exceeds supported bound")
        return len(value)
    # Some Suricata EVE formats expose one rdata value rather than an answer list.
    return 1


def extract_dns_behavior_features(
    *,
    event_id: str,
    source_type: str,
    raw_line: str,
) -> DNSBehaviorFeatures | None:
    """Derive non-reversible DNS metrics from an already-local structured event.

    Raw query text is used only within this call. The returned object retains
    the v0.0.3 typed DNS hash plus bounded numeric/categorical metadata.
    """

    if source_type not in SUPPORTED_DNS_SOURCES:
        raise MonitoringContractError("unsupported DNS behavior source_type")
    try:
        payload = json.loads(raw_line)
    except json.JSONDecodeError as exc:
        raise MonitoringContractError("DNS behavior input must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise MonitoringContractError("DNS behavior input must be a JSON object")

    if source_type == "suricata_eve":
        if str(payload.get("event_type") or "").strip().lower() != "dns":
            return None
        dns = payload.get("dns")
        if not isinstance(dns, dict):
            raise MonitoringContractError("Suricata DNS event requires dns object")
        query_value = dns.get("rrname")
        if query_value in (None, ""):
            # Newer EVE variants may be supported in a future explicit schema;
            # do not infer a query from arbitrary nested fields in this version.
            raise MonitoringContractError("Suricata DNS rrname is required by behavior v1")
        response = _response_code(dns.get("rcode"))
        qtype = _query_type(dns.get("rrtype"))
        answers_value = dns.get("answers") if "answers" in dns else dns.get("rdata")
    else:
        path = str(payload.get("_path") or payload.get("event_type") or "").strip().lower().lstrip("/")
        if path != "dns":
            return None
        query_value = payload.get("query")
        if query_value in (None, ""):
            raise MonitoringContractError("Zeek DNS query is required by behavior v1")
        response = _response_code(payload.get("rcode_name") if "rcode_name" in payload else payload.get("rcode"))
        qtype = _query_type(payload.get("qtype_name") if "qtype_name" in payload else payload.get("qtype"))
        answers_value = payload.get("answers")

    query = _normalized_query(query_value)
    labels = query.split(".")
    entropy, normalized_entropy = _entropy(query)
    result = DNSBehaviorFeatures(
        event_id=event_id,
        source_type=source_type,
        query_entity_ref=opaque_entity_ref("dns", query),
        query_length=len(query),
        label_count=len(labels),
        max_label_length=max(len(label) for label in labels),
        shannon_entropy=entropy,
        normalized_entropy=normalized_entropy,
        digit_count=sum(ch.isdigit() for ch in query),
        hyphen_count=query.count("-"),
        answer_count=_answer_count(answers_value),
        response_code=response,
        query_type=qtype,
    )
    return result.validate()
