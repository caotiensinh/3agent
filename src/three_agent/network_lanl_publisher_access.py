from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import unquote, urlsplit

from .network_lanl_adapter import LANL_AUTH_ADAPTER_ID, LANL_AUTH_ADAPTER_VERSION
from .network_lanl_dns_adapter import LANL_DNS_ADAPTER_ID, LANL_DNS_ADAPTER_VERSION
from .network_lanl_flow_adapter import LANL_FLOW_ADAPTER_ID, LANL_FLOW_ADAPTER_VERSION
from .network_lanl_process_adapter import (
    LANL_PROCESS_ADAPTER_ID,
    LANL_PROCESS_ADAPTER_VERSION,
)
from .network_lanl_redteam_matcher import (
    LANL_REDTEAM_MATCHER_ID,
    LANL_REDTEAM_MATCHER_VERSION,
)
from .network_real_source_acceptance_contract import canonical_sha256

PROFILE_SCHEMA = "workspace-network-v3-02e-lanl-publisher-access/v1"
RECEIPT_SCHEMA = "workspace-network-lanl-publisher-access-receipt/v1"
PHASE = "V3-02E-LANL-PUBLISHER-ACCESS"
PUBLISHER_REFERENCE = "https://csr.lanl.gov/data/cyber1/"
PUBLISHER_SCHEME = "https"
PUBLISHER_HOST = "csr.lanl.gov"
PUBLISHER_PORT = 443
PUBLISHER_PATH_PREFIX = "/data/"

READY = "READY_FOR_LANL_EXECUTION_SPEC"
NOT_ENOUGH = "NOT_ENOUGH_REAL_SOURCE_EVIDENCE"
FAIL_SECURITY = "FAIL_SECURITY"
FAIL_PROVENANCE = "FAIL_PROVENANCE"
FAIL_SCHEMA = "FAIL_SCHEMA"
FAIL_LICENSE = "FAIL_LICENSE"
READINESS_STATES = frozenset(
    {READY, NOT_ENOUGH, FAIL_SECURITY, FAIL_PROVENANCE, FAIL_SCHEMA, FAIL_LICENSE}
)

SOURCE_BINDINGS = {
    "auth": {
        "filename": "auth.txt.gz",
        "listed_size": "7.2G",
        "scorer_only": False,
        "adapter_id": LANL_AUTH_ADAPTER_ID,
        "adapter_version": LANL_AUTH_ADAPTER_VERSION,
    },
    "process": {
        "filename": "proc.txt.gz",
        "listed_size": "2.2G",
        "scorer_only": False,
        "adapter_id": LANL_PROCESS_ADAPTER_ID,
        "adapter_version": LANL_PROCESS_ADAPTER_VERSION,
    },
    "flow": {
        "filename": "flows.txt.gz",
        "listed_size": "1.1G",
        "scorer_only": False,
        "adapter_id": LANL_FLOW_ADAPTER_ID,
        "adapter_version": LANL_FLOW_ADAPTER_VERSION,
    },
    "dns": {
        "filename": "dns.txt.gz",
        "listed_size": "177M",
        "scorer_only": False,
        "adapter_id": LANL_DNS_ADAPTER_ID,
        "adapter_version": LANL_DNS_ADAPTER_VERSION,
    },
    "redteam": {
        "filename": "redteam.txt.gz",
        "listed_size": "4.8K",
        "scorer_only": True,
        "adapter_id": LANL_REDTEAM_MATCHER_ID,
        "adapter_version": LANL_REDTEAM_MATCHER_VERSION,
    },
}
SOURCE_FAMILIES = tuple(SOURCE_BINDINGS)

DURABLE_ALLOWED_KEYS = frozenset(
    {
        "schema_version",
        "phase",
        "readiness",
        "failed_gate_ids",
        "publisher_reference",
        "validated_source_families",
        "missing_source_families",
        "contract_fingerprint",
        "receipt_fingerprint",
    }
)
DURABLE_FORBIDDEN_KEYS = frozenset(
    {
        "email",
        "email_address",
        "intended_use",
        "purpose",
        "form_content",
        "access_url",
        "download_url",
        "direct_url",
        "raw_url",
        "query",
        "fragment",
        "credential",
        "credentials",
        "password",
        "token",
        "cookie",
        "session",
        "authorization",
    }
)
OPERATOR_FORM_KEYS = frozenset(
    {"email", "email_address", "intended_use", "purpose", "form_content"}
)
REDTEAM_SELECTION_KEYS = frozenset(
    {
        "redteam_driven_visible_slice",
        "redteam_selection",
        "truth_driven_selection",
    }
)
MAX_HANDLE_LENGTH = 4096
MAX_DURABLE_BYTES = 65536


class LANLPublisherAccessError(RuntimeError):
    def __init__(self, readiness: str, gate_id: str, message: str):
        if readiness not in READINESS_STATES - {READY, NOT_ENOUGH}:
            raise ValueError("hard access error must use a failure readiness")
        self.readiness = readiness
        self.gate_id = gate_id
        super().__init__(f"{gate_id}: {message}")


@dataclass(frozen=True)
class LANLAccessDecision:
    readiness: str
    failed_gate_ids: tuple[str, ...]
    validated_source_families: tuple[str, ...]
    missing_source_families: tuple[str, ...]
    receipt: dict[str, Any]


def _sha_format(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise LANLPublisherAccessError(FAIL_SCHEMA, "LANL_RECEIPT_SCHEMA", f"{field} invalid")
    text = value.strip().lower()
    if len(text) != 71 or not text.startswith("sha256:"):
        raise LANLPublisherAccessError(FAIL_SCHEMA, "LANL_RECEIPT_SCHEMA", f"{field} invalid")
    try:
        int(text[7:], 16)
    except ValueError as exc:
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_RECEIPT_SCHEMA", f"{field} invalid"
        ) from exc
    return text


def _profile_contract(profile: Mapping[str, Any]) -> None:
    if not isinstance(profile, Mapping) or profile.get("schema_version") != PROFILE_SCHEMA:
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_ACCESS_PROFILE_DRIFT", "profile schema mismatch"
        )
    if profile.get("phase") != PHASE:
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_ACCESS_PROFILE_DRIFT", "profile phase mismatch"
        )

    publisher = profile.get("publisher")
    if not isinstance(publisher, Mapping):
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_ACCESS_PROFILE_DRIFT", "publisher contract missing"
        )
    expected_publisher = {
        "landing_page": PUBLISHER_REFERENCE,
        "scheme": PUBLISHER_SCHEME,
        "host": PUBLISHER_HOST,
        "allowed_port": PUBLISHER_PORT,
        "path_prefix": PUBLISHER_PATH_PREFIX,
        "enrollment_required": True,
        "automated_form_submission_authorized": False,
        "operator_email_required_by_publisher": True,
        "operator_intended_use_required_by_publisher": True,
        "operator_identity_or_form_content_may_be_fabricated": False,
        "operator_form_content_may_be_durable": False,
    }
    for field, expected in expected_publisher.items():
        if publisher.get(field) != expected:
            readiness = (
                FAIL_SECURITY
                if field
                in {
                    "automated_form_submission_authorized",
                    "operator_identity_or_form_content_may_be_fabricated",
                    "operator_form_content_may_be_durable",
                }
                else FAIL_SCHEMA
            )
            raise LANLPublisherAccessError(
                readiness, "LANL_ACCESS_PROFILE_DRIFT", f"publisher field {field} drifted"
            )

    raw_sources = profile.get("required_sources")
    if not isinstance(raw_sources, list) or len(raw_sources) != len(SOURCE_BINDINGS):
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_ACCESS_PROFILE_DRIFT", "required source set drifted"
        )
    seen: set[str] = set()
    for item in raw_sources:
        if not isinstance(item, Mapping):
            raise LANLPublisherAccessError(
                FAIL_SCHEMA, "LANL_ACCESS_PROFILE_DRIFT", "source binding invalid"
            )
        family = str(item.get("source_family", ""))
        expected = SOURCE_BINDINGS.get(family)
        if expected is None or family in seen:
            raise LANLPublisherAccessError(
                FAIL_SCHEMA, "LANL_ACCESS_PROFILE_DRIFT", "source family invalid"
            )
        seen.add(family)
        exact = {
            "filename": expected["filename"],
            "publisher_listed_size": expected["listed_size"],
            "scorer_only": expected["scorer_only"],
            "adapter_id": expected["adapter_id"],
            "adapter_version": expected["adapter_version"],
        }
        for field, value in exact.items():
            if item.get(field) != value:
                raise LANLPublisherAccessError(
                    FAIL_SCHEMA,
                    "LANL_ACCESS_PROFILE_DRIFT",
                    f"source binding {family}/{field} drifted",
                )
    if seen != set(SOURCE_BINDINGS):
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_ACCESS_PROFILE_DRIFT", "source family set incomplete"
        )

    access = profile.get("access_handle_contract")
    if not isinstance(access, Mapping):
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_ACCESS_PROFILE_DRIFT", "access contract missing"
        )
    exact_access = {
        "input_is_ephemeral_only": True,
        "raw_handle_may_be_committed": False,
        "raw_handle_may_be_logged": False,
        "raw_handle_may_be_artifacted": False,
        "required_scheme": PUBLISHER_SCHEME,
        "required_host": PUBLISHER_HOST,
        "required_path_prefix": PUBLISHER_PATH_PREFIX,
        "embedded_userinfo_allowed": False,
        "query_allowed": False,
        "fragment_allowed": False,
        "redirect_to_alternate_host_allowed": False,
        "all_five_families_required_for_readiness": True,
    }
    for field, expected in exact_access.items():
        if access.get(field) != expected:
            readiness = FAIL_SECURITY if isinstance(expected, bool) else FAIL_SCHEMA
            raise LANLPublisherAccessError(
                readiness, "LANL_ACCESS_PROFILE_DRIFT", f"access field {field} drifted"
            )

    durable = profile.get("durable_output")
    if not isinstance(durable, Mapping):
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_ACCESS_PROFILE_DRIFT", "durable contract missing"
        )
    if frozenset(map(str, durable.get("allowed_keys", []))) != DURABLE_ALLOWED_KEYS:
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_ACCESS_PROFILE_DRIFT", "durable allowlist drifted"
        )
    if frozenset(map(str, durable.get("forbidden_keys", []))) != DURABLE_FORBIDDEN_KEYS:
        raise LANLPublisherAccessError(
            FAIL_SECURITY, "LANL_ACCESS_PROFILE_DRIFT", "durable denylist drifted"
        )
    if durable.get("max_bytes") != MAX_DURABLE_BYTES:
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_ACCESS_PROFILE_DRIFT", "durable byte bound drifted"
        )

    if frozenset(map(str, profile.get("readiness_states", []))) != READINESS_STATES:
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_ACCESS_PROFILE_DRIFT", "readiness states drifted"
        )

    authority = profile.get("execution_authority")
    if not isinstance(authority, Mapping) or not authority:
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_ACCESS_PROFILE_DRIFT", "execution authority missing"
        )
    for field, value in authority.items():
        if value is not False:
            raise LANLPublisherAccessError(
                FAIL_SECURITY,
                "LANL_ACQUISITION_ATTEMPT_BEFORE_EXECUTION_SPEC",
                f"execution authority must remain false: {field}",
            )


def _validate_handle(family: str, raw: Any) -> None:
    if not isinstance(raw, str):
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_ACCESS_INPUT_SCHEMA", "access handle must be string"
        )
    text = raw.strip()
    if not text or len(text) > MAX_HANDLE_LENGTH or any(ord(ch) < 32 for ch in text):
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_ACCESS_INPUT_SCHEMA", "access handle is malformed"
        )
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except ValueError as exc:
        raise LANLPublisherAccessError(
            FAIL_PROVENANCE, "LANL_ACCESS_URL_INVALID", "publisher access URL invalid"
        ) from exc

    if parsed.scheme.casefold() != PUBLISHER_SCHEME:
        raise LANLPublisherAccessError(
            FAIL_PROVENANCE, "LANL_ACCESS_URL_INVALID", "publisher access must use HTTPS"
        )
    if parsed.username is not None or parsed.password is not None:
        raise LANLPublisherAccessError(
            FAIL_SECURITY,
            "LANL_ACCESS_HANDLE_HAS_CREDENTIAL_AUTHORITY",
            "embedded URL credentials are forbidden",
        )
    if (parsed.hostname or "").casefold() != PUBLISHER_HOST:
        raise LANLPublisherAccessError(
            FAIL_PROVENANCE,
            "LANL_MIRROR_OR_ALTERNATE_HOST",
            "publisher hostname mismatch",
        )
    if port not in {None, PUBLISHER_PORT}:
        raise LANLPublisherAccessError(
            FAIL_PROVENANCE, "LANL_ACCESS_URL_INVALID", "publisher port mismatch"
        )
    if parsed.query or parsed.fragment:
        raise LANLPublisherAccessError(
            FAIL_SECURITY,
            "LANL_UNREVIEWED_QUERY_OR_FRAGMENT",
            "query/fragment requires separate publisher-mechanism review",
        )

    decoded_path = unquote(parsed.path)
    if "\\" in decoded_path:
        raise LANLPublisherAccessError(
            FAIL_SECURITY, "LANL_ACCESS_PATH_ESCAPE", "unsafe path separator"
        )
    parts = decoded_path.split("/")
    if any(part in {".", ".."} for part in parts):
        raise LANLPublisherAccessError(
            FAIL_SECURITY, "LANL_ACCESS_PATH_ESCAPE", "path traversal forbidden"
        )
    if not decoded_path.startswith(PUBLISHER_PATH_PREFIX):
        raise LANLPublisherAccessError(
            FAIL_PROVENANCE, "LANL_ACCESS_URL_INVALID", "publisher path prefix mismatch"
        )
    expected_filename = str(SOURCE_BINDINGS[family]["filename"])
    if not parts or parts[-1] != expected_filename:
        raise LANLPublisherAccessError(
            FAIL_PROVENANCE,
            "LANL_FILENAME_MISMATCH",
            "publisher filename does not match source family",
        )


def _forbid_durable_keys(value: Any, path: str = "receipt") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).strip().casefold() in DURABLE_FORBIDDEN_KEYS:
                raise LANLPublisherAccessError(
                    FAIL_SECURITY,
                    "LANL_ACCESS_HANDLE_IN_DURABLE_OUTPUT",
                    f"forbidden durable field at {path}",
                )
            _forbid_durable_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _forbid_durable_keys(child, f"{path}[{index}]")


def _receipt(
    *,
    profile: Mapping[str, Any],
    readiness: str,
    failed_gate_ids: tuple[str, ...],
    validated: tuple[str, ...],
    missing: tuple[str, ...],
) -> dict[str, Any]:
    identity = {
        "schema_version": RECEIPT_SCHEMA,
        "phase": PHASE,
        "readiness": readiness,
        "failed_gate_ids": list(failed_gate_ids),
        "publisher_reference": PUBLISHER_REFERENCE,
        "validated_source_families": list(validated),
        "missing_source_families": list(missing),
        "contract_fingerprint": canonical_sha256(profile),
    }
    receipt = dict(identity)
    receipt["receipt_fingerprint"] = canonical_sha256(identity)
    validate_durable_receipt(receipt, profile=profile)
    return receipt


def validate_durable_receipt(receipt: Mapping[str, Any], *, profile: Mapping[str, Any]) -> None:
    _profile_contract(profile)
    if not isinstance(receipt, Mapping):
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_RECEIPT_SCHEMA", "receipt must be object"
        )
    _forbid_durable_keys(receipt)
    if frozenset(receipt) != DURABLE_ALLOWED_KEYS:
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_RECEIPT_SCHEMA", "receipt field set drifted"
        )
    try:
        encoded = json.dumps(
            receipt,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_RECEIPT_SCHEMA", "receipt must be canonical JSON"
        ) from exc
    if len(encoded) > MAX_DURABLE_BYTES:
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_RECEIPT_SCHEMA", "receipt exceeds byte bound"
        )
    if receipt.get("schema_version") != RECEIPT_SCHEMA or receipt.get("phase") != PHASE:
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_RECEIPT_SCHEMA", "receipt schema/phase mismatch"
        )
    readiness = receipt.get("readiness")
    if readiness not in READINESS_STATES:
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_RECEIPT_SCHEMA", "receipt readiness invalid"
        )
    if receipt.get("publisher_reference") != PUBLISHER_REFERENCE:
        raise LANLPublisherAccessError(
            FAIL_PROVENANCE, "LANL_RECEIPT_SCHEMA", "publisher reference mismatch"
        )
    validated = receipt.get("validated_source_families")
    missing = receipt.get("missing_source_families")
    if not isinstance(validated, list) or not isinstance(missing, list):
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_RECEIPT_SCHEMA", "source family lists invalid"
        )
    if any(item not in SOURCE_BINDINGS for item in validated + missing):
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_RECEIPT_SCHEMA", "unknown source family in receipt"
        )
    if len(set(validated)) != len(validated) or len(set(missing)) != len(missing):
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_RECEIPT_SCHEMA", "duplicate source family in receipt"
        )
    if set(validated) & set(missing) or set(validated) | set(missing) != set(SOURCE_BINDINGS):
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_RECEIPT_SCHEMA", "receipt source partition invalid"
        )
    gates = receipt.get("failed_gate_ids")
    if not isinstance(gates, list) or any(not isinstance(item, str) or not item for item in gates):
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_RECEIPT_SCHEMA", "receipt gates invalid"
        )
    contract_fp = _sha_format(receipt.get("contract_fingerprint"), "contract_fingerprint")
    if contract_fp != canonical_sha256(profile):
        raise LANLPublisherAccessError(
            FAIL_PROVENANCE, "LANL_RECEIPT_SCHEMA", "contract fingerprint mismatch"
        )
    expected_identity = dict(receipt)
    supplied_receipt_fp = _sha_format(
        expected_identity.pop("receipt_fingerprint"), "receipt_fingerprint"
    )
    if supplied_receipt_fp != canonical_sha256(expected_identity):
        raise LANLPublisherAccessError(
            FAIL_PROVENANCE, "LANL_RECEIPT_SCHEMA", "receipt fingerprint mismatch"
        )


def evaluate_access_handles(
    handles: Mapping[str, Any] | None,
    *,
    profile: Mapping[str, Any],
) -> LANLAccessDecision:
    _profile_contract(profile)
    if handles is None:
        handles = {}
    if not isinstance(handles, Mapping):
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_ACCESS_INPUT_SCHEMA", "access input must be object"
        )

    normalized_keys = {str(key).strip().casefold() for key in handles}
    if normalized_keys & OPERATOR_FORM_KEYS:
        raise LANLPublisherAccessError(
            FAIL_SECURITY,
            "LANL_OPERATOR_FORM_CONTENT_PERSISTED",
            "operator form content is forbidden in access input",
        )
    if normalized_keys & REDTEAM_SELECTION_KEYS:
        raise LANLPublisherAccessError(
            FAIL_SECURITY,
            "LANL_REDTEAM_TRUTH_USED_TO_SELECT_VISIBLE_SOURCE",
            "truth-driven visible-source selection is forbidden",
        )
    unknown = set(map(str, handles)) - set(SOURCE_BINDINGS)
    if unknown:
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_ACCESS_INPUT_SCHEMA", "unknown access source family"
        )

    if not handles:
        missing = tuple(SOURCE_FAMILIES)
        gates = ("LANL_ACCESS_HANDLE_MISSING",)
        receipt = _receipt(
            profile=profile,
            readiness=NOT_ENOUGH,
            failed_gate_ids=gates,
            validated=(),
            missing=missing,
        )
        return LANLAccessDecision(NOT_ENOUGH, gates, (), missing, receipt)

    validated: list[str] = []
    for family in SOURCE_FAMILIES:
        if family not in handles:
            continue
        _validate_handle(family, handles[family])
        validated.append(family)
    missing = tuple(family for family in SOURCE_FAMILIES if family not in handles)
    if missing:
        gates = ("LANL_SOURCE_FAMILY_MISSING",)
        receipt = _receipt(
            profile=profile,
            readiness=NOT_ENOUGH,
            failed_gate_ids=gates,
            validated=tuple(validated),
            missing=missing,
        )
        return LANLAccessDecision(
            NOT_ENOUGH, gates, tuple(validated), missing, receipt
        )

    receipt = _receipt(
        profile=profile,
        readiness=READY,
        failed_gate_ids=(),
        validated=tuple(SOURCE_FAMILIES),
        missing=(),
    )
    return LANLAccessDecision(
        READY, (), tuple(SOURCE_FAMILIES), (), receipt
    )


def _read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise LANLPublisherAccessError(
            FAIL_SECURITY, "LANL_ACCESS_INPUT_SCHEMA", "symlink input is forbidden"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_ACCESS_INPUT_SCHEMA", "JSON input is invalid"
        ) from exc
    if not isinstance(value, dict):
        raise LANLPublisherAccessError(
            FAIL_SCHEMA, "LANL_ACCESS_INPUT_SCHEMA", "JSON input must be object"
        )
    return value


def _write_receipt(path: Path, receipt: Mapping[str, Any], *, profile: Mapping[str, Any]) -> None:
    validate_durable_receipt(receipt, profile=profile)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise LANLPublisherAccessError(
            FAIL_SECURITY, "LANL_ACCESS_HANDLE_IN_DURABLE_OUTPUT", "output symlink forbidden"
        )
    path.write_text(
        json.dumps(receipt, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline LANL publisher-access readiness validator"
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--handles-json")
    parser.add_argument("--output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        profile = _read_json(Path(args.profile))
        handles = _read_json(Path(args.handles_json)) if args.handles_json else {}
        decision = evaluate_access_handles(handles, profile=profile)
        _write_receipt(Path(args.output), decision.receipt, profile=profile)
    except LANLPublisherAccessError as exc:
        print(json.dumps({"readiness": exc.readiness, "gate_id": exc.gate_id}, sort_keys=True))
        return 1
    print(
        json.dumps(
            {
                "readiness": decision.readiness,
                "failed_gate_ids": list(decision.failed_gate_ids),
            },
            sort_keys=True,
        )
    )
    if decision.readiness == READY:
        return 0
    if decision.readiness == NOT_ENOUGH:
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
