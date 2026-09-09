from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

COMPUTER_ACTION_REQUEST_SCHEMA = "workspace-computer-action-request/v1"
COMPUTER_OBSERVATION_SCHEMA = "workspace-computer-observation/v1"
COMPUTER_ROUTE_DECISION_SCHEMA = "workspace-computer-route-decision/v1"

RISK_CLASSES = frozenset(
    {
        "R0_OBSERVE",
        "R1_REVERSIBLE_INTERACTION",
        "R2_STATE_CHANGE",
        "R3_PRIVILEGED_OR_SENSITIVE",
    }
)

EXECUTION_ROUTES = (
    "api",
    "cli",
    "dom",
    "accessibility",
    "vision_pointer",
)

_OPERATION_POLICY = {
    "computer.screen.observe": ("read", "R0_OBSERVE", False),
    "computer.window.observe": ("read", "R0_OBSERVE", False),
    "computer.accessibility.observe": ("read", "R0_OBSERVE", False),
    "browser.dom.observe": ("read", "R0_OBSERVE", False),
    "browser.navigate": ("network_read", "R1_REVERSIBLE_INTERACTION", False),
    "browser.interact": ("write", "R2_STATE_CHANGE", True),
    "computer.pointer.interact": ("write", "R2_STATE_CHANGE", True),
    "computer.keyboard.interact": ("write", "R2_STATE_CHANGE", True),
    "computer.clipboard.read": ("read", "R0_OBSERVE", False),
    "computer.clipboard.write": ("write", "R2_STATE_CHANGE", True),
}

_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,255}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROVIDER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SURFACES = frozenset({"browser", "desktop", "system"})
MAX_ARGUMENT_BYTES = 16 * 1024
MAX_OBSERVATION_BYTES = 64 * 1024


class ComputerUseError(ValueError):
    """Computer-use input is malformed, stale, or outside the canonical contract."""


def _canonical_json(value: Any, *, error_code: str) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ComputerUseError(error_code) from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        _canonical_json(value, error_code="COMPUTER_VALUE_NOT_CANONICAL_JSON").encode("utf-8")
    ).hexdigest()


def _reference(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not _REF_RE.fullmatch(value):
        raise ComputerUseError(f"INVALID_{field_name.upper()}")
    if "://" in value or any(part == ".." for part in value.split("/")):
        raise ComputerUseError(f"INVALID_{field_name.upper()}")
    return value


def _sha256(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ComputerUseError(f"INVALID_{field_name.upper()}")
    return value


def _provider_ref(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value != value.strip() or not _PROVIDER_RE.fullmatch(value):
        raise ComputerUseError("INVALID_PROVIDER_REF")
    return value


def _timestamp(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise ComputerUseError(f"INVALID_{field_name.upper()}")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ComputerUseError(f"INVALID_{field_name.upper()}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ComputerUseError(f"{field_name.upper()}_MUST_BE_TIMEZONE_AWARE")
    canonical = parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if canonical != value:
        raise ComputerUseError(f"{field_name.upper()}_MUST_BE_NORMALIZED_UTC")
    return value


def _bounded_mapping(value: Mapping[str, Any], *, limit: int, error_prefix: str) -> str:
    if not isinstance(value, Mapping):
        raise ComputerUseError(f"{error_prefix}_MUST_BE_OBJECT")
    canonical = _canonical_json(dict(value), error_code=f"{error_prefix}_NOT_CANONICAL_JSON")
    if len(canonical.encode("utf-8")) > limit:
        raise ComputerUseError(f"{error_prefix}_BOUND_EXCEEDED")
    return canonical


def operation_policy(operation: str) -> tuple[str, str, bool]:
    try:
        return _OPERATION_POLICY[operation]
    except KeyError as exc:
        raise ComputerUseError("UNKNOWN_COMPUTER_OPERATION") from exc


@dataclass(frozen=True)
class ComputerActionRequest:
    session_id: str
    action_id: str
    task_id: str
    plan_fingerprint: str
    node_id: str
    operation: str
    effect: str
    resource_kind: str
    resource_ref: str
    arguments: Mapping[str, Any]
    state_precondition_sha256: str
    idempotency_key: str
    risk_class: str
    requires_writer: bool
    provider_ref: str | None = None
    expected_postcondition: str | None = None
    schema_version: str = COMPUTER_ACTION_REQUEST_SCHEMA

    def validate(self) -> "ComputerActionRequest":
        if self.schema_version != COMPUTER_ACTION_REQUEST_SCHEMA:
            raise ComputerUseError("COMPUTER_ACTION_SCHEMA_VERSION_MISMATCH")
        _reference(self.session_id, "session_id")
        _reference(self.action_id, "action_id")
        _reference(self.task_id, "task_id")
        _sha256(self.plan_fingerprint, "plan_fingerprint")
        _reference(self.node_id, "node_id")
        expected_effect, expected_risk, expected_writer = operation_policy(self.operation)
        if self.effect != expected_effect:
            raise ComputerUseError("COMPUTER_ACTION_EFFECT_MISMATCH")
        if self.risk_class not in RISK_CLASSES or self.risk_class != expected_risk:
            raise ComputerUseError("COMPUTER_ACTION_RISK_MISMATCH")
        if not isinstance(self.requires_writer, bool) or self.requires_writer != expected_writer:
            raise ComputerUseError("COMPUTER_ACTION_WRITER_REQUIREMENT_MISMATCH")
        _reference(self.resource_kind, "resource_kind")
        _reference(self.resource_ref, "resource_ref")
        _bounded_mapping(self.arguments, limit=MAX_ARGUMENT_BYTES, error_prefix="COMPUTER_ACTION_ARGUMENTS")
        _sha256(self.state_precondition_sha256, "state_precondition_sha256")
        _sha256(self.idempotency_key, "idempotency_key")
        _provider_ref(self.provider_ref)
        if self.expected_postcondition is not None:
            text = self.expected_postcondition
            if (
                not isinstance(text, str)
                or text != text.strip()
                or not text
                or len(text) > 512
                or "\n" in text
                or "\r" in text
            ):
                raise ComputerUseError("INVALID_EXPECTED_POSTCONDITION")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "action_id": self.action_id,
            "task_id": self.task_id,
            "plan_fingerprint": self.plan_fingerprint,
            "node_id": self.node_id,
            "provider_ref": self.provider_ref,
            "operation": self.operation,
            "effect": self.effect,
            "resource_kind": self.resource_kind,
            "resource_ref": self.resource_ref,
            "arguments": dict(self.arguments),
            "state_precondition_sha256": self.state_precondition_sha256,
            "expected_postcondition": self.expected_postcondition,
            "risk_class": self.risk_class,
            "requires_writer": self.requires_writer,
            "idempotency_key": self.idempotency_key,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())


@dataclass(frozen=True)
class ComputerObservation:
    session_id: str
    task_id: str
    state_id: str
    state_sha256: str
    surface: str
    active_target_ref: str
    captured_at: str
    structured_observation: Mapping[str, Any]
    screenshot_sha256: str | None = None
    schema_version: str = COMPUTER_OBSERVATION_SCHEMA

    def validate(self) -> "ComputerObservation":
        if self.schema_version != COMPUTER_OBSERVATION_SCHEMA:
            raise ComputerUseError("COMPUTER_OBSERVATION_SCHEMA_VERSION_MISMATCH")
        _reference(self.session_id, "session_id")
        _reference(self.task_id, "task_id")
        _reference(self.state_id, "state_id")
        _sha256(self.state_sha256, "state_sha256")
        if self.surface not in _SURFACES:
            raise ComputerUseError("UNKNOWN_COMPUTER_SURFACE")
        _reference(self.active_target_ref, "active_target_ref")
        _timestamp(self.captured_at, "captured_at")
        _bounded_mapping(
            self.structured_observation,
            limit=MAX_OBSERVATION_BYTES,
            error_prefix="COMPUTER_STRUCTURED_OBSERVATION",
        )
        if self.screenshot_sha256 is not None:
            _sha256(self.screenshot_sha256, "screenshot_sha256")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "task_id": self.task_id,
            "state_id": self.state_id,
            "state_sha256": self.state_sha256,
            "surface": self.surface,
            "active_target_ref": self.active_target_ref,
            "captured_at": self.captured_at,
            "structured_observation": dict(self.structured_observation),
            "screenshot_sha256": self.screenshot_sha256,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())


@dataclass(frozen=True)
class ComputerRouteDecision:
    route: str
    reason_code: str
    schema_version: str = COMPUTER_ROUTE_DECISION_SCHEMA

    def validate(self) -> "ComputerRouteDecision":
        if self.schema_version != COMPUTER_ROUTE_DECISION_SCHEMA:
            raise ComputerUseError("COMPUTER_ROUTE_SCHEMA_VERSION_MISMATCH")
        if self.route not in EXECUTION_ROUTES:
            raise ComputerUseError("UNKNOWN_COMPUTER_EXECUTION_ROUTE")
        _reference(self.reason_code, "reason_code")
        return self

    def canonical_dict(self) -> dict[str, str]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "route": self.route,
            "reason_code": self.reason_code,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())


def select_execution_route(
    *,
    available_routes: tuple[str, ...],
    authorized_routes: tuple[str, ...] | None = None,
    provider_preference: str | None = None,
) -> ComputerRouteDecision:
    """Choose the safest sufficient route; provider preference never broadens authority."""

    if not isinstance(available_routes, tuple) or not available_routes:
        raise ComputerUseError("COMPUTER_AVAILABLE_ROUTES_REQUIRED")
    unknown_available = set(available_routes) - set(EXECUTION_ROUTES)
    if unknown_available:
        raise ComputerUseError("UNKNOWN_COMPUTER_EXECUTION_ROUTE")

    if authorized_routes is None:
        authorized = set(available_routes)
    else:
        if not isinstance(authorized_routes, tuple):
            raise ComputerUseError("COMPUTER_AUTHORIZED_ROUTES_MUST_BE_TUPLE")
        unknown_authorized = set(authorized_routes) - set(EXECUTION_ROUTES)
        if unknown_authorized:
            raise ComputerUseError("UNKNOWN_COMPUTER_EXECUTION_ROUTE")
        authorized = set(authorized_routes)

    if provider_preference is not None and provider_preference not in EXECUTION_ROUTES:
        raise ComputerUseError("UNKNOWN_PROVIDER_ROUTE_PREFERENCE")

    candidates = set(available_routes) & authorized
    for route in EXECUTION_ROUTES:
        if route in candidates:
            reason = "SAFEST_AUTHORIZED_ROUTE_SELECTED"
            if provider_preference is not None and provider_preference == route:
                reason = "SAFEST_AUTHORIZED_ROUTE_MATCHES_PROVIDER_PREFERENCE"
            return ComputerRouteDecision(route=route, reason_code=reason).validate()

    raise ComputerUseError("NO_AUTHORIZED_COMPUTER_EXECUTION_ROUTE")


def require_fresh_observation(
    action: ComputerActionRequest,
    observation: ComputerObservation,
) -> None:
    """Reject actions created from a different task/session or stale observed state."""

    action.validate()
    observation.validate()
    if action.session_id != observation.session_id:
        raise ComputerUseError("COMPUTER_ACTION_SESSION_STALE")
    if action.task_id != observation.task_id:
        raise ComputerUseError("COMPUTER_ACTION_TASK_MISMATCH")
    if action.state_precondition_sha256 != observation.state_sha256:
        raise ComputerUseError("COMPUTER_ACTION_STATE_STALE")


def derive_action_policy(operation: str) -> dict[str, Any]:
    """Return deterministic metadata used by later WorkSpace authority integration."""

    effect, risk_class, requires_writer = operation_policy(operation)
    return {
        "effect": effect,
        "risk_class": risk_class,
        "requires_writer": requires_writer,
    }
