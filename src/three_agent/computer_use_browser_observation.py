from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Protocol
from urllib.parse import urlparse

from .computer_use import ComputerObservation
from .computer_use_privacy import ComputerPrivacyError, sanitize_computer_content

MAX_BROWSER_DOM_BYTES = 24 * 1024
MAX_BROWSER_ACCESSIBILITY_BYTES = 24 * 1024
MAX_BROWSER_METADATA_BYTES = 8 * 1024
MAX_BROWSER_SCREENSHOT_BYTES = 8 * 1024 * 1024
_PROFILE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TARGET_PART_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SCREENSHOT_POLICIES = frozenset({"deny", "on_demand"})


class BrowserObservationError(ValueError):
    """Read-only browser observation violated isolation, locality, privacy, or size rules."""


@dataclass(frozen=True)
class BrowserObservationConfig:
    profile_id: str
    control_endpoint: str
    profile_mode: str = "isolated"
    storage_identity: str = "public_browser"
    accessible_storage_classes: tuple[str, ...] = ("public_browser",)
    screenshot_policy: str = "deny"

    def validate(self) -> "BrowserObservationConfig":
        if not _PROFILE_ID_RE.fullmatch(self.profile_id):
            raise BrowserObservationError("INVALID_BROWSER_PROFILE_ID")
        if self.profile_mode != "isolated":
            raise BrowserObservationError("BROWSER_PERSONAL_PROFILE_ATTACH_FORBIDDEN")
        if self.storage_identity != "public_browser":
            raise BrowserObservationError("BROWSER_PROFILE_IDENTITY_NOT_ISOLATED")
        if self.accessible_storage_classes != ("public_browser",):
            raise BrowserObservationError("BROWSER_CONFIDENTIAL_STORAGE_ACCESS_FORBIDDEN")
        if self.screenshot_policy not in _SCREENSHOT_POLICIES:
            raise BrowserObservationError("INVALID_BROWSER_SCREENSHOT_POLICY")
        _require_private_control_endpoint(self.control_endpoint)
        return self


@dataclass(frozen=True)
class BrowserReadOnlyCapture:
    profile_id: str
    window_id: str
    tab_id: str
    metadata: Mapping[str, Any]
    dom_snapshot: Mapping[str, Any]
    accessibility_snapshot: Mapping[str, Any]
    captured_at: str
    screenshot_bytes: bytes | None = None


class BrowserReadOnlyBackend(Protocol):
    """Backend contract for isolated read-only browser state acquisition only."""

    def capture_read_only(
        self,
        *,
        profile_id: str,
        include_screenshot: bool,
    ) -> BrowserReadOnlyCapture:
        ...


def _canonical_bytes(value: Mapping[str, Any], *, limit: int, error_code: str) -> bytes:
    if not isinstance(value, Mapping):
        raise BrowserObservationError(f"{error_code}_MUST_BE_OBJECT")
    try:
        payload = json.dumps(
            dict(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BrowserObservationError(f"{error_code}_NOT_CANONICAL_JSON") from exc
    if len(payload) > limit:
        raise BrowserObservationError(f"{error_code}_BOUND_EXCEEDED")
    return payload


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _require_private_control_endpoint(endpoint: str) -> None:
    if not isinstance(endpoint, str) or endpoint != endpoint.strip() or not endpoint:
        raise BrowserObservationError("INVALID_BROWSER_CONTROL_ENDPOINT")
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise BrowserObservationError("INVALID_BROWSER_CONTROL_ENDPOINT")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise BrowserObservationError("INVALID_BROWSER_CONTROL_ENDPOINT")
    host = parsed.hostname
    if host == "localhost":
        return
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise BrowserObservationError("BROWSER_CONTROL_ENDPOINT_NOT_LOCAL_OR_PRIVATE") from exc
    if not (address.is_loopback or address.is_private) or address.is_unspecified or address.is_multicast:
        raise BrowserObservationError("BROWSER_CONTROL_ENDPOINT_NOT_LOCAL_OR_PRIVATE")


def _target_part(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not _TARGET_PART_RE.fullmatch(value):
        raise BrowserObservationError(f"INVALID_BROWSER_{field_name.upper()}")
    return value


def _sanitize_mapping(value: Mapping[str, Any], *, error_code: str) -> Mapping[str, Any]:
    try:
        sanitized = sanitize_computer_content(value)
    except ComputerPrivacyError as exc:
        raise BrowserObservationError(error_code) from exc
    if not isinstance(sanitized, Mapping):
        raise BrowserObservationError(error_code)
    return sanitized


def capture_isolated_browser_observation(
    *,
    config: BrowserObservationConfig,
    backend: BrowserReadOnlyBackend,
    session_id: str,
    task_id: str,
    include_screenshot: bool = False,
) -> ComputerObservation:
    """Capture one bounded and privacy-sanitized isolated browser observation.

    Screenshot capture is explicit and denied unless trusted configuration permits
    on-demand evidence. No navigation, click, typing, download, or arbitrary CDP
    command surface is exposed here.
    """

    config.validate()
    if include_screenshot and config.screenshot_policy != "on_demand":
        raise BrowserObservationError("BROWSER_SCREENSHOT_POLICY_DENIED")
    capture = backend.capture_read_only(
        profile_id=config.profile_id,
        include_screenshot=include_screenshot,
    )
    if not isinstance(capture, BrowserReadOnlyCapture):
        raise BrowserObservationError("INVALID_BROWSER_BACKEND_CAPTURE")
    if capture.profile_id != config.profile_id:
        raise BrowserObservationError("BROWSER_BACKEND_PROFILE_ATTESTATION_MISMATCH")

    window_id = _target_part(capture.window_id, "window_id")
    tab_id = _target_part(capture.tab_id, "tab_id")
    metadata_bytes = _canonical_bytes(
        _sanitize_mapping(capture.metadata, error_code="BROWSER_METADATA_PRIVACY_REJECTED"),
        limit=MAX_BROWSER_METADATA_BYTES,
        error_code="BROWSER_METADATA",
    )
    dom_bytes = _canonical_bytes(
        _sanitize_mapping(capture.dom_snapshot, error_code="BROWSER_DOM_PRIVACY_REJECTED"),
        limit=MAX_BROWSER_DOM_BYTES,
        error_code="BROWSER_DOM_SNAPSHOT",
    )
    accessibility_bytes = _canonical_bytes(
        _sanitize_mapping(capture.accessibility_snapshot, error_code="BROWSER_ACCESSIBILITY_PRIVACY_REJECTED"),
        limit=MAX_BROWSER_ACCESSIBILITY_BYTES,
        error_code="BROWSER_ACCESSIBILITY_SNAPSHOT",
    )

    screenshot_sha256 = None
    if include_screenshot:
        if not isinstance(capture.screenshot_bytes, bytes):
            raise BrowserObservationError("BROWSER_SCREENSHOT_REQUIRED")
        if len(capture.screenshot_bytes) > MAX_BROWSER_SCREENSHOT_BYTES:
            raise BrowserObservationError("BROWSER_SCREENSHOT_BOUND_EXCEEDED")
        screenshot_sha256 = _sha256_bytes(capture.screenshot_bytes)
    elif capture.screenshot_bytes is not None:
        raise BrowserObservationError("BROWSER_UNREQUESTED_SCREENSHOT_RETURNED")

    target_ref = f"browser:profile:{config.profile_id}/tab:{tab_id}"
    structured = {
        "profile_id": config.profile_id,
        "profile_mode": config.profile_mode,
        "storage_identity": config.storage_identity,
        "window_id": window_id,
        "tab_id": tab_id,
        "metadata": json.loads(metadata_bytes.decode("utf-8")),
        "dom": json.loads(dom_bytes.decode("utf-8")),
        "accessibility": json.loads(accessibility_bytes.decode("utf-8")),
    }
    state_payload = json.dumps(
        {"target_ref": target_ref, "structured": structured, "screenshot_sha256": screenshot_sha256},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    state_sha256 = _sha256_bytes(state_payload)
    return ComputerObservation(
        session_id=session_id,
        task_id=task_id,
        state_id="state:" + state_sha256.removeprefix("sha256:"),
        state_sha256=state_sha256,
        surface="browser",
        active_target_ref=target_ref,
        captured_at=capture.captured_at,
        structured_observation=structured,
        screenshot_sha256=screenshot_sha256,
    ).validate()
