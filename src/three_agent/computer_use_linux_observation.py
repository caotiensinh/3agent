from __future__ import annotations

import hashlib
import io
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol

from .computer_use import ComputerObservation
from .computer_use_privacy import ComputerPrivacyError, sanitize_computer_content

MAX_LINUX_METADATA_BYTES = 8 * 1024
MAX_LINUX_ACCESSIBILITY_BYTES = 32 * 1024
MAX_LINUX_SCREENSHOT_BYTES = 8 * 1024 * 1024
MAX_LINUX_ATSPI_NODES = 256
MAX_LINUX_ATSPI_DEPTH = 8
_SCREENSHOT_POLICIES = frozenset({"deny", "on_demand"})
_TARGET_ID_RE = re.compile(r"^atspi-[0-9a-f]{32}$")


class LinuxObservationError(ValueError):
    """Read-only Linux observation violated platform, privacy, or size rules."""


@dataclass(frozen=True)
class LinuxObservationConfig:
    screenshot_policy: str = "deny"
    max_atspi_nodes: int = MAX_LINUX_ATSPI_NODES
    max_atspi_depth: int = MAX_LINUX_ATSPI_DEPTH

    def validate(self) -> "LinuxObservationConfig":
        if self.screenshot_policy not in _SCREENSHOT_POLICIES:
            raise LinuxObservationError("INVALID_LINUX_SCREENSHOT_POLICY")
        if not isinstance(self.max_atspi_nodes, int) or not (
            1 <= self.max_atspi_nodes <= MAX_LINUX_ATSPI_NODES
        ):
            raise LinuxObservationError("INVALID_LINUX_ATSPI_NODE_LIMIT")
        if not isinstance(self.max_atspi_depth, int) or not (
            0 <= self.max_atspi_depth <= MAX_LINUX_ATSPI_DEPTH
        ):
            raise LinuxObservationError("INVALID_LINUX_ATSPI_DEPTH_LIMIT")
        return self


@dataclass(frozen=True)
class LinuxReadOnlyCapture:
    target_id: str
    process_id: int
    application_name: str
    metadata: Mapping[str, Any]
    accessibility_snapshot: Mapping[str, Any]
    captured_at: str


class LinuxReadOnlyBackend(Protocol):
    """Semantic Linux acquisition contract; never exposes input or mutation."""

    def capture_read_only(
        self,
        *,
        max_atspi_nodes: int,
        max_atspi_depth: int,
    ) -> LinuxReadOnlyCapture:
        ...


class LinuxScreenshotFallbackBackend(Protocol):
    """Isolated pixel fallback used only by explicit screenshot observation."""

    def capture_screenshot(self) -> bytes:
        ...


def _canonical_bytes(value: Mapping[str, Any], *, limit: int, error_code: str) -> bytes:
    if not isinstance(value, Mapping):
        raise LinuxObservationError(f"{error_code}_MUST_BE_OBJECT")
    try:
        payload = json.dumps(
            dict(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LinuxObservationError(f"{error_code}_NOT_CANONICAL_JSON") from exc
    if len(payload) > limit:
        raise LinuxObservationError(f"{error_code}_BOUND_EXCEEDED")
    return payload


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _sanitize_mapping(value: Mapping[str, Any], *, error_code: str) -> Mapping[str, Any]:
    try:
        sanitized = sanitize_computer_content(value)
    except ComputerPrivacyError as exc:
        raise LinuxObservationError(error_code) from exc
    if not isinstance(sanitized, Mapping):
        raise LinuxObservationError(error_code)
    return sanitized


def _bounded_application_name(value: Any) -> str:
    if not isinstance(value, str):
        raise LinuxObservationError("INVALID_LINUX_APPLICATION_NAME")
    text = value.strip()
    if not text or len(text.encode("utf-8")) > 512 or "\x00" in text:
        raise LinuxObservationError("INVALID_LINUX_APPLICATION_NAME")
    return text


def _count_nodes(value: Any) -> int:
    if not isinstance(value, Mapping):
        return 0
    total = 1
    children = value.get("children")
    if isinstance(children, list):
        total += sum(_count_nodes(child) for child in children)
    return total


def capture_linux_observation(
    *,
    config: LinuxObservationConfig,
    backend: LinuxReadOnlyBackend,
    session_id: str,
    task_id: str,
    include_screenshot: bool = False,
    screenshot_backend: LinuxScreenshotFallbackBackend | None = None,
) -> ComputerObservation:
    """Capture one bounded Linux observation with semantic AT-SPI first.

    Screenshot acquisition is deliberately separated from the semantic backend.
    Pixel data is permitted only by explicit on-demand policy and only its digest
    crosses into the canonical ComputerObservation.
    """

    config.validate()
    if include_screenshot and config.screenshot_policy != "on_demand":
        raise LinuxObservationError("LINUX_SCREENSHOT_POLICY_DENIED")
    if include_screenshot and screenshot_backend is None:
        raise LinuxObservationError("LINUX_SCREENSHOT_BACKEND_REQUIRED")
    if not include_screenshot and screenshot_backend is not None:
        raise LinuxObservationError("LINUX_UNREQUESTED_SCREENSHOT_BACKEND")

    capture = backend.capture_read_only(
        max_atspi_nodes=config.max_atspi_nodes,
        max_atspi_depth=config.max_atspi_depth,
    )
    if not isinstance(capture, LinuxReadOnlyCapture):
        raise LinuxObservationError("INVALID_LINUX_BACKEND_CAPTURE")
    if not isinstance(capture.target_id, str) or not _TARGET_ID_RE.fullmatch(capture.target_id):
        raise LinuxObservationError("INVALID_LINUX_TARGET_ID")
    if isinstance(capture.process_id, bool) or not isinstance(capture.process_id, int) or capture.process_id <= 0:
        raise LinuxObservationError("INVALID_LINUX_PROCESS_ID")
    application_name = _bounded_application_name(capture.application_name)

    metadata = _sanitize_mapping(capture.metadata, error_code="LINUX_METADATA_PRIVACY_REJECTED")
    accessibility = _sanitize_mapping(
        capture.accessibility_snapshot,
        error_code="LINUX_ACCESSIBILITY_PRIVACY_REJECTED",
    )
    if _count_nodes(accessibility) > config.max_atspi_nodes:
        raise LinuxObservationError("LINUX_ATSPI_NODE_BOUND_EXCEEDED")

    metadata_bytes = _canonical_bytes(
        metadata,
        limit=MAX_LINUX_METADATA_BYTES,
        error_code="LINUX_METADATA",
    )
    accessibility_bytes = _canonical_bytes(
        accessibility,
        limit=MAX_LINUX_ACCESSIBILITY_BYTES,
        error_code="LINUX_ACCESSIBILITY_SNAPSHOT",
    )

    screenshot_sha256 = None
    if include_screenshot:
        assert screenshot_backend is not None
        screenshot = screenshot_backend.capture_screenshot()
        if not isinstance(screenshot, bytes) or not screenshot:
            raise LinuxObservationError("LINUX_SCREENSHOT_REQUIRED")
        if len(screenshot) > MAX_LINUX_SCREENSHOT_BYTES:
            raise LinuxObservationError("LINUX_SCREENSHOT_BOUND_EXCEEDED")
        screenshot_sha256 = _sha256_bytes(screenshot)

    target_ref = f"linux:atspi:{capture.target_id}/process:{capture.process_id}"
    structured = {
        "platform": "linux",
        "backend": "atspi2",
        "target_id": capture.target_id,
        "process_id": capture.process_id,
        "application_name": application_name,
        "metadata": json.loads(metadata_bytes.decode("utf-8")),
        "accessibility": json.loads(accessibility_bytes.decode("utf-8")),
    }
    state_payload = json.dumps(
        {
            "target_ref": target_ref,
            "structured": structured,
            "screenshot_sha256": screenshot_sha256,
        },
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
        surface="desktop",
        active_target_ref=target_ref,
        captured_at=capture.captured_at,
        structured_observation=structured,
        screenshot_sha256=screenshot_sha256,
    ).validate()


def _load_atspi() -> Any:
    try:
        import gi

        gi.require_version("Atspi", "2.0")
        from gi.repository import Atspi
    except (ImportError, ValueError) as exc:
        raise LinuxObservationError("LINUX_ATSPI2_UNAVAILABLE") from exc
    try:
        Atspi.init()
    except Exception as exc:
        raise LinuxObservationError("LINUX_ATSPI2_INIT_FAILED") from exc
    return Atspi


def _state_contains(atspi: Any, node: Any, state_name: str) -> bool:
    state_type = getattr(getattr(atspi, "StateType", object()), state_name, None)
    if state_type is None:
        return False
    try:
        states = node.get_state_set()
        return bool(states is not None and states.contains(state_type))
    except Exception:
        return False


def _accessible_identity(node: Any) -> str:
    try:
        raw = node.get_accessible_id()
    except Exception:
        raw = None
    if not isinstance(raw, str) or not raw:
        parts: list[str] = []
        current = node
        for _ in range(32):
            try:
                index = int(current.get_index_in_parent())
                parent = current.get_parent()
            except Exception:
                break
            parts.append(str(index))
            if parent is None:
                break
            current = parent
        raw = "path:" + "/".join(reversed(parts))
    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:32]
    return "atspi-" + digest


def _safe_call_text(node: Any, method: str, *, limit: int = 512) -> str:
    try:
        value = getattr(node, method)()
    except Exception:
        return ""
    if value is None:
        return ""
    text = str(value).replace("\x00", "").strip()
    return text[:limit]


def _safe_interfaces(node: Any) -> list[str]:
    try:
        interfaces = node.get_interfaces()
    except Exception:
        return []
    allowed = {"Action", "Component", "EditableText", "Selection", "Text", "Value"}
    result = sorted({str(item) for item in interfaces or [] if str(item) in allowed})
    return result[:16]


def _is_secure_accessible(atspi: Any, node: Any, role_name: str) -> bool:
    normalized = role_name.lower().replace("_", " ").replace("-", " ")
    if "password" in normalized:
        return True
    return _state_contains(atspi, node, "PROTECTED")


def _snapshot_node(
    atspi: Any,
    node: Any,
    *,
    depth: int,
    max_depth: int,
    remaining: list[int],
) -> Mapping[str, Any] | None:
    if node is None or depth > max_depth or remaining[0] <= 0:
        return None
    remaining[0] -= 1
    role_name = _safe_call_text(node, "get_role_name", limit=128) or "unknown"
    secure = _is_secure_accessible(atspi, node, role_name)
    name = _safe_call_text(node, "get_name")
    if secure and name:
        name = "[REDACTED_SECURE_UI]"
    result: dict[str, Any] = {
        "accessible_id": _accessible_identity(node),
        "role": role_name,
        "name": name,
        "interfaces": _safe_interfaces(node),
        "is_enabled": _state_contains(atspi, node, "ENABLED"),
        "is_focused": _state_contains(atspi, node, "FOCUSED"),
        "is_showing": _state_contains(atspi, node, "SHOWING"),
        "is_visible": _state_contains(atspi, node, "VISIBLE"),
        "is_secure": secure,
        "children": [],
    }
    if secure:
        result["secure_content_redacted"] = True
    if depth < max_depth and remaining[0] > 0:
        try:
            child_count = max(0, int(node.get_child_count()))
        except Exception:
            child_count = 0
        for index in range(child_count):
            if remaining[0] <= 0:
                break
            try:
                child = node.get_child_at_index(index)
            except Exception:
                continue
            converted = _snapshot_node(
                atspi,
                child,
                depth=depth + 1,
                max_depth=max_depth,
                remaining=remaining,
            )
            if converted is not None:
                result["children"].append(converted)
    return result


def _find_active_window(atspi: Any, desktop: Any) -> Any:
    try:
        application_count = max(0, int(desktop.get_child_count()))
    except Exception as exc:
        raise LinuxObservationError("LINUX_ATSPI_DESKTOP_UNREADABLE") from exc
    focused_fallback = None
    for app_index in range(application_count):
        try:
            application = desktop.get_child_at_index(app_index)
            window_count = max(0, int(application.get_child_count()))
        except Exception:
            continue
        for window_index in range(window_count):
            try:
                window = application.get_child_at_index(window_index)
            except Exception:
                continue
            if _state_contains(atspi, window, "ACTIVE"):
                return window
            if focused_fallback is None and _state_contains(atspi, window, "FOCUSED"):
                focused_fallback = window
    if focused_fallback is not None:
        return focused_fallback
    raise LinuxObservationError("LINUX_ATSPI_ACTIVE_WINDOW_NOT_FOUND")


class LinuxAtspiObservationBackend:
    """Direct AT-SPI2 semantic observation backend.

    The implementation imports GObject introspection lazily and calls AT-SPI2
    directly. It never generates or executes shell commands and never exposes
    a mutation primitive.
    """

    def capture_read_only(
        self,
        *,
        max_atspi_nodes: int,
        max_atspi_depth: int,
    ) -> LinuxReadOnlyCapture:
        if not sys.platform.startswith("linux"):
            raise LinuxObservationError("LINUX_ATSPI_BACKEND_REQUIRES_LINUX")
        config = LinuxObservationConfig(
            max_atspi_nodes=max_atspi_nodes,
            max_atspi_depth=max_atspi_depth,
        ).validate()
        atspi = _load_atspi()
        try:
            desktop = atspi.get_desktop(0)
        except Exception as exc:
            raise LinuxObservationError("LINUX_ATSPI_DESKTOP_UNAVAILABLE") from exc
        if desktop is None:
            raise LinuxObservationError("LINUX_ATSPI_DESKTOP_UNAVAILABLE")
        window = _find_active_window(atspi, desktop)
        try:
            process_id = int(window.get_process_id())
        except Exception as exc:
            raise LinuxObservationError("LINUX_ATSPI_PROCESS_ID_UNAVAILABLE") from exc
        if process_id <= 0:
            raise LinuxObservationError("LINUX_ATSPI_PROCESS_ID_UNAVAILABLE")
        try:
            application = window.get_application()
        except Exception:
            application = None
        application_name = _safe_call_text(application or window, "get_name") or "unknown-application"
        remaining = [config.max_atspi_nodes]
        snapshot = _snapshot_node(
            atspi,
            window,
            depth=0,
            max_depth=config.max_atspi_depth,
            remaining=remaining,
        )
        if not isinstance(snapshot, Mapping):
            raise LinuxObservationError("LINUX_ATSPI_SNAPSHOT_EMPTY")
        return LinuxReadOnlyCapture(
            target_id=_accessible_identity(window),
            process_id=process_id,
            application_name=application_name,
            metadata={
                "window_role": _safe_call_text(window, "get_role_name", limit=128),
                "window_name": _safe_call_text(window, "get_name"),
                "atspi_node_count": config.max_atspi_nodes - remaining[0],
                "atspi_version": _atspi_version(atspi),
            },
            accessibility_snapshot=snapshot,
            captured_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )


def _atspi_version(atspi: Any) -> str:
    try:
        version = atspi.get_version()
    except Exception:
        return "unknown"
    if isinstance(version, tuple):
        return ".".join(str(part) for part in version)
    return str(version)


class PillowLinuxScreenshotFallback:
    """Explicit, isolated screenshot fallback with no input or shell surface."""

    def capture_screenshot(self) -> bytes:
        if not sys.platform.startswith("linux"):
            raise LinuxObservationError("LINUX_SCREENSHOT_BACKEND_REQUIRES_LINUX")
        try:
            from PIL import ImageGrab

            image = ImageGrab.grab()
            output = io.BytesIO()
            image.save(output, format="PNG")
            payload = output.getvalue()
        except Exception as exc:
            raise LinuxObservationError("LINUX_SCREENSHOT_CAPTURE_FAILED") from exc
        if not payload:
            raise LinuxObservationError("LINUX_SCREENSHOT_REQUIRED")
        return payload
