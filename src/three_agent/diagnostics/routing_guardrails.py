from __future__ import annotations

from ..micro_tool_registry import RejectedCandidate, ToolSelectionResult
from .complaint_intake import normalize_text

_REMOTE_CAMERA_MARKERS = (
    "rtsp",
    "onvif",
    "nvr",
    "vms",
    "poe",
    "camera offline",
    "camera mat",
    "camera khong xem duoc",
    "カメラ オフライン",
    "監視カメラ",
)
_LOCAL_CAMERA_MARKERS = (
    "teams",
    "zoom",
    "webcam",
    "camera device",
    "camera khong nhan",
    "webカメラ",
    "カメラ 認識",
)
_VPN_AUTH_MARKERS = (
    "login fail",
    "login failed",
    "cannot login",
    "password",
    "mat khau",
    "doi mat khau",
    "mfa",
    "otp",
    "authentication",
    "dang nhap",
    "ログイン",
    "パスワード",
)
_VPN_ROUTE_MARKERS = (
    "vpn vao duoc nhung",
    "vpn da vao duoc nhung",
    "vpn ket noi duoc nhung",
    "vpn connected but",
    "connected to vpn but",
    "server noi bo",
    "internal resource",
    "internal server",
    "vpn route",
    "vpn接続できるが",
    "vpn接続済みだが",
)


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(normalize_text(marker) in text for marker in markers)


def apply_cross_domain_guardrails(
    raw_query: str,
    result: ToolSelectionResult,
) -> ToolSelectionResult:
    """Fail closed when a keyword match crosses an obvious subsystem boundary.

    The selector remains evidence-oriented. These guardrails only suppress a selected
    tool when the user's wording clearly places the incident in another subsystem;
    they never add authority, execute a tool, or assert a root cause.
    """

    text = normalize_text(raw_query)
    suppressions: dict[str, str] = {}

    if _contains_any(text, _REMOTE_CAMERA_MARKERS) and not _contains_any(text, _LOCAL_CAMERA_MARKERS):
        suppressions["camera.devices.snapshot"] = "CROSS_DOMAIN_REMOTE_CAMERA"

    if (
        "vpn" in text
        and _contains_any(text, _VPN_AUTH_MARKERS)
        and not _contains_any(text, _VPN_ROUTE_MARKERS)
    ):
        suppressions["network.route.snapshot"] = "CROSS_DOMAIN_VPN_AUTH"

    if not suppressions:
        return result

    selected = tuple(item for item in result.selected if item.id not in suppressions)
    rejected = list(result.rejected)
    already_rejected = {(item.tool_id, item.reason_code) for item in rejected}
    for item in result.selected:
        reason = suppressions.get(item.id)
        if reason is None or (item.id, reason) in already_rejected:
            continue
        rejected.append(RejectedCandidate(item.id, reason))
    rejected.sort(key=lambda item: (item.tool_id, item.reason_code))
    return ToolSelectionResult(
        selected=selected,
        rejected=tuple(rejected),
        mode=result.mode,
        schema_version=result.schema_version,
    )


__all__ = ["apply_cross_domain_guardrails"]
