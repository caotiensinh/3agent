from __future__ import annotations

from dataclasses import dataclass
from typing import Any

CAPABILITY_AUTHORITY_SCHEMA = "workspace-chat-capability-authority/v1"


@dataclass(frozen=True)
class WebChatCapabilityContract:
    feature: str
    transport: str
    endpoint: str
    authority: str


# These are the only feature flags that currently have a complete web-chat
# interaction path in the production frontend and authenticated HTTP runtime.
WEB_CHAT_EXECUTABLE_CAPABILITIES: dict[str, WebChatCapabilityContract] = {
    "upload": WebChatCapabilityContract(
        feature="upload",
        transport="POST",
        endpoint="/api/upload",
        authority="authenticated_local_upload",
    ),
    "library": WebChatCapabilityContract(
        feature="library",
        transport="GET",
        endpoint="/api/uploads",
        authority="authenticated_owner_scoped_read",
    ),
    "deep_research": WebChatCapabilityContract(
        feature="deep_research",
        transport="POST",
        endpoint="/api/chat",
        authority="policy_bounded_research_mode",
    ),
    "web_search": WebChatCapabilityContract(
        feature="web_search",
        transport="POST",
        endpoint="/api/chat",
        authority="policy_authorized_public_research_only",
    ),
}

# These controls may be visible for discovery/status, but must remain disabled
# until a separately reviewed handler/runtime and authority contract is added.
WEB_CHAT_DISCOVERY_ONLY_CAPABILITIES = frozenset(
    {
        "image_generation",
        "voice_input",
        "github",
        "figma",
        "canva",
        "gmail",
    }
)


def capability_authority_metadata() -> dict[str, Any]:
    return {
        "schema_version": CAPABILITY_AUTHORITY_SCHEMA,
        "executable": {
            name: {
                "transport": contract.transport,
                "endpoint": contract.endpoint,
                "authority": contract.authority,
            }
            for name, contract in sorted(WEB_CHAT_EXECUTABLE_CAPABILITIES.items())
        },
        "discovery_only": sorted(WEB_CHAT_DISCOVERY_ONLY_CAPABILITIES),
    }


def enforce_web_chat_capability_authority(payload: dict[str, Any]) -> dict[str, Any]:
    """Fail closed when UI capability metadata exceeds bound web-chat authority.

    The function intentionally mutates the supplied capability payload because the
    gateway builds a fresh response object per request. A future capability is not
    allowed to become enabled merely because UI/config metadata was changed; its
    executable handler must first be added to the authoritative contract above.
    """

    features = payload.setdefault("features", {})
    if not isinstance(features, dict):
        raise ValueError("workspace chat capabilities.features must be an object")

    for name, raw in features.items():
        if not isinstance(raw, dict):
            raise ValueError(f"workspace chat capability {name!r} must be an object")
        if bool(raw.get("enabled")) and name not in WEB_CHAT_EXECUTABLE_CAPABILITIES:
            raw["enabled"] = False
            raw["state_label"] = "Unavailable"
            raw["reason"] = (
                "WorkSpace web chat has no reviewed executable handler and authority "
                f"contract for capability '{name}'."
            )

    payload["authority_contract"] = capability_authority_metadata()
    return payload
