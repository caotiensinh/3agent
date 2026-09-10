from types import SimpleNamespace

from three_agent import chat_gateway
from three_agent.chat_gateway import workspace_ui_capabilities
from three_agent.workspace_chat_capabilities import (
    WEB_CHAT_DISCOVERY_ONLY_CAPABILITIES,
    WEB_CHAT_EXECUTABLE_CAPABILITIES,
    enforce_web_chat_capability_authority,
)
from three_agent.workspace_frontend import WORKSPACE_HTML


def _config():
    return SimpleNamespace(
        internet_gateway=SimpleNamespace(enabled=True, public_search_enabled=True),
        confidentiality_mode="public",
        raw={"github": {"enabled": True}},
        product_name="WorkSpace",
        environment="test",
    )


def test_production_capabilities_enable_only_reviewed_executable_handlers():
    payload = workspace_ui_capabilities(_config())
    enabled = {
        name for name, feature in payload["features"].items() if feature["enabled"]
    }

    assert enabled == set(WEB_CHAT_EXECUTABLE_CAPABILITIES)
    assert payload["features"]["web_search"]["enabled"] is True
    for feature in WEB_CHAT_DISCOVERY_ONLY_CAPABILITIES:
        assert payload["features"][feature]["enabled"] is False

    authority = payload["authority_contract"]
    assert authority["schema_version"] == "workspace-chat-capability-authority/v1"
    assert authority["executable"]["upload"]["endpoint"] == "/api/upload"
    assert authority["executable"]["library"]["endpoint"] == "/api/uploads"
    assert authority["executable"]["deep_research"]["endpoint"] == "/api/chat"
    assert authority["executable"]["web_search"]["endpoint"] == "/api/chat"


def test_rogue_enabled_capability_fails_closed_without_handler_contract():
    payload = {
        "features": {
            "future_connector": {
                "enabled": True,
                "state_label": "Ready",
                "reason": "misconfigured",
            }
        }
    }

    enforced = enforce_web_chat_capability_authority(payload)

    feature = enforced["features"]["future_connector"]
    assert feature["enabled"] is False
    assert feature["state_label"] == "Unavailable"
    assert "no reviewed executable handler" in feature["reason"]


def test_production_entrypoint_binds_authoritative_capability_filter():
    assert chat_gateway.workspace_ui_capabilities is workspace_ui_capabilities


def test_discovery_controls_remain_visible_but_non_executable_until_authorized():
    for feature in ("figma", "canva", "gmail", "github", "image_generation"):
        assert f'data-action="{feature}"' in WORKSPACE_HTML

    payload = workspace_ui_capabilities(_config())
    for feature in ("figma", "canva", "gmail", "github", "image_generation"):
        assert payload["features"][feature]["enabled"] is False


def test_voice_flag_cannot_be_enabled_without_bound_recorder_contract():
    payload = workspace_ui_capabilities(_config())
    assert payload["features"]["voice_input"]["enabled"] is False
    assert "voice_input" in WEB_CHAT_DISCOVERY_ONLY_CAPABILITIES
