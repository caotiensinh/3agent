import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent.chat_gateway_v4 import (
    HTML_V4,
    MAX_UPLOAD_REQUEST_BYTES,
    _recent_uploads,
    _request_purpose,
    _validate_owned_uploads,
    _validate_request_options,
    workspace_ui_capabilities,
)
from three_agent.knowledge_gateway import (
    MAX_UPLOAD_BYTES,
    MAX_UPLOADS_PER_TASK,
    UploadSecurityError,
)


def config(*, public_search: bool, mode: str) -> SimpleNamespace:
    return SimpleNamespace(
        product_name="WorkSpace",
        environment="public-research-zone" if mode == "public-research" else "secure-local",
        confidentiality_mode=mode,
        internet_gateway=SimpleNamespace(
            enabled=True,
            public_search_enabled=public_search,
        ),
        raw={"github": {"enabled": False, "push_mode": "operator_only"}},
    )


class StubGateway:
    def __init__(self, root: Path) -> None:
        self.root = root

    def validate_upload_ids(self, values):
        result = []
        for value in values:
            value = str(value)
            if not (self.root / value / "manifest.json").is_file():
                raise UploadSecurityError(f"Unknown upload_id: {value}")
            if value not in result:
                result.append(value)
        return result


def write_manifest(
    root: Path,
    upload_id: str,
    *,
    sender: str,
    name: str = "notes.txt",
    documents: int = 1,
    images: int = 0,
) -> None:
    folder = root / upload_id
    folder.mkdir(parents=True)
    (folder / "original.txt").write_text("safe", encoding="utf-8")
    payload = {
        "schema_version": 1,
        "upload_id": upload_id,
        "name": name,
        "size": 4,
        "sha256": "sha256:" + "a" * 64,
        "sender": sender,
        "documents": [
            {"name": f"doc-{index}.txt", "kind": "text", "text_file": "doc.txt", "chars": 4}
            for index in range(documents)
        ],
        "images": [
            {"name": f"image-{index}.png", "kind": "image", "width": 1, "height": 1}
            for index in range(images)
        ],
        "warnings": ["metadata-only warning"],
    }
    (folder / "manifest.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )


class ChatGatewayV4Tests(unittest.TestCase):
    def test_workspace_composer_and_real_endpoint_contract_are_present(self):
        for value in (
            'id="plusBtn"',
            'id="micBtn"',
            'id="sendBtn"',
            'placeholder="Ask WorkSpace"',
            'data-action="upload"',
            'data-action="library"',
            'data-action="web_search"',
            'data-action="deep_research"',
            'data-action="image_generation"',
            'data-action="github"',
            "/api/upload",
            "/api/uploads",
            "/api/capabilities",
            "/api/chat",
            "upload_ids",
            "mode:state.requestMode",
            "effort:document.getElementById('effort').value",
        ):
            self.assertIn(value, HTML_V4)
        self.assertNotIn("Ask 3Agent", HTML_V4)
        self.assertNotIn("SpeechRecognition", HTML_V4)
        self.assertNotIn("webkitSpeechRecognition", HTML_V4)
        self.assertIn(
            ".txt,.md,.markdown,.html,.htm,.zip,.png,.jpg,.jpeg,.webp",
            HTML_V4,
        )
        self.assertLess(MAX_UPLOAD_BYTES, MAX_UPLOAD_REQUEST_BYTES)
        self.assertEqual(MAX_UPLOADS_PER_TASK, 8)

    def test_capability_manifest_fails_closed_for_external_or_unconfigured_features(self):
        secure = workspace_ui_capabilities(
            config(public_search=False, mode="confidential")
        )
        self.assertEqual(secure["product_name"], "WorkSpace")
        self.assertTrue(secure["features"]["upload"]["enabled"])
        self.assertTrue(secure["features"]["library"]["enabled"])
        self.assertTrue(secure["features"]["deep_research"]["enabled"])
        self.assertFalse(secure["features"]["web_search"]["enabled"])
        self.assertFalse(secure["features"]["image_generation"]["enabled"])
        self.assertFalse(secure["features"]["voice_input"]["enabled"])
        self.assertFalse(secure["features"]["github"]["enabled"])

        public = workspace_ui_capabilities(
            config(public_search=True, mode="public-research")
        )
        self.assertTrue(public["features"]["web_search"]["enabled"])

    def test_request_mode_and_effort_are_real_server_side_controls(self):
        secure = config(public_search=False, mode="confidential")
        self.assertEqual(
            _validate_request_options("deep_research", "high", secure),
            ("deep_research", "high"),
        )
        with self.assertRaisesRegex(ValueError, "Web search is disabled"):
            _validate_request_options("web_search", "high", secure)
        with self.assertRaisesRegex(ValueError, "Unsupported WorkSpace request mode"):
            _validate_request_options("invented", "high", secure)
        with self.assertRaisesRegex(ValueError, "Unsupported WorkSpace effort"):
            _validate_request_options("chat", "unbounded", secure)

        public = config(public_search=True, mode="public-research")
        self.assertEqual(
            _validate_request_options("web_search", "standard", public),
            ("web_search", "standard"),
        )
        self.assertNotEqual(
            _request_purpose("chat", "standard"),
            _request_purpose("deep_research", "high"),
        )
        self.assertIn("deterministic budgets", _request_purpose("deep_research", "high"))

    def test_library_is_metadata_only_and_scoped_to_same_lan_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            own_id = "a" * 16
            foreign_id = "b" * 16
            write_manifest(root, own_id, sender="192.168.11.20")
            write_manifest(root, foreign_id, sender="192.168.11.21", name="foreign.txt")
            gateway = StubGateway(root)

            rows = _recent_uploads(gateway, "192.168.11.20")
            self.assertEqual([row["upload_id"] for row in rows], [own_id])
            self.assertNotIn("sender", rows[0])
            self.assertNotIn("path", rows[0])
            self.assertNotIn("documents", rows[0])
            self.assertNotIn("images", rows[0])

            self.assertEqual(
                _validate_owned_uploads(gateway, [own_id], "192.168.11.20"),
                [own_id],
            )
            with self.assertRaisesRegex(UploadSecurityError, "not owned"):
                _validate_owned_uploads(
                    gateway,
                    [foreign_id],
                    "192.168.11.20",
                )


if __name__ == "__main__":
    unittest.main()
