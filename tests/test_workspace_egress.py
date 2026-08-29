import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.config import GatewayConfig
from three_agent.gateways import InternetGateway, OutboundSecurityError
from three_agent.privacy import OutboundDLPError, assess_public_egress_text


class FakeSecureGateway(InternetGateway):
    def _read_https(self, agent_id, task_id, url, *, timeout, action):
        del timeout, action
        if "duckduckgo.com" in url:
            data = b'<a href="https://example.com/public-source">source</a>'
            self._record(agent_id, task_id, url, True, action="test_search")
            return data
        if url == "https://example.com/public-source":
            return b"public evidence"
        raise AssertionError(f"unexpected URL {url}")


def secure_config(log: Path, *, search: bool = True) -> GatewayConfig:
    return GatewayConfig(
        enabled=True,
        allow_all=False,
        audit_log=log,
        mode="strict",
        public_search_enabled=search,
        allowed_search_hosts=("html.duckduckgo.com",),
        max_response_bytes=1024 * 1024,
        max_query_chars=120,
        grant_ttl_seconds=60,
    )


class WorkSpaceEgressTests(unittest.TestCase):
    def test_confidential_mode_blocks_public_search(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = FakeSecureGateway(secure_config(Path(tmp) / "audit.jsonl", search=False), False)
            with self.assertRaises(OutboundSecurityError):
                gateway.get(
                    "research",
                    "TASK-1",
                    "https://html.duckduckgo.com/html/?q=public+topic",
                )

    def test_dlp_blocks_identifiers_and_confidential_markers(self):
        self.assertFalse(assess_public_egress_text("server 192.168.11.190 firmware").allowed)
        self.assertFalse(assess_public_egress_text("社外秘 camera design benchmark").allowed)
        self.assertFalse(assess_public_egress_text("contact dev@example.com product").allowed)
        self.assertTrue(assess_public_egress_text("NVIDIA RTX 5090 Ollama support").allowed)

    @patch("three_agent.gateways._validate_public_url", lambda url, https_only=True: None)
    def test_search_result_can_be_fetched_once_but_arbitrary_url_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "audit.jsonl"
            gateway = FakeSecureGateway(secure_config(log), False)
            search = gateway.get(
                "research",
                "TASK-1",
                "https://html.duckduckgo.com/html/?q=public+topic",
            )
            self.assertIn(b"example.com", search)
            self.assertEqual(
                gateway.get("research", "TASK-1", "https://example.com/public-source"),
                b"public evidence",
            )
            with self.assertRaises(OutboundSecurityError):
                gateway.get("research", "TASK-1", "https://example.com/public-source")
            with self.assertRaises(OutboundSecurityError):
                gateway.get("research", "TASK-1", "https://evil.example/exfiltrate")

    @patch("three_agent.gateways._validate_public_url", lambda url, https_only=True: None)
    def test_audit_stores_query_hash_not_query_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "audit.jsonl"
            gateway = FakeSecureGateway(secure_config(log), False)
            gateway.get(
                "research",
                "TASK-2",
                "https://html.duckduckgo.com/html/?q=public+ollama+documentation",
            )
            text = log.read_text(encoding="utf-8")
            self.assertNotIn("public ollama documentation", text)
            self.assertIn("query_sha256", text)

    def test_arbitrary_post_body_is_always_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = FakeSecureGateway(secure_config(Path(tmp) / "audit.jsonl"), False)
            with self.assertRaises(OutboundSecurityError):
                gateway.post_json(
                    "research",
                    "TASK-3",
                    "https://example.com/upload",
                    {"secret": "internal-data"},
                )

    def test_dlp_raises_before_sensitive_query_can_leave(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = FakeSecureGateway(secure_config(Path(tmp) / "audit.jsonl"), False)
            with patch("three_agent.gateways._validate_public_url", lambda url, https_only=True: None):
                with self.assertRaises(OutboundDLPError):
                    gateway.get(
                        "research",
                        "TASK-4",
                        "https://html.duckduckgo.com/html/?q=secret+192.168.1.20",
                    )


if __name__ == "__main__":
    unittest.main()
