import base64
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.config import GatewayConfig
from three_agent.gateways import (
    ExecutionGateway,
    InternetGateway,
    OutboundSecurityError,
    decode_bing_click_redirect,
)


PUBLIC_ADDRINFO = [
    (2, 1, 6, "", ("93.184.216.34", 443)),
]


def _bing_click_url(target: str) -> str:
    payload = base64.urlsafe_b64encode(target.encode("utf-8")).decode("ascii").rstrip("=")
    return f"https://www.bing.com/ck/a?a=1&u=a1{payload}&ntb=1"


class GatewayTests(unittest.TestCase):
    def test_execution_gateway_allows_test_command_and_audits(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "exec.jsonl"
            gateway = ExecutionGateway(GatewayConfig(True, True, log), test_mode_full_access=True)
            result = gateway.run("research", "TASK-X", [sys.executable, "-c", "print('ok')"])
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), "ok")
            self.assertTrue(log.exists())

    def test_execution_gateway_denies_when_not_full_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "exec.jsonl"
            gateway = ExecutionGateway(GatewayConfig(True, True, log), test_mode_full_access=False)
            with self.assertRaises(PermissionError):
                gateway.run("research", None, [sys.executable, "-c", "print('no')"])


class DecodeBingClickRedirectTests(unittest.TestCase):
    def test_decodes_a1_prefixed_unpadded_base64_payload(self):
        target = "https://ja.wikipedia.org/wiki/Linux"
        payload = base64.urlsafe_b64encode(target.encode("utf-8")).decode("ascii").rstrip("=")
        self.assertEqual(decode_bing_click_redirect("a1" + payload), target)

    def test_rejects_missing_prefix_bad_base64_or_non_url_payload(self):
        self.assertEqual(decode_bing_click_redirect(""), "")
        self.assertEqual(decode_bing_click_redirect("not-prefixed-at-all"), "")
        self.assertEqual(decode_bing_click_redirect("a1###not-base64###"), "")
        not_a_url = base64.urlsafe_b64encode(b"just some text").decode("ascii").rstrip("=")
        self.assertEqual(decode_bing_click_redirect("a1" + not_a_url), "")


def _secure_bing_config(log: Path) -> GatewayConfig:
    return GatewayConfig(
        enabled=True,
        allow_all=False,
        audit_log=log,
        mode="strict",
        public_search_enabled=True,
        allowed_search_hosts=("www.bing.com",),
        broker_socket=None,
        direct_egress=True,
    )


class InternetGatewayBingRedirectGrantTests(unittest.TestCase):
    """Bing's own result links are click-tracking redirects, not the destination.

    Regression coverage for the bug this exposed once the research capability
    grant actually let live traffic reach Bing: every fetched source failed
    with OutboundSecurityError("Search parameters contain a non-allowlisted
    key") because InternetGateway.get() re-routed the bing.com-hosted
    redirect through search_get() instead of treating it as a content fetch.
    """

    def test_decoded_bing_redirect_target_is_granted_by_search_and_then_fetchable(self):
        target = "https://ja.wikipedia.org/wiki/Linux"
        search_html = (
            f'<html><body><li class="b_algo"><h2>'
            f'<a href="{_bing_click_url(target)}">Linux</a>'
            f"</h2></li></body></html>"
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            gateway = InternetGateway(_secure_bing_config(Path(tmp) / "internet-egress.jsonl"), test_mode_full_access=False)
            with patch("three_agent.gateways.socket.getaddrinfo", return_value=PUBLIC_ADDRINFO), patch.object(
                InternetGateway, "_read_https", side_effect=[search_html, b"<html>ok</html>"]
            ):
                gateway.search_get("research", "TASK-BING", "https://www.bing.com/search", {"q": "linux"})
                data = gateway.get("research", "TASK-BING", target)
            self.assertEqual(data, b"<html>ok</html>")

    def test_the_raw_bing_wrapper_url_itself_is_never_granted_as_a_content_fetch(self):
        target = "https://ja.wikipedia.org/wiki/Linux"
        wrapper_url = _bing_click_url(target)
        search_html = (
            f'<html><body><li class="b_algo"><h2>'
            f'<a href="{wrapper_url}">Linux</a>'
            f"</h2></li></body></html>"
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            gateway = InternetGateway(_secure_bing_config(Path(tmp) / "internet-egress.jsonl"), test_mode_full_access=False)
            with patch("three_agent.gateways.socket.getaddrinfo", return_value=PUBLIC_ADDRINFO), patch.object(
                InternetGateway, "_read_https", side_effect=[search_html, b"<html>ok</html>"]
            ):
                gateway.search_get("research", "TASK-BING", "https://www.bing.com/search", {"q": "linux"})
                # fetching the bing.com host itself is still routed through
                # search_get()'s strict q/count-only parameter allowlist, not
                # granted as an arbitrary content fetch.
                with self.assertRaises(OutboundSecurityError):
                    gateway.get("research", "TASK-BING", wrapper_url)


if __name__ == "__main__":
    unittest.main()
