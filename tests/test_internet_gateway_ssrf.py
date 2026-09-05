from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from three_agent.config import GatewayConfig
from three_agent.gateways import InternetGateway, OutboundSecurityError, _validate_public_url


PUBLIC_ADDRINFO = [
    (2, 1, 6, "", ("93.184.216.34", 443)),
]
MIXED_ADDRINFO = [
    (2, 1, 6, "", ("93.184.216.34", 443)),
    (2, 1, 6, "", ("10.10.10.10", 443)),
]


def secure_config(log: Path) -> GatewayConfig:
    return GatewayConfig(
        enabled=True,
        allow_all=False,
        audit_log=log,
        mode="strict",
        public_search_enabled=True,
        max_response_bytes=1024 * 1024,
        max_query_chars=240,
        grant_ttl_seconds=60,
        direct_egress=True,
    )


class _RedirectToMetadataOpener:
    def __init__(self) -> None:
        self.calls = 0

    def open(self, request, timeout=30):
        del timeout
        self.calls += 1
        raise HTTPError(
            request.full_url,
            302,
            "Found",
            {"Location": "https://169.254.169.254/latest/meta-data/"},
            None,
        )


class InternetGatewaySsrfTests(unittest.TestCase):
    def test_non_https_and_non_443_destinations_are_denied(self) -> None:
        with self.assertRaises(OutboundSecurityError):
            _validate_public_url("http://example.com/")
        with self.assertRaises(OutboundSecurityError):
            _validate_public_url("https://example.com:8443/")
        with self.assertRaises(OutboundSecurityError):
            _validate_public_url("file:///etc/passwd")

    def test_url_credentials_and_local_names_are_denied(self) -> None:
        with self.assertRaises(OutboundSecurityError):
            _validate_public_url("https://user:password@example.com/")
        for url in (
            "https://localhost/",
            "https://service.localhost/",
            "https://printer.local/",
        ):
            with self.subTest(url=url), self.assertRaises(OutboundSecurityError):
                _validate_public_url(url)

    def test_private_link_local_loopback_and_ipv6_ula_are_denied(self) -> None:
        blocked = (
            "https://127.0.0.1/",
            "https://10.0.0.1/",
            "https://172.16.0.1/",
            "https://192.168.1.1/",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/",
            "https://[fe80::1]/",
            "https://[fd00::1]/",
        )
        for url in blocked:
            with self.subTest(url=url), self.assertRaises(OutboundSecurityError):
                _validate_public_url(url)

    def test_dns_answer_is_denied_when_any_resolved_address_is_non_public(self) -> None:
        with patch("three_agent.gateways.socket.getaddrinfo", return_value=MIXED_ADDRINFO):
            with self.assertRaises(OutboundSecurityError):
                _validate_public_url("https://example.com/")

    def test_dns_resolution_failure_fails_closed(self) -> None:
        import socket

        with patch(
            "three_agent.gateways.socket.getaddrinfo",
            side_effect=socket.gaierror("test resolution failure"),
        ):
            with self.assertRaises(OutboundSecurityError):
                _validate_public_url("https://example.com/")

    def test_public_dns_answer_is_accepted(self) -> None:
        with patch("three_agent.gateways.socket.getaddrinfo", return_value=PUBLIC_ADDRINFO):
            _validate_public_url("https://example.com/public-doc")

    def test_public_to_metadata_redirect_is_revalidated_before_second_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_path = Path(tmp) / "audit.jsonl"
            gateway = InternetGateway(secure_config(audit_path), False)
            opener = _RedirectToMetadataOpener()
            gateway._opener = opener
            validated: list[str] = []

            def validate(url: str, https_only: bool = True) -> None:
                del https_only
                validated.append(url)
                if "169.254.169.254" in url:
                    raise OutboundSecurityError("metadata target denied")

            with patch("three_agent.gateways._validate_public_url", side_effect=validate):
                with self.assertRaises(OutboundSecurityError):
                    gateway._read_https(
                        "research",
                        "TASK-SSRF",
                        "https://example.com/start",
                        timeout=5,
                        action="public_result_fetch",
                    )

            self.assertEqual(
                opener.calls,
                1,
                "redirect target must be denied before a second network request",
            )
            self.assertEqual(
                validated,
                [
                    "https://example.com/start",
                    "https://169.254.169.254/latest/meta-data/",
                ],
            )

            events = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertTrue(
                any(
                    event.get("allowed") is False
                    and str(event.get("reason", "")).startswith("redirect_target_rejected:")
                    for event in events
                ),
                "rejected redirect must produce metadata-only audit evidence",
            )
            self.assertNotIn(
                "169.254.169.254",
                audit_path.read_text(encoding="utf-8"),
                "audit must not retain the raw private metadata target",
            )


if __name__ == "__main__":
    unittest.main()
