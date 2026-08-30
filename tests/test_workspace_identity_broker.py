from __future__ import annotations

import os
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from three_agent.workspace_identity_broker import (
    BrokerConfig,
    BrokerState,
    _pkce_pair,
    _provider_authorize_url,
)


ENV = {
    "WORKSPACE_IDENTITY_PUBLIC_BASE_URL": "https://auth.workspace.example.com",
    "WORKSPACE_IDENTITY_ALLOWED_RETURN_ORIGINS": "http://192.168.11.112:8787,https://workspace.example.com",
    "WORKSPACE_IDENTITY_KEY": "identity-key-0123456789-0123456789-abcdef",
    "WORKSPACE_EXTERNAL_AUTH_REDEEM_KEY": "redeem-key-0123456789-0123456789-abcdef",
    "WORKSPACE_GOOGLE_CLIENT_ID": "google-client",
    "WORKSPACE_GOOGLE_CLIENT_SECRET": "google-secret",
    "WORKSPACE_GITHUB_CLIENT_ID": "github-client",
    "WORKSPACE_GITHUB_CLIENT_SECRET": "github-secret",
    "WORKSPACE_LINE_CHANNEL_ID": "line-channel",
    "WORKSPACE_LINE_CHANNEL_SECRET": "line-secret",
}


class IdentityBrokerTests(unittest.TestCase):
    def config(self) -> BrokerConfig:
        with patch.dict(os.environ, ENV, clear=False):
            return BrokerConfig()

    def test_all_three_external_providers_can_be_configured(self) -> None:
        config = self.config()
        self.assertEqual(set(config.providers), {"google", "github", "line"})
        self.assertEqual(config.redeem_host, "127.0.0.1")

    def test_provider_authorization_scopes_are_identity_only(self) -> None:
        config = self.config()
        _, challenge = _pkce_pair()
        for provider in ("google", "github", "line"):
            url = _provider_authorize_url(config, provider, "state", "nonce", challenge)
            params = parse_qs(urlparse(url).query)
            scope = set(params.get("scope", [""])[0].split())
            if provider == "github":
                self.assertEqual(scope, {"read:user"})
            else:
                self.assertEqual(scope, {"openid", "profile"})
            self.assertNotIn("repo", scope)
            self.assertNotIn("user:email", scope)
            self.assertNotIn("email", scope)
            self.assertNotIn("offline_access", scope)
            self.assertEqual(params.get("code_challenge_method"), ["S256"])

    def test_external_key_is_stable_hmac_not_raw_provider_subject(self) -> None:
        state = BrokerState(self.config())
        raw_subject = "provider-user-123456789"
        first = state.external_key("google", raw_subject)
        second = state.external_key("google", raw_subject)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)
        self.assertNotIn(raw_subject, first)
        self.assertNotEqual(first, state.external_key("github", raw_subject))

    def test_public_base_requires_https(self) -> None:
        broken = dict(ENV)
        broken["WORKSPACE_IDENTITY_PUBLIC_BASE_URL"] = "http://auth.workspace.example.com"
        with patch.dict(os.environ, broken, clear=False):
            with self.assertRaisesRegex(ValueError, "HTTPS"):
                BrokerConfig()

    def test_redeem_key_and_identity_key_require_real_entropy_budget(self) -> None:
        broken = dict(ENV)
        broken["WORKSPACE_IDENTITY_KEY"] = "short"
        with patch.dict(os.environ, broken, clear=False):
            with self.assertRaisesRegex(ValueError, "IDENTITY_KEY"):
                BrokerConfig()


if __name__ == "__main__":
    unittest.main()
