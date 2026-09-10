import unittest

from three_agent.computer_use_browser_observation import (
    BrowserObservationConfig,
    BrowserObservationError,
    BrowserReadOnlyCapture,
    capture_isolated_browser_observation,
)


class FakeBrowserBackend:
    def __init__(self, capture):
        self.capture = capture
        self.calls = []

    def capture_read_only(self, *, profile_id, include_screenshot):
        self.calls.append((profile_id, include_screenshot))
        return self.capture


def capture(
    *,
    screenshot=None,
    dom=None,
    accessibility=None,
    metadata=None,
    target_tab="tab1",
    profile_id="isolated",
):
    return BrowserReadOnlyCapture(
        profile_id=profile_id,
        window_id="window1",
        tab_id=target_tab,
        metadata=(
            {"title": "Example", "url": "https://example.test/read-only"}
            if metadata is None
            else metadata
        ),
        dom_snapshot=(
            {"nodes": [{"role": "heading", "text": "Hello"}]}
            if dom is None
            else dom
        ),
        accessibility_snapshot=(
            {"nodes": [{"role": "heading", "name": "Hello"}]}
            if accessibility is None
            else accessibility
        ),
        captured_at="2026-09-10T00:00:00Z",
        screenshot_bytes=screenshot,
    )


class BrowserObservationTests(unittest.TestCase):
    def test_isolated_profile_capture_is_bounded_and_read_only(self):
        backend = FakeBrowserBackend(capture())
        observation = capture_isolated_browser_observation(
            config=BrowserObservationConfig(
                profile_id="isolated",
                control_endpoint="http://127.0.0.1:9222",
            ),
            backend=backend,
            session_id="session:browser",
            task_id="task:browser",
        )
        self.assertEqual(backend.calls, [("isolated", False)])
        self.assertEqual(observation.surface, "browser")
        self.assertEqual(observation.active_target_ref, "browser:profile:isolated/tab:tab1")
        self.assertEqual(observation.structured_observation["profile_mode"], "isolated")
        self.assertEqual(observation.structured_observation["storage_identity"], "public_browser")
        self.assertIsNone(observation.screenshot_sha256)

    def test_personal_profile_mode_is_rejected(self):
        with self.assertRaisesRegex(BrowserObservationError, "BROWSER_PERSONAL_PROFILE_ATTACH_FORBIDDEN"):
            BrowserObservationConfig(
                profile_id="Default",
                control_endpoint="http://127.0.0.1:9222",
                profile_mode="personal",
            ).validate()

    def test_backend_profile_attestation_mismatch_is_rejected(self):
        with self.assertRaisesRegex(BrowserObservationError, "BROWSER_BACKEND_PROFILE_ATTESTATION_MISMATCH"):
            capture_isolated_browser_observation(
                config=BrowserObservationConfig(
                    profile_id="isolated",
                    control_endpoint="http://127.0.0.1:9222",
                ),
                backend=FakeBrowserBackend(capture(profile_id="Default")),
                session_id="session:browser",
                task_id="task:browser",
            )

    def test_public_control_endpoint_is_rejected(self):
        with self.assertRaisesRegex(BrowserObservationError, "BROWSER_CONTROL_ENDPOINT_NOT_LOCAL_OR_PRIVATE"):
            BrowserObservationConfig(
                profile_id="isolated",
                control_endpoint="https://8.8.8.8:9222",
            ).validate()

    def test_confidential_storage_class_is_rejected(self):
        with self.assertRaisesRegex(BrowserObservationError, "BROWSER_CONFIDENTIAL_STORAGE_ACCESS_FORBIDDEN"):
            BrowserObservationConfig(
                profile_id="isolated",
                control_endpoint="http://localhost:9222",
                accessible_storage_classes=("public_browser", "confidential_core"),
            ).validate()

    def test_screenshot_is_on_demand_and_only_hash_is_retained(self):
        raw = b"fake-png-bytes"
        observation = capture_isolated_browser_observation(
            config=BrowserObservationConfig(
                profile_id="isolated",
                control_endpoint="http://10.0.0.2:9222",
            ),
            backend=FakeBrowserBackend(capture(screenshot=raw)),
            session_id="session:browser",
            task_id="task:browser",
            include_screenshot=True,
        )
        self.assertTrue(observation.screenshot_sha256.startswith("sha256:"))
        self.assertNotIn(raw.decode("utf-8"), str(observation.structured_observation))

    def test_unrequested_screenshot_fails_closed(self):
        with self.assertRaisesRegex(BrowserObservationError, "BROWSER_UNREQUESTED_SCREENSHOT_RETURNED"):
            capture_isolated_browser_observation(
                config=BrowserObservationConfig(
                    profile_id="isolated",
                    control_endpoint="http://127.0.0.1:9222",
                ),
                backend=FakeBrowserBackend(capture(screenshot=b"unexpected")),
                session_id="session:browser",
                task_id="task:browser",
                include_screenshot=False,
            )

    def test_password_and_secure_field_values_are_redacted(self):
        observation = capture_isolated_browser_observation(
            config=BrowserObservationConfig(
                profile_id="isolated",
                control_endpoint="http://127.0.0.1:9222",
            ),
            backend=FakeBrowserBackend(
                capture(
                    dom={
                        "nodes": [
                            {"type": "password", "value": "hunter2", "textContent": "hunter2"},
                            {"role": "textbox", "password": "dom-secret"},
                        ]
                    },
                    accessibility={
                        "nodes": [
                            {"role": "password", "value": "a11y-secret", "text": "a11y-secret"},
                            {"protected": True, "value": "protected-secret"},
                        ]
                    },
                )
            ),
            session_id="session:browser",
            task_id="task:browser",
        )
        retained = str(observation.structured_observation)
        for secret in ("hunter2", "dom-secret", "a11y-secret", "protected-secret"):
            self.assertNotIn(secret, retained)
        self.assertIn("[REDACTED]", retained)

    def test_cookie_token_and_authorization_keys_are_redacted(self):
        observation = capture_isolated_browser_observation(
            config=BrowserObservationConfig(
                profile_id="isolated",
                control_endpoint="http://127.0.0.1:9222",
            ),
            backend=FakeBrowserBackend(
                capture(
                    metadata={
                        "title": "Account",
                        "cookie": "sid=super-secret",
                        "Set-Cookie": "sid=another-secret",
                        "authorization": "Bearer top-secret",
                        "access-token": "token-secret",
                    }
                )
            ),
            session_id="session:browser",
            task_id="task:browser",
        )
        retained = str(observation.structured_observation)
        for secret in ("super-secret", "another-secret", "top-secret", "token-secret"):
            self.assertNotIn(secret, retained)

    def test_url_credentials_query_and_fragment_are_removed(self):
        observation = capture_isolated_browser_observation(
            config=BrowserObservationConfig(
                profile_id="isolated",
                control_endpoint="http://127.0.0.1:9222",
            ),
            backend=FakeBrowserBackend(
                capture(
                    metadata={
                        "url": "https://user:password@example.test/account?token=secret#private"
                    }
                )
            ),
            session_id="session:browser",
            task_id="task:browser",
        )
        retained_url = observation.structured_observation["metadata"]["url"]
        self.assertEqual(retained_url, "https://example.test/account")

    def test_oversized_dom_snapshot_is_rejected_after_sanitization(self):
        with self.assertRaisesRegex(BrowserObservationError, "BROWSER_DOM_SNAPSHOT_BOUND_EXCEEDED"):
            capture_isolated_browser_observation(
                config=BrowserObservationConfig(
                    profile_id="isolated",
                    control_endpoint="http://127.0.0.1:9222",
                ),
                backend=FakeBrowserBackend(capture(dom={"text": "x" * (24 * 1024)})),
                session_id="session:browser",
                task_id="task:browser",
            )

    def test_navigation_like_target_change_produces_new_target_and_state(self):
        config = BrowserObservationConfig(
            profile_id="isolated",
            control_endpoint="http://127.0.0.1:9222",
        )
        first = capture_isolated_browser_observation(
            config=config,
            backend=FakeBrowserBackend(capture(target_tab="tab1")),
            session_id="session:browser",
            task_id="task:browser",
        )
        second = capture_isolated_browser_observation(
            config=config,
            backend=FakeBrowserBackend(capture(target_tab="tab2")),
            session_id="session:browser",
            task_id="task:browser",
        )
        self.assertNotEqual(first.active_target_ref, second.active_target_ref)
        self.assertNotEqual(first.state_sha256, second.state_sha256)


if __name__ == "__main__":
    unittest.main()
