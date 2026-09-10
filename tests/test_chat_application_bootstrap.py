from __future__ import annotations

import os
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock

from three_agent import chat_application


class _FakeOrchestrator:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.internet_gateway = object()

    def initialize(self) -> None:
        self.events.append("orchestrator.initialize")


class _FakeAuth:
    def __init__(self, events: list[str], _path: object) -> None:
        self.events = events

    def initialize(self) -> None:
        self.events.append("auth.initialize")

    def bootstrap_admin(
        self,
        username: str,
        _password: str,
        **_kwargs: object,
    ) -> dict[str, str]:
        self.events.append("auth.bootstrap_admin")
        return {"username": username, "user_id": "admin-1"}


class _FakeExternalStore:
    def __init__(self, events: list[str], _auth: object) -> None:
        self.events = events

    def initialize(self) -> None:
        self.events.append("external.initialize")


class _FakeService:
    def __init__(self, events: list[str], _orchestrator: object, **_kwargs: object) -> None:
        self.events = events

    def start(self) -> None:
        self.events.append("service.start")


class _FakeServer:
    def __init__(self, events: list[str], _address: object, _handler: object) -> None:
        self.events = events
        self.app = None
        self.events.append("server.construct")

    def serve_forever(self, *, poll_interval: float) -> None:
        if poll_interval != 0.5:
            raise AssertionError(f"unexpected poll_interval={poll_interval}")
        self.events.append("server.serve")

    def server_close(self) -> None:
        self.events.append("server.close")


class ChatApplicationBootstrapTests(unittest.TestCase):
    def _configure_success(self, events: list[str]) -> ExitStack:
        config = SimpleNamespace(
            raw={},
            database_path="workspace.db",
            artifact_root="artifacts",
        )
        orchestrator = _FakeOrchestrator(events)
        gateway = chat_application.chat_gateway

        def _build_runtime(received: object) -> object:
            self.assertIs(received, config)
            events.append("runtime.build")
            return SimpleNamespace(
                orchestrator=orchestrator,
                local_model_gateway=None,
            )

        stack = ExitStack()
        stack.enter_context(mock.patch.object(chat_application, "load_config", return_value=config))
        stack.enter_context(
            mock.patch.object(chat_application, "build_application_runtime", side_effect=_build_runtime)
        )
        stack.enter_context(
            mock.patch.object(
                gateway,
                "ExternalSessionAuthStore",
                side_effect=lambda path: _FakeAuth(events, path),
            )
        )
        stack.enter_context(
            mock.patch.object(
                gateway,
                "ExternalIdentityStore",
                side_effect=lambda auth: _FakeExternalStore(events, auth),
            )
        )
        stack.enter_context(
            mock.patch.object(
                gateway.ExternalAuthSettings,
                "from_env",
                return_value=SimpleNamespace(enabled=False, providers=()),
            )
        )
        stack.enter_context(
            mock.patch.object(
                gateway,
                "ContinuitySecurityAwareProjectChatService",
                side_effect=lambda orchestrator, **kwargs: _FakeService(
                    events,
                    orchestrator,
                    **kwargs,
                ),
            )
        )
        stack.enter_context(
            mock.patch.object(
                gateway,
                "ApprovedAssetApplication",
                side_effect=lambda *args: SimpleNamespace(args=args),
            )
        )
        stack.enter_context(
            mock.patch.object(
                gateway,
                "ThreadingHTTPServer",
                side_effect=lambda address, handler: _FakeServer(events, address, handler),
            )
        )
        stack.enter_context(mock.patch.object(gateway, "_parse_allowed_ids", return_value=set()))
        stack.enter_context(
            mock.patch.object(
                gateway,
                "_lan_hint",
                side_effect=lambda host, port: f"http://{host}:{port}",
            )
        )
        stack.enter_context(
            mock.patch.dict(
                os.environ,
                {
                    "THREE_AGENT_WEB_HOST": "127.0.0.1",
                    "THREE_AGENT_WEB_PORT": "8787",
                },
                clear=False,
            )
        )
        stack.enter_context(
            mock.patch.dict(
                os.environ,
                {"THREE_AGENT_TELEGRAM_BOT_TOKEN": ""},
                clear=False,
            )
        )
        return stack

    def test_packaged_chat_bootstraps_application_runtime_before_server(self) -> None:
        events: list[str] = []
        with self._configure_success(events):
            self.assertEqual(chat_application.main(), 0)

        self.assertLess(events.index("runtime.build"), events.index("orchestrator.initialize"))
        self.assertLess(events.index("orchestrator.initialize"), events.index("server.construct"))
        self.assertEqual(events[-2:], ["server.serve", "server.close"])

    def test_application_runtime_failure_prevents_server_bind(self) -> None:
        config = SimpleNamespace(
            raw={},
            database_path="workspace.db",
            artifact_root="artifacts",
        )
        server_called = False

        def _fail(_config: object) -> object:
            raise RuntimeError("local-ai composition rejected")

        def _server(*_args: object, **_kwargs: object) -> object:
            nonlocal server_called
            server_called = True
            raise AssertionError("server must not be constructed")

        with (
            mock.patch.object(chat_application, "load_config", return_value=config),
            mock.patch.object(chat_application, "build_application_runtime", side_effect=_fail),
            mock.patch.object(chat_application.chat_gateway, "ThreadingHTTPServer", side_effect=_server),
        ):
            with self.assertRaisesRegex(RuntimeError, "local-ai composition rejected"):
                chat_application.main()

        self.assertFalse(server_called)

    def test_packaged_chat_scripts_use_canonical_application_entrypoint(self) -> None:
        pyproject = (
            __import__("pathlib").Path(__file__).resolve().parents[1] / "pyproject.toml"
        ).read_text(encoding="utf-8")
        self.assertIn('workspace-chat = "three_agent.chat_application:main"', pyproject)
        self.assertIn('three-agent-chat = "three_agent.chat_application:main"', pyproject)


if __name__ == "__main__":
    unittest.main()
