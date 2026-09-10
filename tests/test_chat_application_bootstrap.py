from __future__ import annotations

from types import SimpleNamespace

import pytest

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

    def bootstrap_admin(self, username: str, _password: str, **_kwargs: object) -> dict[str, str]:
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
        assert poll_interval == 0.5
        self.events.append("server.serve")

    def server_close(self) -> None:
        self.events.append("server.close")


def _configure_success(monkeypatch: pytest.MonkeyPatch, events: list[str]) -> None:
    config = SimpleNamespace(raw={}, database_path="workspace.db", artifact_root="artifacts")
    orchestrator = _FakeOrchestrator(events)

    monkeypatch.setattr(chat_application, "load_config", lambda: config)

    def _build_runtime(received: object) -> object:
        assert received is config
        events.append("runtime.build")
        return SimpleNamespace(orchestrator=orchestrator, local_model_gateway=None)

    monkeypatch.setattr(chat_application, "build_application_runtime", _build_runtime)
    gateway = chat_application.chat_gateway
    monkeypatch.setattr(gateway, "ExternalSessionAuthStore", lambda path: _FakeAuth(events, path))
    monkeypatch.setattr(gateway, "ExternalIdentityStore", lambda auth: _FakeExternalStore(events, auth))
    monkeypatch.setattr(
        gateway.ExternalAuthSettings,
        "from_env",
        staticmethod(lambda: SimpleNamespace(enabled=False, providers=())),
    )
    monkeypatch.setattr(
        gateway,
        "ContinuitySecurityAwareProjectChatService",
        lambda orchestrator, **kwargs: _FakeService(events, orchestrator, **kwargs),
    )
    monkeypatch.setattr(gateway, "ApprovedAssetApplication", lambda *args: SimpleNamespace(args=args))
    monkeypatch.setattr(gateway, "ThreadingHTTPServer", lambda address, handler: _FakeServer(events, address, handler))
    monkeypatch.setattr(gateway, "_parse_allowed_ids", lambda _value: set())
    monkeypatch.setattr(gateway, "_lan_hint", lambda host, port: f"http://{host}:{port}")
    monkeypatch.delenv("THREE_AGENT_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.setenv("THREE_AGENT_WEB_HOST", "127.0.0.1")
    monkeypatch.setenv("THREE_AGENT_WEB_PORT", "8787")


def test_packaged_chat_bootstraps_application_runtime_before_server(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    _configure_success(monkeypatch, events)

    assert chat_application.main() == 0
    assert events.index("runtime.build") < events.index("orchestrator.initialize")
    assert events.index("orchestrator.initialize") < events.index("server.construct")
    assert events[-2:] == ["server.serve", "server.close"]


def test_application_runtime_failure_prevents_server_bind(monkeypatch: pytest.MonkeyPatch) -> None:
    config = SimpleNamespace(raw={}, database_path="workspace.db", artifact_root="artifacts")
    server_called = False
    monkeypatch.setattr(chat_application, "load_config", lambda: config)

    def _fail(_config: object) -> object:
        raise RuntimeError("local-ai composition rejected")

    def _server(*_args: object, **_kwargs: object) -> object:
        nonlocal server_called
        server_called = True
        raise AssertionError("server must not be constructed")

    monkeypatch.setattr(chat_application, "build_application_runtime", _fail)
    monkeypatch.setattr(chat_application.chat_gateway, "ThreadingHTTPServer", _server)

    with pytest.raises(RuntimeError, match="local-ai composition rejected"):
        chat_application.main()
    assert server_called is False


def test_packaged_chat_scripts_use_canonical_application_entrypoint() -> None:
    pyproject = (__file__ and __import__("pathlib").Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert 'workspace-chat = "three_agent.chat_application:main"' in pyproject
    assert 'three-agent-chat = "three_agent.chat_application:main"' in pyproject
