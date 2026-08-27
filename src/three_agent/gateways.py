from __future__ import annotations

import json
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

from .config import GatewayConfig

TZ = ZoneInfo("Asia/Tokyo")


def _audit(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


class InternetGateway:
    def __init__(self, config: GatewayConfig, test_mode_full_access: bool):
        self.config = config
        self.test_mode_full_access = test_mode_full_access

    def get(self, agent_id: str, task_id: str | None, url: str, timeout: int = 30) -> bytes:
        allowed = self.config.enabled and self.test_mode_full_access and self.config.allow_all
        record = {
            "timestamp": datetime.now(TZ).isoformat(),
            "agent_id": agent_id,
            "task_id": task_id,
            "action": "http_get",
            "url": url,
            "allowed": allowed,
        }
        _audit(self.config.audit_log, record)
        if not allowed:
            raise PermissionError("Outbound Internet is not permitted by current gateway policy")
        req = Request(url, headers={"User-Agent": "3Agent-TestHarness/0.1"})
        with urlopen(req, timeout=timeout) as response:
            return response.read()


class ExecutionGateway:
    def __init__(self, config: GatewayConfig, test_mode_full_access: bool):
        self.config = config
        self.test_mode_full_access = test_mode_full_access

    def run(self, agent_id: str, task_id: str | None, argv: list[str], cwd: str | None = None) -> subprocess.CompletedProcess[str]:
        allowed = self.config.enabled and self.test_mode_full_access and self.config.allow_all
        _audit(
            self.config.audit_log,
            {
                "timestamp": datetime.now(TZ).isoformat(),
                "agent_id": agent_id,
                "task_id": task_id,
                "action": "command",
                "argv": argv,
                "cwd": cwd,
                "allowed": allowed,
            },
        )
        if not allowed:
            raise PermissionError("Command execution is not permitted by current gateway policy")
        return subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
