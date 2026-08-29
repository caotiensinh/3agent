from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import struct
from dataclasses import replace
from pathlib import Path

from .config import load_config
from .gateways import InternetGateway
from .privacy import redact_sensitive_text

_MAX_REQUEST_BYTES = 16 * 1024
_ALLOWED_AGENT = "research"


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = conn.recv(remaining)
        if not chunk:
            raise ConnectionError("client disconnected")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _peer_uid(conn: socket.socket) -> int | None:
    if not hasattr(socket, "SO_PEERCRED"):
        return None
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


def _safe_identity(request: dict) -> tuple[str, str | None]:
    agent_id = str(request.get("agent_id", ""))
    task_id_raw = request.get("task_id")
    task_id = None if task_id_raw is None else str(task_id_raw)
    if agent_id != _ALLOWED_AGENT:
        raise PermissionError("only research capability may request public egress")
    if task_id is not None and (len(task_id) > 128 or any(ch in task_id for ch in "\r\n\x00")):
        raise PermissionError("invalid task identity")
    return agent_id, task_id


class EgressBroker:
    def __init__(self, config_path: str, socket_path: Path, allowed_uid: int):
        app = load_config(config_path)
        direct_config = replace(
            app.internet_gateway,
            broker_socket=None,
            direct_egress=True,
        )
        self.gateway = InternetGateway(direct_config, test_mode_full_access=False)
        self.socket_path = Path(socket_path)
        self.allowed_uid = int(allowed_uid)

    def _dispatch(self, request: dict) -> bytes:
        agent_id, task_id = _safe_identity(request)
        action = str(request.get("action", ""))
        if action == "search":
            endpoint = str(request.get("endpoint", ""))
            params = request.get("params")
            if len(endpoint) > 512 or not isinstance(params, dict):
                raise PermissionError("invalid public search request")
            return self.gateway.search_get(
                agent_id,
                task_id,
                endpoint,
                {str(k): v for k, v in params.items()},
                timeout=30,
            )
        if action == "fetch_result":
            url = str(request.get("url", ""))
            if len(url) > 2048:
                raise PermissionError("public result URL too long")
            return self.gateway.get(agent_id, task_id, url, timeout=30)
        raise PermissionError("unsupported egress broker action")

    def _serve_connection(self, conn: socket.socket) -> None:
        peer_uid = _peer_uid(conn)
        if peer_uid is None or peer_uid != self.allowed_uid:
            raise PermissionError("egress broker peer UID rejected")
        request_size = struct.unpack("!I", _recv_exact(conn, 4))[0]
        if request_size <= 0 or request_size > _MAX_REQUEST_BYTES:
            raise PermissionError("egress broker request size rejected")
        request = json.loads(_recv_exact(conn, request_size).decode("utf-8"))
        if not isinstance(request, dict):
            raise PermissionError("egress broker request must be a JSON object")
        body = self._dispatch(request)
        response = {"ok": True, "body_b64": base64.b64encode(body).decode("ascii")}
        encoded = json.dumps(response, separators=(",", ":")).encode("utf-8")
        conn.sendall(struct.pack("!I", len(encoded)) + encoded)

    def serve_forever(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists() or self.socket_path.is_socket():
            self.socket_path.unlink()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(self.socket_path))
            os.chmod(self.socket_path, 0o660)
            server.listen(16)
            while True:
                conn, _ = server.accept()
                with conn:
                    try:
                        self._serve_connection(conn)
                    except Exception as exc:
                        response = {
                            "ok": False,
                            "error": redact_sensitive_text(f"{type(exc).__name__}: {exc}")[:300],
                        }
                        encoded = json.dumps(response, separators=(",", ":")).encode("utf-8")
                        try:
                            conn.sendall(struct.pack("!I", len(encoded)) + encoded)
                        except OSError:
                            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="workspace-egressd")
    parser.add_argument("--config", default=os.getenv("WORKSPACE_CONFIG", "/etc/workspace/workspace.secure.json"))
    parser.add_argument("--socket", default="/run/workspace/egress.sock")
    parser.add_argument("--allow-uid", type=int, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    EgressBroker(args.config, Path(args.socket), args.allow_uid).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
