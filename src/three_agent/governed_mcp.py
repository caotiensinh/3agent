from __future__ import annotations

import asyncio
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Protocol
from urllib.parse import urlparse

MCP_RECEIPT_SCHEMA = "workspace-governed-mcp-receipt/v1"


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class MCPTransport(Protocol):
    async def list_tools(self) -> list[str]: ...
    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any: ...
    async def close(self) -> None: ...


@dataclass(frozen=True)
class MCPServerPolicy:
    server_id: str
    allowed_tools: frozenset[str]
    transport: str = "stdio"
    command: str | None = None
    args: tuple[str, ...] = ()
    url: str | None = None
    allowed_hosts: frozenset[str] = frozenset()
    env_allowlist: frozenset[str] = frozenset()
    timeout_seconds: float = 30.0
    max_calls: int = 20
    max_output_bytes: int = 256 * 1024
    allow_remote: bool = False

    def validate(self) -> None:
        if not self.server_id.strip():
            raise ValueError("server_id is required")
        if self.transport not in {"stdio", "streamable-http"}:
            raise ValueError("transport must be stdio or streamable-http")
        if not self.allowed_tools:
            raise ValueError("allowed_tools must not be empty")
        if self.timeout_seconds <= 0 or self.max_calls < 1 or self.max_output_bytes < 1:
            raise ValueError("MCP budgets must be positive")
        if self.transport == "stdio":
            if not self.command:
                raise ValueError("stdio transport requires command")
        else:
            if not self.allow_remote:
                raise PermissionError("MCP_REMOTE_DISABLED_BY_POLICY")
            parsed = urlparse(self.url or "")
            if parsed.scheme != "https" or not parsed.hostname:
                raise ValueError("remote MCP requires an https URL")
            if parsed.hostname not in self.allowed_hosts:
                raise PermissionError("MCP_REMOTE_HOST_NOT_ALLOWED")


@dataclass(frozen=True)
class MCPCallReceipt:
    sequence: int
    receipt_id: str
    prev_hash: str
    event_hash: str
    server_id: str
    tool_name: str
    actor: str
    result: str
    output_bytes: int
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": MCP_RECEIPT_SCHEMA,
            "sequence": self.sequence,
            "receipt_id": self.receipt_id,
            "prev_hash": self.prev_hash,
            "event_hash": self.event_hash,
            "server_id": self.server_id,
            "tool_name": self.tool_name,
            "actor": self.actor,
            "result": self.result,
            "output_bytes": self.output_bytes,
            "details": self.details,
        }


TransportFactory = Callable[[MCPServerPolicy, dict[str, str]], Awaitable[MCPTransport] | MCPTransport]
RevocationCheck = Callable[[str, str], bool]


class GovernedMCPClient:
    """Policy-enforced MCP client with deny-by-default registration and budgets."""

    def __init__(
        self,
        *,
        transport_factory: TransportFactory | None = None,
        revocation_check: RevocationCheck | None = None,
    ):
        self._policies: dict[str, MCPServerPolicy] = {}
        self._transports: dict[str, MCPTransport] = {}
        self._calls: dict[str, int] = {}
        self._receipts: list[MCPCallReceipt] = []
        self._transport_factory = transport_factory or _official_transport_factory
        self._revocation_check = revocation_check

    def register(self, policy: MCPServerPolicy) -> None:
        policy.validate()
        if policy.server_id in self._policies:
            raise ValueError("MCP_SERVER_ALREADY_REGISTERED")
        self._policies[policy.server_id] = policy
        self._calls[policy.server_id] = 0

    def policy(self, server_id: str) -> MCPServerPolicy:
        try:
            return self._policies[server_id]
        except KeyError as exc:
            raise PermissionError("MCP_SERVER_NOT_REGISTERED") from exc

    @staticmethod
    def sanitized_environment(policy: MCPServerPolicy) -> dict[str, str]:
        safe: dict[str, str] = {}
        for key in sorted(policy.env_allowlist):
            if key in os.environ:
                safe[key] = os.environ[key]
        return safe

    async def _transport(self, server_id: str) -> MCPTransport:
        policy = self.policy(server_id)
        existing = self._transports.get(server_id)
        if existing is not None:
            return existing
        env = self.sanitized_environment(policy)
        created = self._transport_factory(policy, env)
        transport = await created if hasattr(created, "__await__") else created
        self._transports[server_id] = transport
        return transport

    async def list_tools(self, server_id: str) -> tuple[str, ...]:
        policy = self.policy(server_id)
        transport = await self._transport(server_id)
        discovered = await asyncio.wait_for(transport.list_tools(), timeout=policy.timeout_seconds)
        return tuple(sorted(set(discovered).intersection(policy.allowed_tools)))

    async def call_tool(
        self,
        server_id: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        actor: str,
        task_id: str | None = None,
    ) -> tuple[Any, MCPCallReceipt]:
        policy = self.policy(server_id)
        if tool_name not in policy.allowed_tools:
            raise PermissionError("MCP_TOOL_NOT_ALLOWED")
        if self._revocation_check and task_id and self._revocation_check(task_id, f"mcp:{server_id}:{tool_name}"):
            raise PermissionError("MCP_CAPABILITY_REVOKED")
        used = self._calls[server_id]
        if used >= policy.max_calls:
            raise RuntimeError("MCP_CALL_BUDGET_EXHAUSTED")

        transport = await self._transport(server_id)
        args = arguments or {}
        argument_hash = _sha256(_canonical_json(args))
        try:
            result = await asyncio.wait_for(
                transport.call_tool(tool_name, args), timeout=policy.timeout_seconds
            )
            encoded = _canonical_json(result).encode("utf-8")
            if len(encoded) > policy.max_output_bytes:
                raise RuntimeError("MCP_OUTPUT_BUDGET_EXCEEDED")
            self._calls[server_id] = used + 1
            receipt = self._append_receipt(
                server_id=server_id,
                tool_name=tool_name,
                actor=actor,
                result="ok",
                output_bytes=len(encoded),
                details={"argument_hash": argument_hash, "task_id": task_id or ""},
            )
            return result, receipt
        except Exception as exc:
            self._calls[server_id] = used + 1
            self._append_receipt(
                server_id=server_id,
                tool_name=tool_name,
                actor=actor,
                result="error",
                output_bytes=0,
                details={
                    "argument_hash": argument_hash,
                    "task_id": task_id or "",
                    "error_type": type(exc).__name__,
                },
            )
            raise

    def _append_receipt(
        self,
        *,
        server_id: str,
        tool_name: str,
        actor: str,
        result: str,
        output_bytes: int,
        details: dict[str, Any],
    ) -> MCPCallReceipt:
        prev_hash = self._receipts[-1].event_hash if self._receipts else "GENESIS"
        body = {
            "sequence": len(self._receipts) + 1,
            "server_id": server_id,
            "tool_name": tool_name,
            "actor": actor,
            "result": result,
            "output_bytes": output_bytes,
            "details": details,
            "prev_hash": prev_hash,
        }
        event_hash = _sha256(_canonical_json(body))
        receipt = MCPCallReceipt(
            sequence=body["sequence"],
            receipt_id="mcp_" + event_hash[:32],
            prev_hash=prev_hash,
            event_hash=event_hash,
            server_id=server_id,
            tool_name=tool_name,
            actor=actor,
            result=result,
            output_bytes=output_bytes,
            details=details,
        )
        self._receipts.append(receipt)
        return receipt

    def receipts(self) -> tuple[MCPCallReceipt, ...]:
        return tuple(self._receipts)

    def verify_receipt_chain(self) -> bool:
        previous = "GENESIS"
        for receipt in self._receipts:
            if receipt.prev_hash != previous:
                return False
            body = {
                "sequence": receipt.sequence,
                "server_id": receipt.server_id,
                "tool_name": receipt.tool_name,
                "actor": receipt.actor,
                "result": receipt.result,
                "output_bytes": receipt.output_bytes,
                "details": receipt.details,
                "prev_hash": receipt.prev_hash,
            }
            expected = _sha256(_canonical_json(body))
            if receipt.event_hash != expected or receipt.receipt_id != "mcp_" + expected[:32]:
                return False
            previous = receipt.event_hash
        return True

    async def close(self) -> None:
        for transport in list(self._transports.values()):
            await transport.close()
        self._transports.clear()


class _OfficialMCPTransport:
    def __init__(self, context_manager: Any, session_context: Any, session: Any):
        self._context_manager = context_manager
        self._session_context = session_context
        self._session = session

    async def list_tools(self) -> list[str]:
        response = await self._session.list_tools()
        return [str(tool.name) for tool in response.tools]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        response = await self._session.call_tool(name, arguments)
        if hasattr(response, "model_dump"):
            return response.model_dump(mode="json")
        return response

    async def close(self) -> None:
        await self._session_context.__aexit__(None, None, None)
        await self._context_manager.__aexit__(None, None, None)


async def _official_transport_factory(
    policy: MCPServerPolicy, env: dict[str, str]
) -> MCPTransport:
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        from mcp.client.streamable_http import streamable_http_client
    except ImportError as exc:
        raise RuntimeError("MCP_SDK_NOT_INSTALLED: install workspace-local-ai[mcp]") from exc

    if policy.transport == "stdio":
        params = StdioServerParameters(command=str(policy.command), args=list(policy.args), env=env)
        context_manager = stdio_client(params)
    else:
        context_manager = streamable_http_client(str(policy.url))

    streams = await context_manager.__aenter__()
    read_stream, write_stream = streams[0], streams[1]
    session_context = ClientSession(read_stream, write_stream)
    session = await session_context.__aenter__()
    await session.initialize()
    return _OfficialMCPTransport(context_manager, session_context, session)
