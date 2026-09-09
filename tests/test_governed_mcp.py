from __future__ import annotations

import asyncio
import os
import unittest

from three_agent.governed_mcp import GovernedMCPClient, MCPServerPolicy


class FakeTransport:
    def __init__(self, *, output=None, tools=None, delay=0.0):
        self.output = output if output is not None else {"ok": True}
        self.tools = tools or ["safe", "hidden"]
        self.delay = delay
        self.closed = False

    async def list_tools(self):
        return list(self.tools)

    async def call_tool(self, name, arguments):
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.output

    async def close(self):
        self.closed = True


class GovernedMCPClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_unregistered_server_is_denied(self):
        client = GovernedMCPClient(transport_factory=lambda p, e: FakeTransport())
        with self.assertRaisesRegex(PermissionError, "MCP_SERVER_NOT_REGISTERED"):
            await client.call_tool("missing", "safe", {}, actor="agent")

    async def test_tool_allowlist_filters_discovery_and_execution(self):
        client = GovernedMCPClient(transport_factory=lambda p, e: FakeTransport())
        client.register(MCPServerPolicy(server_id="local", allowed_tools=frozenset({"safe"}), command="example-mcp"))
        self.assertEqual(await client.list_tools("local"), ("safe",))
        result, receipt = await client.call_tool("local", "safe", {"x": 1}, actor="agent")
        self.assertEqual(result, {"ok": True})
        self.assertEqual(receipt.result, "ok")
        with self.assertRaisesRegex(PermissionError, "MCP_TOOL_NOT_ALLOWED"):
            await client.call_tool("local", "hidden", {}, actor="agent")
        self.assertTrue(client.verify_receipt_chain())

    async def test_remote_is_deny_by_default_and_host_allowlisted(self):
        with self.assertRaisesRegex(PermissionError, "MCP_REMOTE_DISABLED_BY_POLICY"):
            MCPServerPolicy(server_id="remote", allowed_tools=frozenset({"safe"}), transport="streamable-http", url="https://mcp.example.test/api", allowed_hosts=frozenset({"mcp.example.test"})).validate()
        MCPServerPolicy(server_id="remote", allowed_tools=frozenset({"safe"}), transport="streamable-http", url="https://mcp.example.test/api", allowed_hosts=frozenset({"mcp.example.test"}), allow_remote=True).validate()
        with self.assertRaisesRegex(PermissionError, "MCP_REMOTE_HOST_NOT_ALLOWED"):
            MCPServerPolicy(server_id="remote", allowed_tools=frozenset({"safe"}), transport="streamable-http", url="https://evil.example/api", allowed_hosts=frozenset({"mcp.example.test"}), allow_remote=True).validate()

    async def test_environment_is_reduced_to_allowlist(self):
        old_secret = os.environ.get("WORKSPACE_SECRET_TEST")
        old_safe = os.environ.get("WORKSPACE_SAFE_TEST")
        try:
            os.environ["WORKSPACE_SECRET_TEST"] = "secret"
            os.environ["WORKSPACE_SAFE_TEST"] = "safe"
            policy = MCPServerPolicy(server_id="local", allowed_tools=frozenset({"safe"}), command="example-mcp", env_allowlist=frozenset({"WORKSPACE_SAFE_TEST"}))
            env = GovernedMCPClient.sanitized_environment(policy)
            self.assertEqual(env, {"WORKSPACE_SAFE_TEST": "safe"})
            self.assertNotIn("WORKSPACE_SECRET_TEST", env)
        finally:
            if old_secret is None: os.environ.pop("WORKSPACE_SECRET_TEST", None)
            else: os.environ["WORKSPACE_SECRET_TEST"] = old_secret
            if old_safe is None: os.environ.pop("WORKSPACE_SAFE_TEST", None)
            else: os.environ["WORKSPACE_SAFE_TEST"] = old_safe

    async def test_call_budget_output_budget_and_timeout_are_enforced(self):
        big = GovernedMCPClient(transport_factory=lambda p, e: FakeTransport(output={"v": "x" * 200}))
        big.register(MCPServerPolicy(server_id="big", allowed_tools=frozenset({"safe"}), command="example", max_output_bytes=50))
        with self.assertRaisesRegex(RuntimeError, "MCP_OUTPUT_BUDGET_EXCEEDED"):
            await big.call_tool("big", "safe", {}, actor="agent")
        self.assertEqual(big.receipts()[-1].result, "error")

        one = GovernedMCPClient(transport_factory=lambda p, e: FakeTransport())
        one.register(MCPServerPolicy(server_id="one", allowed_tools=frozenset({"safe"}), command="example", max_calls=1))
        await one.call_tool("one", "safe", {}, actor="agent")
        with self.assertRaisesRegex(RuntimeError, "MCP_CALL_BUDGET_EXHAUSTED"):
            await one.call_tool("one", "safe", {}, actor="agent")

        slow = GovernedMCPClient(transport_factory=lambda p, e: FakeTransport(delay=0.05))
        slow.register(MCPServerPolicy(server_id="slow", allowed_tools=frozenset({"safe"}), command="example", timeout_seconds=0.001))
        with self.assertRaises(asyncio.TimeoutError):
            await slow.call_tool("slow", "safe", {}, actor="agent")

    async def test_monotonic_capability_revocation_blocks_bound_call(self):
        client = GovernedMCPClient(transport_factory=lambda p, e: FakeTransport(), revocation_check=lambda task_id, capability: task_id == "task-1" and capability == "mcp:local:safe")
        client.register(MCPServerPolicy(server_id="local", allowed_tools=frozenset({"safe"}), command="example"))
        with self.assertRaisesRegex(PermissionError, "MCP_CAPABILITY_REVOKED"):
            await client.call_tool("local", "safe", {}, actor="agent", task_id="task-1")

    async def test_close_closes_transports(self):
        fake = FakeTransport()
        client = GovernedMCPClient(transport_factory=lambda p, e: fake)
        client.register(MCPServerPolicy(server_id="local", allowed_tools=frozenset({"safe"}), command="example"))
        await client.list_tools("local")
        await client.close()
        self.assertTrue(fake.closed)


if __name__ == "__main__":
    unittest.main()
