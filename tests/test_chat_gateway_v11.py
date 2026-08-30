from __future__ import annotations

import unittest

from three_agent.chat_gateway_v11 import PromptCompilerHTTPHandler
from three_agent.prompt_compiler import PROMPT_COMPILER_VERSION
from three_agent.public_query_compiler import PUBLIC_QUERY_COMPILER_VERSION


class PromptCompilerGatewayTests(unittest.TestCase):
    def test_gateway_version_tracks_prompt_compiler_release(self) -> None:
        self.assertEqual(PromptCompilerHTTPHandler.server_version, "WorkSpaceChat/0.12")

    def test_compiler_versions_are_stable_named_contracts(self) -> None:
        self.assertEqual(
            PROMPT_COMPILER_VERSION,
            "workspace-prompt-compiler/deterministic-v1",
        )
        self.assertEqual(
            PUBLIC_QUERY_COMPILER_VERSION,
            "workspace-public-query-compiler/v1",
        )


if __name__ == "__main__":
    unittest.main()
