from __future__ import annotations

import json
import unittest
from types import SimpleNamespace

from three_agent.adaptive_learning_reflection import (
    IsolatedReflectionRunner,
    ReflectionWorkerExecutionConfig,
)
from three_agent.adaptive_learning_reflection_contract import (
    BoundedReflectionPacket,
    REFLECTION_RESULT_SCHEMA,
    ReflectionResult,
)

H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64


class ReflectionIPCEncodingTests(unittest.TestCase):
    def test_subprocess_text_pipes_are_explicit_utf8(self):
        captured = {}

        def executor(command, **kwargs):
            captured["command"] = command
            captured.update(kwargs)
            result = ReflectionResult(
                result="NO_LEARNING_VALUE",
                kind="none",
                title="",
                content="",
                scope="",
                action="none",
                execution_mode="none",
                reusable_value_reason="単発事象で再利用価値がありません。",
            ).validate()
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    result.to_payload(),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                stderr="",
            )

        packet = BoundedReflectionPacket(
            admission_id="admission:" + "a" * 64,
            admission_provenance_sha256=H1,
            binding_sha256=H2,
            task_id="task:jp-reflection",
            domain="analyst",
            sensitivity="confidential",
            risk_level="medium",
            outcome="verified_success",
            evidence_hashes=(H1,),
            summary="日本語の検証済み要約。ベトナム語の説明も保持する。",
            output_schema_version=REFLECTION_RESULT_SCHEMA,
            allowed_action="create",
            target_item_id=None,
            base_item_sha256=None,
        ).validate()
        runner = IsolatedReflectionRunner(
            ReflectionWorkerExecutionConfig(
                base_url="http://127.0.0.1:11434",
                model="local:test",
                timeout_seconds=30,
            ),
            executor=executor,
            python_executable="/trusted/python",
        )
        outcome = runner.run(packet)

        self.assertEqual(outcome.result, "NO_LEARNING_VALUE")
        self.assertEqual(captured["encoding"], "utf-8")
        self.assertEqual(captured["errors"], "strict")
        self.assertIn("日本語", captured["input"])
        self.assertFalse(captured["shell"])


if __name__ == "__main__":
    unittest.main()
