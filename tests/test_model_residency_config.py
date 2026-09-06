import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.config import load_config


class ModelResidencyConfigTests(unittest.TestCase):
    def write_config(self, root: Path, residency: dict) -> Path:
        path = root / "config.json"
        path.write_text(
            json.dumps(
                {
                    "environment": "secure-local",
                    "confidentiality_mode": "confidential",
                    "database_path": str(root / "tasks.db"),
                    "artifact_root": str(root / "data"),
                    "profile_root": str(root / "profiles"),
                    "llm": {
                        "provider": "ollama",
                        "base_url": "http://127.0.0.1:11434",
                        "model": "qwen3:30b",
                        "timeout_seconds": 1200,
                        "keep_alive": "2m",
                    },
                    "model_policy": {
                        "enabled": True,
                        "fast_model": "qwen3:14b",
                        "research_model": "qwen3:30b",
                        "presentation_model": "qwen3:14b",
                        "report_model": "qwen3:14b",
                        "deep_model": "qwen3:30b",
                        "resource_control": {
                            "enabled": True,
                            "residency": residency,
                        },
                    },
                    "internet_gateway": {
                        "enabled": True,
                        "mode": "strict",
                        "public_search_enabled": False,
                        "direct_egress": False,
                    },
                    "execution_gateway": {"enabled": True},
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_on_demand_residency_policy_loads(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
            path = self.write_config(
                Path(tmp),
                {
                    "enabled": True,
                    "strategy": "on_demand",
                    "idle_ttl_seconds": 90,
                    "eviction_policy": "idle_lru",
                    "runtime_download": False,
                },
            )
            config = load_config(str(path))
            policy = config.model_policy
            self.assertIsNotNone(policy)
            self.assertTrue(policy.residency_enabled)
            self.assertEqual(policy.residency_strategy, "on_demand")
            self.assertEqual(policy.residency_idle_ttl_seconds, 90.0)
            self.assertEqual(policy.residency_eviction_policy, "idle_lru")
            self.assertFalse(policy.runtime_model_download)

    def test_preload_strategy_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
            path = self.write_config(
                Path(tmp),
                {
                    "enabled": True,
                    "strategy": "preload_all",
                    "runtime_download": False,
                },
            )
            with self.assertRaisesRegex(ValueError, "strategy must be on_demand"):
                load_config(str(path))

    def test_runtime_download_is_rejected_from_config(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
            path = self.write_config(
                Path(tmp),
                {
                    "enabled": True,
                    "strategy": "on_demand",
                    "runtime_download": True,
                },
            )
            with self.assertRaisesRegex(ValueError, "runtime model download is forbidden"):
                load_config(str(path))

    def test_runtime_download_is_rejected_from_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_config(
                Path(tmp),
                {
                    "enabled": True,
                    "strategy": "on_demand",
                    "runtime_download": False,
                },
            )
            with patch.dict(
                os.environ,
                {"WORKSPACE_RUNTIME_MODEL_DOWNLOAD": "true"},
                clear=True,
            ):
                with self.assertRaisesRegex(ValueError, "runtime model download is forbidden"):
                    load_config(str(path))


if __name__ == "__main__":
    unittest.main()
