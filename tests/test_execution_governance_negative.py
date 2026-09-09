from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.validate_execution_governance import (
    GovernanceError,
    _resolve_repo_path,
    load_json,
    validate_policy,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "workspace.execution-governance.json"


class ExecutionGovernanceNegativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))

    def policy_copy(self) -> dict:
        return copy.deepcopy(self.policy)

    def test_missing_policy_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing-policy.json"
            with self.assertRaises(FileNotFoundError):
                load_json(missing)

    def test_malformed_policy_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "malformed.json"
            path.write_text('{"policy_id":', encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                load_json(path)

    def test_non_object_policy_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "array-root.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(GovernanceError, "root must be a JSON object"):
                load_json(path)

    def test_duplicate_json_key_is_rejected_at_parse_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "duplicate.json"
            path.write_text(
                '{"policy_id":"workspace_execution_governance",'
                '"policy_id":"shadow_policy"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(GovernanceError, "duplicate JSON key.*policy_id"):
                load_json(path)

    def test_unsupported_policy_version_is_rejected(self) -> None:
        policy = self.policy_copy()
        policy["version"] = "999.0.0"
        with self.assertRaisesRegex(GovernanceError, "unsupported policy version"):
            validate_policy(policy)

    def test_unknown_top_level_rule_is_rejected(self) -> None:
        policy = self.policy_copy()
        policy["shadow_governance_override"] = {"enabled": True}
        with self.assertRaisesRegex(GovernanceError, "unknown top-level policy keys"):
            validate_policy(policy)

    def test_mandatory_ci_gate_cannot_be_disabled(self) -> None:
        policy = self.policy_copy()
        policy["main_integration"]["merge_requires_governance_validator_pass"] = False
        with self.assertRaisesRegex(GovernanceError, "main merge must require governance validation"):
            validate_policy(policy)

    def test_invalid_parallel_lane_type_is_rejected(self) -> None:
        policy = self.policy_copy()
        policy["parallel_execution"]["target_active_lanes"] = "20"
        with self.assertRaisesRegex(GovernanceError, "target lanes must be 20"):
            validate_policy(policy)

    def test_relative_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp).resolve()
            with self.assertRaisesRegex(GovernanceError, "must remain inside repository root"):
                _resolve_repo_path(repo_root, "../outside.json", "policy")

    def test_absolute_path_outside_repo_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = (Path(tmp) / "repo").resolve()
            repo_root.mkdir()
            outside = (Path(tmp) / "outside.json").resolve()
            with self.assertRaisesRegex(GovernanceError, "must remain inside repository root"):
                _resolve_repo_path(repo_root, str(outside), "session")

    def test_path_inside_repo_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp).resolve()
            resolved = _resolve_repo_path(repo_root, "config/policy.json", "policy")
            self.assertEqual(resolved, repo_root / "config" / "policy.json")


if __name__ == "__main__":
    unittest.main()
