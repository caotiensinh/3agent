from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scripts.validate_execution_governance as governance
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

    def write_policy(self, repo_root: Path, policy: dict) -> Path:
        policy_path = repo_root / "config" / "workspace.execution-governance.json"
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        return policy_path

    def run_main_quietly(self, argv: list[str]) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return governance.main(argv)

    def run_main_with_result(self, repo_root: Path, *extra_args: str) -> tuple[int, dict]:
        result_path = repo_root / "governance-result.json"
        rc = self.run_main_quietly(
            [
                "--repo-root",
                str(repo_root),
                "--json-output",
                str(result_path),
                *extra_args,
            ]
        )
        payload = json.loads(result_path.read_text(encoding="utf-8"))
        return rc, payload

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

    def test_incomplete_policy_is_rejected(self) -> None:
        policy = self.policy_copy()
        del policy["main_integration"]
        with self.assertRaisesRegex(GovernanceError, "missing top-level policy keys"):
            validate_policy(policy)

    def test_empty_mandatory_policy_id_is_rejected(self) -> None:
        policy = self.policy_copy()
        policy["policy_id"] = ""
        with self.assertRaisesRegex(GovernanceError, "stable policy_id required"):
            validate_policy(policy)

    def test_invalid_terminal_state_enum_is_rejected(self) -> None:
        policy = self.policy_copy()
        policy["state_machine"]["successful_terminal_state"] = "PASS"
        with self.assertRaisesRegex(GovernanceError, "VERIFIED_PASS must be the only success state"):
            validate_policy(policy)

    def test_conflicting_lane_limits_are_rejected(self) -> None:
        policy = self.policy_copy()
        policy["parallel_execution"]["maximum_active_lanes"] = 10
        with self.assertRaisesRegex(GovernanceError, "maximum lanes must be 20"):
            validate_policy(policy)

    def test_mandatory_ci_gate_cannot_be_disabled(self) -> None:
        policy = self.policy_copy()
        policy["main_integration"]["merge_requires_governance_validator_pass"] = False
        with self.assertRaisesRegex(GovernanceError, "main merge must require governance validation"):
            validate_policy(policy)

    def test_unauthorized_self_exemption_is_rejected(self) -> None:
        policy = self.policy_copy()
        policy["repository_default"]["no_actor_self_exemption"] = False
        with self.assertRaisesRegex(GovernanceError, "no_actor_self_exemption=true"):
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

    def test_symlink_escape_outside_repo_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo_root = root / "repo"
            repo_root.mkdir()
            outside = root / "outside.json"
            outside.write_text("{}", encoding="utf-8")
            link = repo_root / "policy-link.json"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaisesRegex(GovernanceError, "must remain inside repository root"):
                _resolve_repo_path(repo_root.resolve(), link, "policy")

    def test_path_inside_repo_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp).resolve()
            resolved = _resolve_repo_path(repo_root, "config/policy.json", "policy")
            self.assertEqual(resolved, repo_root / "config" / "policy.json")

    def test_environment_skip_flag_cannot_bypass_invalid_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp).resolve()
            policy = self.policy_copy()
            policy["main_integration"]["merge_requires_governance_validator_pass"] = False
            self.write_policy(repo_root, policy)
            with patch.dict(os.environ, {"WORKSPACE_SKIP_GOVERNANCE": "1"}, clear=False):
                rc = self.run_main_quietly(["--repo-root", str(repo_root)])
            self.assertEqual(rc, 1)

    def test_generated_policy_sibling_is_rejected_as_canonical_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp).resolve()
            self.write_policy(repo_root, self.policy_copy())
            generated = repo_root / "config" / "workspace.execution-governance.generated.json"
            generated.write_text(json.dumps(self.policy), encoding="utf-8")
            with self.assertRaisesRegex(GovernanceError, "canonical policy duplication/drift"):
                validate_policy(self.policy_copy(), repo_root=repo_root)

    def test_validator_exception_fails_closed_with_structured_classification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp).resolve()
            self.write_policy(repo_root, self.policy_copy())
            with patch.object(governance, "validate_policy", side_effect=RuntimeError("forced validator fault")):
                rc, payload = self.run_main_with_result(repo_root)
            self.assertEqual(rc, 1)
            self.assertFalse(payload["valid"])
            self.assertEqual(payload["classification"], "VALIDATOR_ERROR")
            self.assertEqual(payload["violations"][0]["rule_id"], "GOV-VALIDATOR-EXCEPTION")

    def test_missing_policy_emits_config_error_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp).resolve()
            rc, payload = self.run_main_with_result(
                repo_root,
                "--policy",
                "config/missing-policy.json",
            )
            self.assertEqual(rc, 1)
            self.assertFalse(payload["valid"])
            self.assertEqual(payload["classification"], "CONFIG_ERROR")
            self.assertEqual(payload["violations"][0]["rule_id"], "GOV-CONFIG-MISSING")

    def test_malformed_policy_emits_policy_invalid_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp).resolve()
            policy_path = repo_root / "config" / "workspace.execution-governance.json"
            policy_path.parent.mkdir(parents=True, exist_ok=True)
            policy_path.write_text('{"policy_id":', encoding="utf-8")
            rc, payload = self.run_main_with_result(repo_root)
            self.assertEqual(rc, 1)
            self.assertFalse(payload["valid"])
            self.assertEqual(payload["classification"], "POLICY_INVALID")
            self.assertEqual(payload["violations"][0]["rule_id"], "GOV-JSON-MALFORMED")

    def test_duplicate_json_key_emits_duplicate_failure_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp).resolve()
            policy_path = repo_root / "config" / "workspace.execution-governance.json"
            policy_path.parent.mkdir(parents=True, exist_ok=True)
            policy_path.write_text(
                '{"policy_id":"workspace_execution_governance",'
                '"policy_id":"shadow_policy"}',
                encoding="utf-8",
            )
            rc, payload = self.run_main_with_result(repo_root)
            self.assertEqual(rc, 1)
            self.assertFalse(payload["valid"])
            self.assertEqual(payload["classification"], "DUPLICATE_FAILURE")
            self.assertEqual(payload["violations"][0]["rule_id"], "GOV-JSON-DUPLICATE")

    def test_valid_policy_emits_pass_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp).resolve()
            self.write_policy(repo_root, self.policy_copy())
            rc, payload = self.run_main_with_result(repo_root)
            self.assertEqual(rc, 0)
            self.assertTrue(payload["valid"])
            self.assertEqual(payload["classification"], "PASS")
            self.assertEqual(payload["violations"], [])


if __name__ == "__main__":
    unittest.main()
