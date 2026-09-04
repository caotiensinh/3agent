from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_execution_governance.py"
SPEC = importlib.util.spec_from_file_location("execution_governance_validator", SCRIPT)
validator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(validator)


def evidence(label: str):
    return [f"test:{label}"]


def lane(index: int, status: str = "VERIFIED_PASS"):
    return {
        "lane_id": f"L{index:02d}",
        "goal": f"goal-{index}",
        "required": True,
        "dependencies": [],
        "write_set": [f"path/{index}"],
        "acceptance_criteria": [{
            "id": f"AC-{index:02d}",
            "statement": "observable condition",
            "required": True,
            "status": "PASS" if status == "VERIFIED_PASS" else "FAIL",
            "verifier": "python -m unittest",
            "evidence": evidence(f"ac-{index}"),
        }],
        "verification_checks": [{"id": f"VC-{index:02d}", "status": "PASS" if status == "VERIFIED_PASS" else "FAIL", "evidence": evidence(f"vc-{index}")}],
        "evidence": evidence(f"lane-{index}"),
        "attempts": [{"strategy": "deterministic_verification", "result": status}],
        "status": status,
    }


def receipt(count: int = 10):
    return {
        "session_id": "S-001",
        "goal": "prove governance",
        "substantial": True,
        "repository_mutation": True,
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "outcome": "VERIFIED_PASS",
        "lanes": [lane(i) for i in range(1, count + 1)],
        "effectiveness": {
            "goal_coverage_percent": 100,
            "verified_completion_percent": 100,
            "evidence_coverage_percent": 100,
            "first_pass_yield_percent": 100,
            "rework_ratio": 0,
            "failed_required_lanes": 0,
            "blocked_required_lanes": 0,
            "canonical_drift_count": 0,
        },
        "completion_percent": 100,
        "remaining_percent": 0,
        "blockers": [],
        "commits": ["c" * 40],
    }


class ExecutionGovernanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = json.loads((ROOT / "config" / "workspace.execution-governance.json").read_text(encoding="utf-8"))

    def test_policy_is_machine_valid(self):
        validator.validate_policy(self.policy, repo_root=ROOT)

    def test_ten_lane_verified_pass_is_accepted(self):
        validator.validate_receipt(self.policy, receipt(10))

    def test_twenty_lanes_is_accepted(self):
        validator.validate_receipt(self.policy, receipt(20))

    def test_twenty_one_lanes_is_rejected(self):
        with self.assertRaises(validator.GovernanceError):
            validator.validate_receipt(self.policy, receipt(21))

    def test_false_pass_without_evidence_is_rejected(self):
        data = receipt(10)
        data["lanes"][0]["acceptance_criteria"][0]["evidence"] = []
        with self.assertRaises(validator.GovernanceError):
            validator.validate_receipt(self.policy, data)

    def test_retryable_failure_prevents_stop(self):
        data = receipt(10)
        data["lanes"][0] = lane(1, "FAILED_RETRYABLE")
        with self.assertRaises(validator.GovernanceError):
            validator.validate_receipt(self.policy, data)

    def test_blocked_external_needs_evidence(self):
        data = receipt(10)
        data["outcome"] = "BLOCKED_EXTERNAL"
        data["completion_percent"] = 90
        data["remaining_percent"] = 10
        data["lanes"][0]["status"] = "BLOCKED_EXTERNAL"
        data["blockers"] = [{"external": True, "owner": "vendor", "next_action": "restore service", "evidence": []}]
        with self.assertRaises(validator.GovernanceError):
            validator.validate_receipt(self.policy, data)

    def test_hard_failed_requires_strategy_diversity_and_evidence(self):
        data = receipt(10)
        data["outcome"] = "HARD_FAILED"
        data["completion_percent"] = 90
        data["remaining_percent"] = 10
        data["lanes"][0]["status"] = "HARD_FAILED"
        data["strategy_families_used"] = ["direct_discovery", "dependency_isolation", "deterministic_verification"]
        data["failure_evidence"] = ["log:irreducible"]
        validator.validate_receipt(self.policy, data)

    def test_duplicate_canonical_policy_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "config"
            config.mkdir()
            canonical = config / "workspace.execution-governance.json"
            canonical.write_text(json.dumps(self.policy), encoding="utf-8")
            (config / "workspace.execution-governance-copy.json").write_text(json.dumps(self.policy), encoding="utf-8")
            with self.assertRaises(validator.GovernanceError):
                validator.validate_policy(self.policy, repo_root=root)


if __name__ == "__main__":
    unittest.main()
