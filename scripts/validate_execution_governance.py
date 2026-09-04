#!/usr/bin/env python3
"""Validate the canonical WorkSpace execution-governance policy and session receipts."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

CANONICAL_RELATIVE = Path("config/workspace.execution-governance.json")
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class GovernanceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GovernanceError(message)


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    _require(isinstance(data, dict), f"{path}: root must be a JSON object")
    return data


def validate_policy(policy: dict[str, Any], repo_root: Path | None = None) -> None:
    canonical = policy.get("canonical_source", {})
    parallel = policy.get("parallel_execution", {})
    state = policy.get("state_machine", {})
    acceptance = policy.get("acceptance", {})
    stop_gate = policy.get("session_stop_gate", {})
    effectiveness = policy.get("session_effectiveness", {})

    _require(policy.get("policy_id") == "workspace_execution_governance", "stable policy_id required")
    _require(canonical.get("path") == CANONICAL_RELATIVE.as_posix(), "canonical path drift")
    _require(canonical.get("single_source_of_truth") is True, "single source of truth must be enabled")
    _require(canonical.get("duplicate_policy_files_forbidden") is True, "duplicate policy files must be forbidden")
    _require(parallel.get("preferred_active_lanes_min") == 10, "preferred lane minimum must be 10")
    _require(10 <= int(parallel.get("target_active_lanes", 0)) <= 20, "target lanes must be 10..20")
    _require(parallel.get("maximum_active_lanes") == 20, "maximum lanes must be 20")
    _require(parallel.get("shared_write_set_requires_single_owner") is True, "shared write sets need one owner")
    _require(state.get("successful_terminal_state") == "VERIFIED_PASS", "VERIFIED_PASS must be the only success state")
    unsuccessful = set(state.get("unsuccessful_terminal_states", []))
    _require(unsuccessful == {"BLOCKED_EXTERNAL", "HARD_FAILED", "ABORTED_BY_OPERATOR"}, "unexpected unsuccessful terminal states")
    _require(state.get("failed_retryable_must_reenter_solver_loop") is True, "retryable failure must loop")
    _require(acceptance.get("mandatory_pass_requires_executed_verifier") is True, "executed verifier required")
    _require(acceptance.get("mandatory_pass_requires_evidence") is True, "evidence required")
    _require(stop_gate.get("may_stop_false_while_retryable_failure_exists") is True, "retryable failures must prevent stop")
    thresholds = effectiveness.get("successful_thresholds", {})
    for metric in ("goal_coverage_percent", "verified_completion_percent", "evidence_coverage_percent"):
        _require(thresholds.get(metric) == 100, f"{metric} threshold must be 100")
    for metric in ("failed_required_lanes", "blocked_required_lanes", "canonical_drift_count"):
        _require(thresholds.get(metric) == 0, f"{metric} threshold must be 0")

    if repo_root is not None:
        candidates = sorted(repo_root.glob("config/workspace.execution-governance*.json"))
        _require(candidates == [repo_root / CANONICAL_RELATIVE], f"canonical policy duplication/drift: {candidates}")


def _evidence_present(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return bool(value) and all(_evidence_present(item) for item in value)
    if isinstance(value, dict):
        return bool(value)
    return False


def validate_receipt(policy: dict[str, Any], receipt: dict[str, Any]) -> None:
    required_fields = policy["session_receipt"]["required_fields"]
    missing = [field for field in required_fields if field not in receipt]
    _require(not missing, f"session receipt missing fields: {missing}")
    _require(SHA40.fullmatch(str(receipt["base_sha"])) is not None, "base_sha must be 40 lowercase hex")
    _require(SHA40.fullmatch(str(receipt["head_sha"])) is not None, "head_sha must be 40 lowercase hex")

    lanes = receipt["lanes"]
    _require(isinstance(lanes, list) and lanes, "lanes must be a non-empty list")
    max_lanes = int(policy["parallel_execution"]["maximum_active_lanes"])
    _require(len(lanes) <= max_lanes, f"lane count {len(lanes)} exceeds maximum {max_lanes}")

    if receipt["substantial"]:
        preferred = int(policy["parallel_execution"]["preferred_active_lanes_min"])
        if len(lanes) < preferred:
            limit = receipt.get("dependency_limit")
            _require(isinstance(limit, dict) and _evidence_present(limit.get("evidence")), "substantial session below 10 lanes requires dependency_limit evidence")

    required_lane_fields = policy["lane_contract"]["required_fields"]
    allowed_non_terminal = set(policy["state_machine"]["non_terminal_states"])
    success = policy["state_machine"]["successful_terminal_state"]
    unsuccessful = set(policy["state_machine"]["unsuccessful_terminal_states"])
    all_states = allowed_non_terminal | {success} | unsuccessful

    required_lanes = []
    for lane in lanes:
        missing_lane = [field for field in required_lane_fields if field not in lane]
        _require(not missing_lane, f"lane missing fields: {missing_lane}")
        _require(lane["status"] in all_states, f"lane {lane['lane_id']} has invalid status {lane['status']}")
        if lane.get("required"):
            required_lanes.append(lane)

        criteria = lane["acceptance_criteria"]
        checks = lane["verification_checks"]
        _require(isinstance(criteria, list) and criteria, f"lane {lane['lane_id']} requires acceptance criteria")
        _require(isinstance(checks, list) and checks, f"lane {lane['lane_id']} requires verification checks")
        if lane["status"] == success:
            _require(_evidence_present(lane["evidence"]), f"PASS lane {lane['lane_id']} lacks lane evidence")
            for criterion in criteria:
                if criterion.get("required", True):
                    _require(criterion.get("status") == "PASS", f"lane {lane['lane_id']} required criterion did not PASS")
                    _require(bool(str(criterion.get("verifier", "")).strip()), f"lane {lane['lane_id']} required criterion lacks verifier")
                    _require(_evidence_present(criterion.get("evidence")), f"lane {lane['lane_id']} required criterion lacks evidence")
            for check in checks:
                _require(check.get("status") == "PASS", f"lane {lane['lane_id']} verification check did not PASS")
                _require(_evidence_present(check.get("evidence")), f"lane {lane['lane_id']} verification check lacks evidence")

    _require(required_lanes, "at least one required lane is mandatory")
    outcome = receipt["outcome"]
    _require(outcome in ({success} | unsuccessful), f"session outcome {outcome} is not terminal")
    _require(not any(lane["status"] == "FAILED_RETRYABLE" for lane in lanes), "FAILED_RETRYABLE prevents session stop")

    effectiveness = receipt["effectiveness"]
    for metric in policy["session_effectiveness"]["required_metrics"]:
        _require(metric in effectiveness, f"effectiveness missing {metric}")

    completion = float(receipt["completion_percent"])
    remaining = float(receipt["remaining_percent"])
    _require(abs((completion + remaining) - 100.0) < 1e-9, "completion + remaining must equal 100")

    if outcome == success:
        _require(all(lane["status"] == success for lane in required_lanes), "all required lanes must be VERIFIED_PASS")
        thresholds = policy["session_effectiveness"]["successful_thresholds"]
        for metric, expected in thresholds.items():
            _require(effectiveness.get(metric) == expected, f"successful session requires {metric}={expected}")
        _require(completion == 100.0 and remaining == 0.0, "VERIFIED_PASS requires 100/0 completion")
        _require(not receipt["blockers"], "VERIFIED_PASS cannot contain blockers")
        if receipt["repository_mutation"]:
            commits = receipt["commits"]
            _require(isinstance(commits, list) and commits, "repository mutation requires commit evidence")
            _require(all(SHA40.fullmatch(str(sha)) for sha in commits), "commit evidence must contain 40-char SHAs")
    else:
        _require(completion < 100.0, "unsuccessful terminal state cannot claim 100% completion")
        if outcome == "BLOCKED_EXTERNAL":
            blockers = receipt["blockers"]
            _require(isinstance(blockers, list) and blockers, "BLOCKED_EXTERNAL requires blockers")
            for blocker in blockers:
                _require(blocker.get("external") is True, "BLOCKED_EXTERNAL blocker must be external")
                _require(_evidence_present(blocker.get("evidence")), "blocker requires evidence")
                _require(bool(str(blocker.get("owner", "")).strip()), "blocker requires owner")
                _require(bool(str(blocker.get("next_action", "")).strip()), "blocker requires next_action")
        elif outcome == "HARD_FAILED":
            families = receipt.get("strategy_families_used", [])
            minimum = int(policy["adaptive_solver"]["minimum_distinct_strategy_families_before_hard_failed"])
            _require(len(set(families)) >= minimum, f"HARD_FAILED requires at least {minimum} strategy families")
            _require(_evidence_present(receipt.get("failure_evidence")), "HARD_FAILED requires failure evidence")
        elif outcome == "ABORTED_BY_OPERATOR":
            _require(_evidence_present(receipt.get("operator_abort_evidence")), "operator abort requires explicit evidence")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", default=str(CANONICAL_RELATIVE))
    parser.add_argument("--session", help="Optional session receipt JSON")
    parser.add_argument("--repo-root", default=".")
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    policy_path = Path(args.policy)
    if not policy_path.is_absolute():
        policy_path = repo_root / policy_path
    try:
        policy = load_json(policy_path)
        validate_policy(policy, repo_root=repo_root)
        if args.session:
            receipt_path = Path(args.session)
            if not receipt_path.is_absolute():
                receipt_path = repo_root / receipt_path
            validate_receipt(policy, load_json(receipt_path))
    except (OSError, json.JSONDecodeError, GovernanceError) as exc:
        print(f"EXECUTION_GOVERNANCE: FAIL: {exc}", file=sys.stderr)
        return 1
    print("EXECUTION_GOVERNANCE: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
