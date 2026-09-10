#!/usr/bin/env python3
"""Validate the canonical WorkSpace execution-governance policy and session receipts."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

CANONICAL_RELATIVE = Path("config/workspace.execution-governance.json")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
PRODUCTION_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".rs",
    ".java",
    ".cs",
    ".sh",
    ".ps1",
    ".yml",
    ".yaml",
    ".json",
}


class GovernanceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GovernanceError(message)


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    _require(isinstance(data, dict), f"{path}: root must be a JSON object")
    return data


def _git_output(repo_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown git failure"
        raise GovernanceError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout


def _is_git_repo(repo_root: Path) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--is-inside-work-tree"],
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.returncode == 0 and completed.stdout.strip() == "true"


def _is_under_protected_root(path: str, roots: list[str]) -> bool:
    candidate = PurePosixPath(path)
    return any(candidate == PurePosixPath(root) or PurePosixPath(root) in candidate.parents for root in roots)


def _new_parallel_implementation_paths(policy: dict[str, Any], repo_root: Path) -> list[str]:
    canonical = policy["canonical_implementation"]
    baseline = str(canonical["legacy_baseline_commit"])
    _require(SHA40.fullmatch(baseline) is not None, "legacy baseline commit must be a 40-char lowercase SHA")

    _git_output(repo_root, "cat-file", "-e", f"{baseline}^{{commit}}")
    changed = _git_output(repo_root, "diff", "--name-status", "--diff-filter=A", f"{baseline}..HEAD", "--")
    protected_roots = [str(root).strip("/") for root in canonical["protected_roots"]]
    patterns = [re.compile(pattern, re.IGNORECASE) for pattern in canonical["forbidden_new_file_name_patterns"]]
    exceptions = {str(path) for path in canonical.get("explicit_compatibility_exceptions", [])}

    violations: list[str] = []
    for raw_line in changed.splitlines():
        parts = raw_line.split("\t")
        if len(parts) < 2:
            continue
        path = parts[-1]
        if path in exceptions or not _is_under_protected_root(path, protected_roots):
            continue
        candidate = PurePosixPath(path)
        if candidate.suffix.lower() not in PRODUCTION_EXTENSIONS:
            continue
        if any(pattern.search(candidate.stem) for pattern in patterns):
            violations.append(path)
    return sorted(set(violations))


def validate_policy(policy: dict[str, Any], repo_root: Path | None = None) -> None:
    canonical = policy.get("canonical_source", {})
    parallel = policy.get("parallel_execution", {})
    lane_contract = policy.get("lane_contract", {})
    failure = policy.get("failure_handling", {})
    canonical_impl = policy.get("canonical_implementation", {})
    integration = policy.get("main_integration", {})
    state = policy.get("state_machine", {})
    acceptance = policy.get("acceptance", {})
    stop_gate = policy.get("session_stop_gate", {})
    effectiveness = policy.get("session_effectiveness", {})

    _require(policy.get("policy_id") == "workspace_execution_governance", "stable policy_id required")
    _require(canonical.get("path") == CANONICAL_RELATIVE.as_posix(), "canonical path drift")
    _require(canonical.get("single_source_of_truth") is True, "single source of truth must be enabled")
    _require(canonical.get("duplicate_policy_files_forbidden") is True, "duplicate policy files must be forbidden")

    _require(parallel.get("preferred_active_lanes_min") == 20, "preferred lane minimum must be 20")
    _require(parallel.get("target_active_lanes") == 20, "target lanes must be 20")
    _require(parallel.get("maximum_active_lanes") == 20, "maximum lanes must be 20")
    _require(parallel.get("lanes_must_be_independent_or_dependency_isolated") is True, "lanes must be independent or dependency isolated")
    _require(parallel.get("shared_write_set_requires_single_owner") is True, "shared write sets need one owner")
    _require(parallel.get("overlapping_lane_write_sets_forbidden") is True, "overlapping lane write sets must be forbidden")
    _require(parallel.get("duplicate_functional_authority_across_lanes_forbidden") is True, "duplicate functional authority must be forbidden")
    _require(parallel.get("canonical_target_requires_single_writer_lane") is True, "canonical target requires one writer")

    required_lane_fields = set(lane_contract.get("required_fields", []))
    _require("functional_authority" in required_lane_fields, "lane contract must declare functional_authority")
    _require("attempts" in required_lane_fields, "lane contract must declare attempts")
    _require(set(lane_contract.get("attempt_outcomes", [])) == {"PASS", "FAIL"}, "attempt outcomes must be PASS/FAIL")
    _require(lane_contract.get("later_attempt_after_fail_requires_prior_failure_diagnosis_ref") is True, "rerun must reference prior failure diagnosis")

    _require(failure.get("failed_verification_requires_log_inspection_before_edit_or_rerun") is True, "failed verification must require log inspection")
    _require(failure.get("blind_rerun_forbidden") is True, "blind rerun must be forbidden")
    _require(failure.get("edit_before_failure_evidence_review_forbidden") is True, "editing before failure evidence review must be forbidden")
    _require(failure.get("same_attempt_rerun_without_new_evidence_forbidden") is True, "same attempt rerun without evidence must be forbidden")
    required_sequence = failure.get("required_sequence", [])
    _require(required_sequence.index("read_failed_logs") < required_sequence.index("record_diagnosis"), "logs must be read before diagnosis")
    _require(required_sequence.index("record_diagnosis") < required_sequence.index("edit_if_justified"), "diagnosis must precede edits")
    _require(required_sequence.index("record_diagnosis") < required_sequence.index("rerun_targeted_verifier"), "diagnosis must precede rerun")

    _require(canonical_impl.get("single_functional_authority_required") is True, "single functional authority must be required")
    _require(canonical_impl.get("new_version_sibling_files_forbidden") is True, "new version sibling files must be forbidden")
    _require(canonical_impl.get("canonical_merge_required_before_main") is True, "canonical reconciliation before main must be required")
    _require(canonical_impl.get("transient_lane_artifacts_must_be_removed_before_main") is True, "transient lane artifacts must be removed before main")
    _require(integration.get("merge_requires_canonical_reconciliation") is True, "main merge must require canonical reconciliation")
    _require(integration.get("merge_requires_no_new_versioned_functional_files") is True, "main merge must reject new versioned functional files")
    _require(integration.get("merge_requires_governance_validator_pass") is True, "main merge must require governance validation")

    _require(state.get("successful_terminal_state") == "VERIFIED_PASS", "VERIFIED_PASS must be the only success state")
    unsuccessful = set(state.get("unsuccessful_terminal_states", []))
    _require(unsuccessful == {"BLOCKED_EXTERNAL", "HARD_FAILED", "ABORTED_BY_OPERATOR"}, "unexpected unsuccessful terminal states")
    _require(state.get("failed_retryable_must_reenter_solver_loop") is True, "retryable failure must loop")
    _require(acceptance.get("mandatory_pass_requires_executed_verifier") is True, "executed verifier required")
    _require(acceptance.get("mandatory_pass_requires_evidence") is True, "evidence required")
    _require(acceptance.get("explicit_pass_or_fail_status_required") is True, "explicit PASS/FAIL status must be required")
    _require(stop_gate.get("may_stop_false_while_retryable_failure_exists") is True, "retryable failures must prevent stop")
    thresholds = effectiveness.get("successful_thresholds", {})
    for metric in ("goal_coverage_percent", "verified_completion_percent", "evidence_coverage_percent"):
        _require(thresholds.get(metric) == 100, f"{metric} threshold must be 100")
    for metric in (
        "failed_required_lanes",
        "blocked_required_lanes",
        "canonical_drift_count",
        "new_parallel_implementation_count",
        "stale_reference_count",
        "transient_lane_artifact_count",
    ):
        _require(thresholds.get(metric) == 0, f"{metric} threshold must be 0")

    if repo_root is not None:
        candidates = sorted(repo_root.glob("config/workspace.execution-governance*.json"))
        _require(candidates == [repo_root / CANONICAL_RELATIVE], f"canonical policy duplication/drift: {candidates}")
        if _is_git_repo(repo_root):
            violations = _new_parallel_implementation_paths(policy, repo_root)
            _require(not violations, f"new parallel/versioned implementation files are forbidden: {violations}")


def _evidence_present(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return bool(value) and all(_evidence_present(item) for item in value)
    if isinstance(value, dict):
        return bool(value)
    return False


def _normalise_write_path(value: Any) -> str:
    text = str(value).strip().replace("\\", "/").strip("/")
    return text


def _write_paths_overlap(left: str, right: str) -> bool:
    if not left or not right:
        return False
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def _validate_lane_independence(lanes: list[dict[str, Any]]) -> None:
    authorities: dict[str, str] = {}
    owned_paths: list[tuple[str, str]] = []
    for lane in lanes:
        lane_id = str(lane.get("lane_id", "")).strip()
        authority = str(lane.get("functional_authority", "")).strip()
        _require(lane_id, "lane_id must be non-empty")
        _require(authority, f"lane {lane_id} requires functional_authority")
        if authority in authorities:
            raise GovernanceError(
                f"functional authority {authority!r} is owned by both {authorities[authority]} and {lane_id}"
            )
        authorities[authority] = lane_id

        write_set = lane.get("write_set")
        _require(isinstance(write_set, list), f"lane {lane_id} write_set must be a list")
        for raw_path in write_set:
            path = _normalise_write_path(raw_path)
            _require(path, f"lane {lane_id} contains an empty write_set entry")
            for prior_path, prior_lane in owned_paths:
                if _write_paths_overlap(path, prior_path):
                    raise GovernanceError(
                        f"write-set overlap: lane {lane_id} path {path!r} conflicts with lane {prior_lane} path {prior_path!r}"
                    )
            owned_paths.append((path, lane_id))


def _validate_attempts(policy: dict[str, Any], lane: dict[str, Any]) -> None:
    lane_id = str(lane["lane_id"])
    attempts = lane.get("attempts")
    _require(isinstance(attempts, list), f"lane {lane_id} attempts must be a list")
    required = policy["lane_contract"]["attempt_required_fields"]
    failed_required = policy["lane_contract"]["failed_attempt_required_fields"]
    allowed_outcomes = set(policy["lane_contract"]["attempt_outcomes"])
    seen_attempt_ids: set[str] = set()

    previous: dict[str, Any] | None = None
    for attempt in attempts:
        _require(isinstance(attempt, dict), f"lane {lane_id} attempt must be an object")
        missing = [field for field in required if field not in attempt]
        _require(not missing, f"lane {lane_id} attempt missing fields: {missing}")
        attempt_id = str(attempt["attempt_id"]).strip()
        _require(attempt_id and attempt_id not in seen_attempt_ids, f"lane {lane_id} attempt_id must be unique and non-empty")
        seen_attempt_ids.add(attempt_id)
        outcome = attempt["outcome"]
        _require(outcome in allowed_outcomes, f"lane {lane_id} attempt {attempt_id} outcome must be PASS/FAIL")
        _require(_evidence_present(attempt.get("verification_evidence")), f"lane {lane_id} attempt {attempt_id} lacks verification evidence")

        if previous is not None and previous.get("outcome") == "FAIL":
            prior_ref = str(attempt.get("prior_failure_diagnosis_ref", "")).strip()
            _require(
                prior_ref == str(previous["attempt_id"]),
                f"lane {lane_id} attempt {attempt_id} must reference prior failed attempt diagnosis {previous['attempt_id']}",
            )
            if attempt.get("strategy_family") == previous.get("strategy_family"):
                _require(
                    bool(str(attempt.get("rerun_justification", "")).strip()),
                    f"lane {lane_id} attempt {attempt_id} repeats a strategy without rerun_justification",
                )

        if outcome == "FAIL":
            missing_failed = [field for field in failed_required if field not in attempt]
            _require(not missing_failed, f"lane {lane_id} failed attempt {attempt_id} missing failure fields: {missing_failed}")
            for field in failed_required:
                _require(_evidence_present(attempt.get(field)), f"lane {lane_id} failed attempt {attempt_id} lacks {field}")

        previous = attempt

    if lane["status"] == policy["state_machine"]["successful_terminal_state"]:
        _require(attempts, f"PASS lane {lane_id} requires at least one executed attempt")
        _require(attempts[-1].get("outcome") == "PASS", f"PASS lane {lane_id} must end with a PASS attempt")
    if lane["status"] == "HARD_FAILED":
        _require(attempts and attempts[-1].get("outcome") == "FAIL", f"HARD_FAILED lane {lane_id} must end with a failed attempt")


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
        target = int(policy["parallel_execution"]["target_active_lanes"])
        if len(lanes) < target:
            limit = receipt.get("dependency_limit")
            _require(
                isinstance(limit, dict) and _evidence_present(limit.get("evidence")),
                f"substantial session below {target} lanes requires dependency_limit evidence",
            )

    _validate_lane_independence(lanes)

    required_lane_fields = policy["lane_contract"]["required_fields"]
    criterion_fields = policy["lane_contract"]["acceptance_criterion_required_fields"]
    verification_fields = policy["lane_contract"]["verification_check_required_fields"]
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
        for criterion in criteria:
            missing_criterion = [field for field in criterion_fields if field not in criterion]
            _require(not missing_criterion, f"lane {lane['lane_id']} acceptance criterion missing fields: {missing_criterion}")
            _require(criterion.get("status") in {"PASS", "FAIL", "PENDING"}, f"lane {lane['lane_id']} has invalid acceptance status")
        for check in checks:
            missing_check = [field for field in verification_fields if field not in check]
            _require(not missing_check, f"lane {lane['lane_id']} verification check missing fields: {missing_check}")
            _require(check.get("status") in {"PASS", "FAIL", "PENDING"}, f"lane {lane['lane_id']} has invalid verification status")

        _validate_attempts(policy, lane)

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
            _require(
                _evidence_present(receipt.get("canonical_reconciliation_evidence")),
                "repository mutation PASS requires canonical_reconciliation_evidence",
            )
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
    except (OSError, json.JSONDecodeError, GovernanceError, ValueError) as exc:
        print(f"EXECUTION_GOVERNANCE: FAIL: {exc}", file=sys.stderr)
        return 1
    print("EXECUTION_GOVERNANCE: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
