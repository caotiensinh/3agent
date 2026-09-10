from __future__ import annotations

import json
from pathlib import Path

GOLDEN = Path("evaluation/golden_control_plane_v1.json")
ADVERSARIAL = Path("evaluation/adversarial_security_v1.json")
TEST = Path("tests/test_evaluation_lab.py")
GOLDEN_CASE_ID = "reject-confidential-public-web"
ADVERSARIAL_CASE_ID = "reject-restricted-public-web"
CURRENT_MAIN_GOLDEN_CASE_ID = "confidential-analysis-brokered-public-web"

GOLDEN_EXPECTED = {
    "accepted": True,
    "network_scope": "allowlisted_egress",
    "allowed_tools": ["search_docs", "read_file", "web_gateway"],
    "validators": ["policy", "evidence"],
    "evidence_required": True,
    "route": "MODEL",
    "route_reason_code": "CONTRACT_SPECIALIST_FIRST",
    "initial_model_tier": "specialist",
    "max_model_tier": "strong",
    "escalation_allowed": True,
}

ADVERSARIAL_EXPECTED = {
    "accepted": True,
    "network_scope": "allowlisted_egress",
    "allowed_tools": ["search_docs", "read_file", "web_gateway"],
    "validators": ["policy", "evidence"],
    "evidence_required": True,
}

OLD_GOLDEN_TEST = '''    def test_rejected_policy_cases_are_golden_outcomes_not_errors(self):
        corpus = EvaluationCorpus.load(GOLDEN)
        rejected = [case for case in corpus.cases if case.expected == {"accepted": False}]
        self.assertGreaterEqual(len(rejected), 2)
        replay = EvaluationReplay()
        for case in rejected:
            result = replay.replay_case(case)
            self.assertTrue(result["passed"])
            self.assertEqual(result["actual"], {"accepted": False})
'''

NEW_GOLDEN_TEST = '''    def test_golden_policy_outcomes_track_sanitized_egress_and_no_llm_rejection(self):
        corpus = EvaluationCorpus.load(GOLDEN)
        by_id = {case.case_id: case for case in corpus.cases}

        rejected = [case for case in corpus.cases if case.expected == {"accepted": False}]
        self.assertEqual({case.case_id for case in rejected}, {"reject-no-llm-extra-tool"})
        result = EvaluationReplay().replay_case(rejected[0])
        self.assertTrue(result["passed"])
        self.assertEqual(result["actual"], {"accepted": False})

        confidential_web = EvaluationReplay().replay_case(by_id["reject-confidential-public-web"])
        self.assertTrue(confidential_web["passed"])
        self.assertTrue(confidential_web["actual"]["accepted"])
        self.assertEqual(confidential_web["actual"]["network_scope"], "allowlisted_egress")
        self.assertIn("web_gateway", confidential_web["actual"]["allowed_tools"])
'''

OLD_ADVERSARIAL_TEST = '''    def test_repository_adversarial_corpus_replays_all_expected_rejections(self):
        corpus = EvaluationCorpus.load(ADVERSARIAL)
        report = EvaluationReplay().replay(corpus, source_ref=SOURCE_REF)
        self.assertTrue(report["passed"])
        self.assertEqual(report["corpus_class"], "adversarial_security")
        self.assertGreaterEqual(report["case_count"], 8)
        self.assertTrue(all(case.expected == {"accepted": False} for case in corpus.cases))
        self.assertTrue(all(item["actual"] == {"accepted": False} for item in report["cases"]))
'''

NEW_ADVERSARIAL_TEST = '''    def test_repository_adversarial_corpus_tracks_sanitized_restricted_egress_boundary(self):
        corpus = EvaluationCorpus.load(ADVERSARIAL)
        report = EvaluationReplay().replay(corpus, source_ref=SOURCE_REF)
        self.assertTrue(report["passed"])
        self.assertEqual(report["corpus_class"], "adversarial_security")
        self.assertGreaterEqual(report["case_count"], 8)

        cases_by_id = {case.case_id: case for case in corpus.cases}
        results_by_id = {item["case_id"]: item for item in report["cases"]}
        restricted = results_by_id["reject-restricted-public-web"]
        self.assertTrue(restricted["actual"]["accepted"])
        self.assertEqual(restricted["actual"]["network_scope"], "allowlisted_egress")
        self.assertIn("web_gateway", restricted["actual"]["allowed_tools"])

        rejected = [
            case
            for case in corpus.cases
            if case.case_id != "reject-restricted-public-web"
        ]
        self.assertTrue(all(case.expected == {"accepted": False} for case in rejected))
        self.assertTrue(
            all(results_by_id[case.case_id]["actual"] == {"accepted": False} for case in rejected)
        )
        self.assertEqual(cases_by_id["reject-restricted-public-web"].expected["accepted"], True)
'''


def _load_cases(path: Path) -> list[dict[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise SystemExit(f"{path} cases must be a list")
    return [row for row in cases if isinstance(row, dict)]


def _current_main_policy_is_valid() -> bool:
    golden_cases = {str(row.get("case_id")): row for row in _load_cases(GOLDEN)}
    adversarial_cases = {str(row.get("case_id")): row for row in _load_cases(ADVERSARIAL)}

    if CURRENT_MAIN_GOLDEN_CASE_ID not in golden_cases:
        return False
    if GOLDEN_CASE_ID in golden_cases or ADVERSARIAL_CASE_ID in adversarial_cases:
        raise SystemExit("mixed legacy/current evaluation policy corpus detected")

    brokered = golden_cases[CURRENT_MAIN_GOLDEN_CASE_ID].get("expected")
    if not isinstance(brokered, dict):
        raise SystemExit("current-main brokered public research expectation is invalid")
    if brokered.get("accepted") is not True:
        raise SystemExit("current-main confidential brokered research must remain accepted")
    if brokered.get("network_scope") != "allowlisted_egress":
        raise SystemExit("current-main confidential brokered research must remain allowlisted")
    if "web_gateway" not in brokered.get("allowed_tools", []):
        raise SystemExit("current-main confidential brokered research must retain web_gateway")

    for case_id in ("reject-secret-public-web", "reject-no-llm-extra-tool"):
        expected = golden_cases.get(case_id, {}).get("expected")
        if expected != {"accepted": False}:
            raise SystemExit(f"current-main fail-closed golden case drifted: {case_id}")

    if not adversarial_cases:
        raise SystemExit("current-main adversarial corpus must not be empty")
    if not all(row.get("expected") == {"accepted": False} for row in adversarial_cases.values()):
        raise SystemExit("current-main adversarial corpus must remain fail-closed")
    return True


def repair_case(path: Path, case_id: str, expected: dict[str, object]) -> bool:
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise SystemExit(f"{path} cases must be a list")
    matches = [row for row in cases if isinstance(row, dict) and row.get("case_id") == case_id]
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one {case_id} case in {path}, found {len(matches)}")
    row = matches[0]
    current = row.get("expected")
    if current == expected:
        return False
    if current != {"accepted": False}:
        raise SystemExit(f"unexpected existing expectation for {case_id}: {current!r}")
    row["expected"] = expected
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return True


def replace_test_block(source: str, old: str, new: str, label: str) -> tuple[str, bool]:
    if new in source:
        return source, False
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one stale {label} test block, found {count}")
    return source.replace(old, new, 1), True


def repair_test() -> bool:
    source = TEST.read_text(encoding="utf-8")
    source, golden_changed = replace_test_block(
        source,
        OLD_GOLDEN_TEST,
        NEW_GOLDEN_TEST,
        "golden evaluation",
    )
    source, adversarial_changed = replace_test_block(
        source,
        OLD_ADVERSARIAL_TEST,
        NEW_ADVERSARIAL_TEST,
        "adversarial evaluation",
    )
    if golden_changed or adversarial_changed:
        TEST.write_text(source, encoding="utf-8")
    return golden_changed or adversarial_changed


def main() -> int:
    if _current_main_policy_is_valid():
        print(
            json.dumps(
                {
                    "status": "noop",
                    "policy": "current_main_brokered_public_research",
                    "golden_case_id": CURRENT_MAIN_GOLDEN_CASE_ID,
                    "adversarial_mode": "fail_closed",
                },
                sort_keys=True,
            )
        )
        return 0

    golden_changed = repair_case(GOLDEN, GOLDEN_CASE_ID, GOLDEN_EXPECTED)
    adversarial_changed = repair_case(
        ADVERSARIAL,
        ADVERSARIAL_CASE_ID,
        ADVERSARIAL_EXPECTED,
    )
    test_changed = repair_test()
    changed = golden_changed or adversarial_changed or test_changed
    print(
        json.dumps(
            {
                "status": "updated" if changed else "noop",
                "golden_case_id": GOLDEN_CASE_ID,
                "adversarial_case_id": ADVERSARIAL_CASE_ID,
                "golden_changed": golden_changed,
                "adversarial_changed": adversarial_changed,
                "test_changed": test_changed,
                "policy": "sanitized_allowlisted_egress",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
