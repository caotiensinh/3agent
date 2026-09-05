from __future__ import annotations

import json
from pathlib import Path

CORPUS = Path("evaluation/golden_control_plane_v1.json")
TEST = Path("tests/test_evaluation_lab.py")
CASE_ID = "reject-confidential-public-web"

EXPECTED = {
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

OLD_TEST = '''    def test_rejected_policy_cases_are_golden_outcomes_not_errors(self):
        corpus = EvaluationCorpus.load(GOLDEN)
        rejected = [case for case in corpus.cases if case.expected == {"accepted": False}]
        self.assertGreaterEqual(len(rejected), 2)
        replay = EvaluationReplay()
        for case in rejected:
            result = replay.replay_case(case)
            self.assertTrue(result["passed"])
            self.assertEqual(result["actual"], {"accepted": False})
'''

NEW_TEST = '''    def test_golden_policy_outcomes_track_sanitized_egress_and_no_llm_rejection(self):
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


def repair_corpus() -> bool:
    payload = json.loads(CORPUS.read_text(encoding="utf-8"))
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise SystemExit("golden corpus cases must be a list")
    matches = [row for row in cases if isinstance(row, dict) and row.get("case_id") == CASE_ID]
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one {CASE_ID} case, found {len(matches)}")
    row = matches[0]
    current = row.get("expected")
    if current == EXPECTED:
        return False
    if current != {"accepted": False}:
        raise SystemExit(f"unexpected existing expectation for {CASE_ID}: {current!r}")
    row["expected"] = EXPECTED
    CORPUS.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return True


def repair_test() -> bool:
    source = TEST.read_text(encoding="utf-8")
    if NEW_TEST in source:
        return False
    count = source.count(OLD_TEST)
    if count != 1:
        raise SystemExit(f"expected exactly one stale evaluation test block, found {count}")
    TEST.write_text(source.replace(OLD_TEST, NEW_TEST, 1), encoding="utf-8")
    return True


def main() -> int:
    corpus_changed = repair_corpus()
    test_changed = repair_test()
    print(
        json.dumps(
            {
                "status": "updated" if corpus_changed or test_changed else "noop",
                "case_id": CASE_ID,
                "corpus_changed": corpus_changed,
                "test_changed": test_changed,
                "policy": "sanitized_allowlisted_egress",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
