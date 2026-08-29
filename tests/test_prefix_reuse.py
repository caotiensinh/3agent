import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from three_agent.cli import main
from three_agent.prefix_reuse import PrefixReusePolicy, PrefixReuseReport


def event(
    timestamp: datetime,
    *,
    prefix: str,
    trust: str = "confidential:test",
    model: str = "qwen-test",
    template: str = "workspace.prompt.v1",
    schema_id: str = "schema-v1",
    prompt_eval_ns: int = 700,
    total_ns: int = 1000,
    prefix_chars: int = 4000,
    process_flag: bool = False,
):
    return {
        "schema_version": "workspace-inference-telemetry/v2",
        "timestamp": timestamp.isoformat(),
        "model": model,
        "structured": True,
        "structured_schema_id": schema_id,
        "prefix_reuse_candidate": process_flag,
        "prompt": {
            "template_version": template,
            "trust_domain": trust,
            "prefix_sha256": "sha256:" + prefix * 64,
            "stable_prefix_chars": prefix_chars,
            "stable_prefix_bytes": prefix_chars,
            "dynamic_suffix_chars": 100,
            "dynamic_suffix_bytes": 100,
        },
        "usage": {
            "prompt_eval_count": 100,
            "eval_count": 20,
            "total_duration_ns": total_ns,
            "prompt_eval_duration_ns": prompt_eval_ns,
        },
    }


def write_rows(path: Path, rows):
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            if isinstance(row, str):
                handle.write(row + "\n")
            else:
                handle.write(json.dumps(row) + "\n")


class PrefixReuseReportTests(unittest.TestCase):
    def test_reconstructs_reuse_across_process_boundaries_instead_of_trusting_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = datetime(2026, 8, 29, 12, tzinfo=timezone.utc)
            path = Path(tmp) / "inference.jsonl"
            write_rows(
                path,
                [
                    event(now - timedelta(hours=4), prefix="a", process_flag=False),
                    event(now - timedelta(hours=3), prefix="a", process_flag=False),
                    event(now - timedelta(hours=2), prefix="a", process_flag=False),
                    event(now - timedelta(hours=1), prefix="b", process_flag=False),
                ],
            )
            report = PrefixReuseReport(path).snapshot(
                policy=PrefixReusePolicy(window_days=7, min_events=1), now=now
            )
            observation = report["observation"]
            self.assertEqual(observation["eligible_events"], 4)
            self.assertEqual(observation["distinct_prefix_keys"], 2)
            self.assertEqual(observation["repeated_prefix_events"], 2)
            self.assertEqual(observation["reuse_opportunity_rate"], 0.5)
            self.assertIsNone(observation["backend_cache_hits"])

    def test_same_prefix_hash_never_crosses_trust_domain_boundary_or_leaks_domain(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = datetime(2026, 8, 29, 12, tzinfo=timezone.utc)
            path = Path(tmp) / "inference.jsonl"
            write_rows(
                path,
                [
                    event(now - timedelta(minutes=2), prefix="c", trust="tenant-a-secret"),
                    event(now - timedelta(minutes=1), prefix="c", trust="tenant-b-secret"),
                ],
            )
            report = PrefixReuseReport(path).snapshot(
                policy=PrefixReusePolicy(min_events=1), now=now
            )
            self.assertEqual(report["observation"]["repeated_prefix_events"], 0)
            segments = report["segments"]["by_trust_domain_fingerprint"]
            self.assertEqual(len(segments), 2)
            self.assertTrue(all(key.startswith("sha256:") for key in segments))
            serialized = json.dumps(report)
            self.assertNotIn("tenant-a-secret", serialized)
            self.assertNotIn("tenant-b-secret", serialized)
            self.assertFalse(report["privacy"]["raw_trust_domain_emitted"])

    def test_template_and_schema_are_part_of_reuse_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = datetime(2026, 8, 29, 12, tzinfo=timezone.utc)
            path = Path(tmp) / "inference.jsonl"
            write_rows(
                path,
                [
                    event(now - timedelta(minutes=3), prefix="d", template="v1", schema_id="s1"),
                    event(now - timedelta(minutes=2), prefix="d", template="v2", schema_id="s1"),
                    event(now - timedelta(minutes=1), prefix="d", template="v1", schema_id="s2"),
                ],
            )
            report = PrefixReuseReport(path).snapshot(
                policy=PrefixReusePolicy(min_events=1), now=now
            )
            self.assertEqual(report["observation"]["distinct_prefix_keys"], 3)
            self.assertEqual(report["observation"]["repeated_prefix_events"], 0)

    def test_low_reuse_requests_prompt_layout_work_before_cache_infrastructure(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = datetime(2026, 8, 29, 12, tzinfo=timezone.utc)
            path = Path(tmp) / "inference.jsonl"
            write_rows(
                path,
                [
                    event(now - timedelta(minutes=index + 1), prefix=hex(index)[2:3])
                    for index in range(10)
                ],
            )
            report = PrefixReuseReport(path).snapshot(
                policy=PrefixReusePolicy(min_events=5, reuse_threshold=0.30), now=now
            )
            gate = report["decision_gate"]
            self.assertEqual(gate["decision"], "REDESIGN_PROMPT_LAYOUT_FIRST")
            self.assertEqual(gate["allowed_action"], "prompt_layout_optimization")
            self.assertFalse(gate["production_serving_change_authorized"])

    def test_high_reuse_and_prefill_dominance_only_allows_serving_benchmark(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = datetime(2026, 8, 29, 12, tzinfo=timezone.utc)
            path = Path(tmp) / "inference.jsonl"
            rows = [
                event(
                    now - timedelta(minutes=index + 1),
                    prefix="e",
                    prompt_eval_ns=800,
                    total_ns=1000,
                )
                for index in range(8)
            ]
            write_rows(path, rows)
            report = PrefixReuseReport(path).snapshot(
                policy=PrefixReusePolicy(min_events=5, reuse_threshold=0.30), now=now
            )
            gate = report["decision_gate"]
            self.assertTrue(gate["reuse_gate_passed"])
            self.assertTrue(gate["prefill_dominates"])
            self.assertEqual(gate["decision"], "SERVING_CACHE_BENCHMARK_ELIGIBLE")
            self.assertEqual(gate["allowed_action"], "benchmark_serving_candidate")
            self.assertFalse(gate["production_serving_change_authorized"])

    def test_small_sample_is_insufficient_even_when_reuse_is_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = datetime(2026, 8, 29, 12, tzinfo=timezone.utc)
            path = Path(tmp) / "inference.jsonl"
            write_rows(
                path,
                [
                    event(now - timedelta(minutes=2), prefix="f"),
                    event(now - timedelta(minutes=1), prefix="f"),
                ],
            )
            report = PrefixReuseReport(path).snapshot(
                policy=PrefixReusePolicy(min_events=20), now=now
            )
            self.assertEqual(
                report["decision_gate"]["decision"],
                "INSUFFICIENT_REPRESENTATIVE_DATA",
            )

    def test_malformed_out_of_window_future_and_sensitive_extras_do_not_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = datetime(2026, 8, 29, 12, tzinfo=timezone.utc)
            path = Path(tmp) / "inference.jsonl"
            sensitive = event(now - timedelta(hours=1), prefix="1")
            sensitive["raw_prompt"] = "TOP-SECRET-PROMPT"
            sensitive["response"] = "TOP-SECRET-RESPONSE"
            write_rows(
                path,
                [
                    sensitive,
                    "{broken-json",
                    event(now - timedelta(days=20), prefix="2"),
                    event(now + timedelta(hours=1), prefix="3"),
                    {"schema_version": "wrong", "timestamp": now.isoformat()},
                ],
            )
            report = PrefixReuseReport(path).snapshot(
                policy=PrefixReusePolicy(window_days=7, min_events=1), now=now
            )
            quality = report["data_quality"]
            self.assertEqual(quality["malformed_json_lines"], 1)
            self.assertEqual(quality["out_of_window_events"], 1)
            self.assertEqual(quality["future_events"], 1)
            self.assertEqual(quality["invalid_metadata_events"], 1)
            serialized = json.dumps(report)
            self.assertNotIn("TOP-SECRET-PROMPT", serialized)
            self.assertNotIn("TOP-SECRET-RESPONSE", serialized)
            self.assertFalse(report["privacy"]["raw_prompt_required"])
            self.assertFalse(report["privacy"]["raw_content_emitted"])

    def test_prefill_share_and_prefix_size_summary_are_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = datetime(2026, 8, 29, 12, tzinfo=timezone.utc)
            path = Path(tmp) / "inference.jsonl"
            write_rows(
                path,
                [
                    event(now - timedelta(minutes=3), prefix="4", prefix_chars=1000, prompt_eval_ns=300, total_ns=1000),
                    event(now - timedelta(minutes=2), prefix="4", prefix_chars=3000, prompt_eval_ns=600, total_ns=1000),
                    event(now - timedelta(minutes=1), prefix="5", prefix_chars=9000, prompt_eval_ns=600, total_ns=1000),
                ],
            )
            report = PrefixReuseReport(path).snapshot(
                policy=PrefixReusePolicy(min_events=1), now=now
            )
            self.assertEqual(report["prefill"]["prompt_eval_duration_share"], 0.5)
            self.assertEqual(report["prefix_size_chars"]["p50"], 3000)
            self.assertEqual(report["prefix_size_chars"]["p95"], 9000)
            self.assertEqual(report["prefix_size_chars"]["maximum"], 9000)

    def test_cli_reads_explicit_telemetry_without_initializing_workflow_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "inference.jsonl"
            now = datetime.now(timezone.utc)
            write_rows(path, [event(now - timedelta(minutes=1), prefix="6")])
            rc = main(
                [
                    "reuse-report",
                    "--telemetry",
                    str(path),
                    "--days",
                    "7",
                    "--min-events",
                    "1",
                ]
            )
            self.assertEqual(rc, 0)

    def test_invalid_policy_fails_closed(self):
        with self.assertRaises(ValueError):
            PrefixReusePolicy(window_days=0).validate()
        with self.assertRaises(ValueError):
            PrefixReusePolicy(min_events=0).validate()
        with self.assertRaises(ValueError):
            PrefixReusePolicy(reuse_threshold=1.1).validate()


if __name__ == "__main__":
    unittest.main()
