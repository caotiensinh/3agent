from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


TELEMETRY_SCHEMA = "workspace-inference-telemetry/v2"
REUSE_REPORT_SCHEMA = "workspace-prefix-reuse-report/v1"
REUSE_GATE_SCHEMA = "workspace-prefix-reuse-decision/v1"


@dataclass(frozen=True)
class PrefixReusePolicy:
    window_days: int = 7
    min_events: int = 20
    reuse_threshold: float = 0.30

    def validate(self) -> "PrefixReusePolicy":
        if isinstance(self.window_days, bool) or not isinstance(self.window_days, int):
            raise ValueError("window_days must be an integer")
        if not 1 <= self.window_days <= 365:
            raise ValueError("window_days must be between 1 and 365")
        if isinstance(self.min_events, bool) or not isinstance(self.min_events, int):
            raise ValueError("min_events must be an integer")
        if not 1 <= self.min_events <= 1_000_000:
            raise ValueError("min_events must be between 1 and 1000000")
        threshold = float(self.reuse_threshold)
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("reuse_threshold must be between 0 and 1")
        return PrefixReusePolicy(
            window_days=self.window_days,
            min_events=self.min_events,
            reuse_threshold=threshold,
        )


class PrefixReuseReport:
    """Reconstruct durable repeated-prefix opportunity from metadata-only JSONL.

    The existing in-process `prefix_reuse_candidate` bit is deliberately ignored.
    Reuse is recomputed from persisted metadata so process restarts do not erase the
    observation. The grouping key includes model, trust domain, template version,
    structured schema ID and stable-prefix hash; no cross-trust-domain reuse is
    inferred.
    """

    def __init__(self, telemetry_path: Path):
        self.telemetry_path = Path(telemetry_path)

    @staticmethod
    def _timestamp(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value.strip():
            return None
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _non_negative_int(value: Any) -> int | None:
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        return None

    @classmethod
    def _event_key(cls, event: dict[str, Any]) -> tuple[str, str, str, str, str] | None:
        if event.get("schema_version") != TELEMETRY_SCHEMA:
            return None
        prompt = event.get("prompt")
        if not isinstance(prompt, dict):
            return None
        model = str(event.get("model") or "").strip()
        trust_domain = str(prompt.get("trust_domain") or "").strip()
        template_version = str(prompt.get("template_version") or "").strip()
        prefix_sha256 = str(prompt.get("prefix_sha256") or "").strip().lower()
        schema_id = str(event.get("structured_schema_id") or "").strip()
        if not model or not trust_domain or not template_version:
            return None
        if not prefix_sha256.startswith("sha256:") or len(prefix_sha256) != 71:
            return None
        if any(ch not in "0123456789abcdef" for ch in prefix_sha256[7:]):
            return None
        return model, trust_domain, template_version, schema_id, prefix_sha256

    @staticmethod
    def _duration_pair(event: dict[str, Any]) -> tuple[int, int] | None:
        usage = event.get("usage")
        if not isinstance(usage, dict):
            return None
        prompt_eval = PrefixReuseReport._non_negative_int(
            usage.get("prompt_eval_duration_ns")
        )
        total = PrefixReuseReport._non_negative_int(usage.get("total_duration_ns"))
        if prompt_eval is None or total is None or total <= 0 or prompt_eval > total:
            return None
        return prompt_eval, total

    @staticmethod
    def _prefix_chars(event: dict[str, Any]) -> int | None:
        prompt = event.get("prompt")
        if not isinstance(prompt, dict):
            return None
        return PrefixReuseReport._non_negative_int(prompt.get("stable_prefix_chars"))

    @staticmethod
    def _percentile(values: list[int], percentile: float) -> int | None:
        if not values:
            return None
        ordered = sorted(values)
        index = max(
            0,
            min(
                len(ordered) - 1,
                int((len(ordered) - 1) * percentile + 0.999999),
            ),
        )
        return ordered[index]

    @staticmethod
    def _rate(numerator: int, denominator: int) -> float:
        if denominator <= 0:
            return 0.0
        return round(numerator / denominator, 6)

    @staticmethod
    def _opaque_domain(value: str) -> str:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return "sha256:" + digest

    @staticmethod
    def _segment(rows: dict[str, dict[str, int]]) -> dict[str, dict[str, float | int]]:
        output: dict[str, dict[str, float | int]] = {}
        for name in sorted(rows):
            total = rows[name]["events"]
            repeated = rows[name]["repeated"]
            output[name] = {
                "events": total,
                "repeated_prefix_events": repeated,
                "reuse_opportunity_rate": PrefixReuseReport._rate(repeated, total),
            }
        return output

    @staticmethod
    def _decision(
        *,
        eligible_events: int,
        reuse_rate: float,
        prompt_eval_share: float | None,
        policy: PrefixReusePolicy,
    ) -> dict[str, Any]:
        data_sufficient = eligible_events >= policy.min_events
        reuse_gate_passed = bool(
            data_sufficient and reuse_rate >= policy.reuse_threshold
        )
        prefill_dominates = bool(
            prompt_eval_share is not None and prompt_eval_share >= 0.5
        )

        if not data_sufficient:
            decision = "INSUFFICIENT_REPRESENTATIVE_DATA"
            allowed_action = "collect_more_metadata"
        elif not reuse_gate_passed:
            decision = "REDESIGN_PROMPT_LAYOUT_FIRST"
            allowed_action = "prompt_layout_optimization"
        elif prefill_dominates:
            decision = "SERVING_CACHE_BENCHMARK_ELIGIBLE"
            allowed_action = "benchmark_serving_candidate"
        else:
            decision = "REUSE_HIGH_PREFILL_NOT_DOMINANT"
            allowed_action = "continue_measurement"

        return {
            "schema_version": REUSE_GATE_SCHEMA,
            "data_sufficient": data_sufficient,
            "min_events": policy.min_events,
            "reuse_threshold": policy.reuse_threshold,
            "reuse_gate_passed": reuse_gate_passed,
            "prefill_dominance_rule": "prompt_eval_duration_share>=0.5",
            "prefill_dominates": prefill_dominates,
            "decision": decision,
            "allowed_action": allowed_action,
            "production_serving_change_authorized": False,
            "backend_cache_hit_claimed": False,
        }

    def snapshot(
        self,
        *,
        policy: PrefixReusePolicy | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        resolved = (policy or PrefixReusePolicy()).validate()
        end = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        start = end - timedelta(days=resolved.window_days)

        total_lines = 0
        malformed_json = 0
        invalid_metadata = 0
        invalid_timestamp = 0
        out_of_window = 0
        future_events = 0
        eligible_events = 0
        repeated_events = 0
        distinct_keys: set[tuple[str, str, str, str, str]] = set()
        key_counts: dict[tuple[str, str, str, str, str], int] = defaultdict(int)
        by_trust: dict[str, dict[str, int]] = defaultdict(
            lambda: {"events": 0, "repeated": 0}
        )
        by_model: dict[str, dict[str, int]] = defaultdict(
            lambda: {"events": 0, "repeated": 0}
        )
        prefix_chars: list[int] = []
        prompt_eval_ns = 0
        measured_total_ns = 0
        duration_events = 0

        if self.telemetry_path.exists():
            with self.telemetry_path.open("r", encoding="utf-8") as handle:
                for raw in handle:
                    line = raw.strip()
                    if not line:
                        continue
                    total_lines += 1
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        malformed_json += 1
                        continue
                    if not isinstance(event, dict):
                        invalid_metadata += 1
                        continue
                    timestamp = self._timestamp(event.get("timestamp"))
                    if timestamp is None:
                        invalid_timestamp += 1
                        continue
                    if timestamp > end:
                        future_events += 1
                        continue
                    if timestamp < start:
                        out_of_window += 1
                        continue
                    key = self._event_key(event)
                    if key is None:
                        invalid_metadata += 1
                        continue

                    eligible_events += 1
                    model, trust_domain, _, _, _ = key
                    repeated = key_counts[key] > 0
                    key_counts[key] += 1
                    distinct_keys.add(key)
                    if repeated:
                        repeated_events += 1
                    trust_fingerprint = self._opaque_domain(trust_domain)
                    by_trust[trust_fingerprint]["events"] += 1
                    by_model[model]["events"] += 1
                    if repeated:
                        by_trust[trust_fingerprint]["repeated"] += 1
                        by_model[model]["repeated"] += 1

                    chars = self._prefix_chars(event)
                    if chars is not None:
                        prefix_chars.append(chars)
                    durations = self._duration_pair(event)
                    if durations is not None:
                        prompt_eval, total = durations
                        prompt_eval_ns += prompt_eval
                        measured_total_ns += total
                        duration_events += 1

        repeat_key_count = sum(1 for count in key_counts.values() if count >= 2)
        reuse_rate = self._rate(repeated_events, eligible_events)
        prompt_eval_share = (
            None
            if measured_total_ns <= 0
            else round(prompt_eval_ns / measured_total_ns, 6)
        )
        decision = self._decision(
            eligible_events=eligible_events,
            reuse_rate=reuse_rate,
            prompt_eval_share=prompt_eval_share,
            policy=resolved,
        )
        average_chars = (
            None if not prefix_chars else round(sum(prefix_chars) / len(prefix_chars), 3)
        )

        return {
            "schema_version": REUSE_REPORT_SCHEMA,
            "window": {
                "days": resolved.window_days,
                "start": start.isoformat(),
                "end": end.isoformat(),
            },
            "observation": {
                "eligible_events": eligible_events,
                "distinct_prefix_keys": len(distinct_keys),
                "repeated_prefix_keys": repeat_key_count,
                "repeated_prefix_events": repeated_events,
                "reuse_opportunity_rate": reuse_rate,
                "backend_cache_hits": None,
                "backend_cache_hit_metric_available": False,
            },
            "prefix_size_chars": {
                "events_with_size": len(prefix_chars),
                "average": average_chars,
                "p50": self._percentile(prefix_chars, 0.50),
                "p95": self._percentile(prefix_chars, 0.95),
                "maximum": max(prefix_chars) if prefix_chars else None,
            },
            "prefill": {
                "duration_events": duration_events,
                "prompt_eval_duration_ns": prompt_eval_ns,
                "measured_total_duration_ns": measured_total_ns,
                "prompt_eval_duration_share": prompt_eval_share,
            },
            "segments": {
                "by_trust_domain_fingerprint": self._segment(by_trust),
                "by_model": self._segment(by_model),
            },
            "data_quality": {
                "total_nonempty_lines": total_lines,
                "malformed_json_lines": malformed_json,
                "invalid_metadata_events": invalid_metadata,
                "invalid_timestamp_events": invalid_timestamp,
                "out_of_window_events": out_of_window,
                "future_events": future_events,
            },
            "decision_gate": decision,
            "privacy": {
                "allowlisted_metadata_only": True,
                "raw_prompt_required": False,
                "raw_response_required": False,
                "raw_tool_output_required": False,
                "raw_content_emitted": False,
                "prefix_text_emitted": False,
                "prefix_hashes_emitted": False,
                "raw_trust_domain_emitted": False,
                "trust_domain_isolation": True,
            },
        }
