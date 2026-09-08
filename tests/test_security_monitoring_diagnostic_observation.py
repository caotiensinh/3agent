import unittest
from dataclasses import replace

from three_agent.security_monitoring.diagnostic_observation import (
    MAX_DIAGNOSTIC_PAYLOAD_BYTES,
    DiagnosticObservation,
    DiagnosticObservationError,
)


def _sha(char: str) -> str:
    return "sha256:" + (char * 64)


def _observation(**overrides: object) -> DiagnosticObservation:
    payload = '{"latency_ms":12,"reachable":true}'
    values: dict[str, object] = {
        "source_tool": "network_quality_probe",
        "source_capability": "icmp_echo",
        "task_ref_sha256": _sha("1"),
        "request_ref_sha256": _sha("2"),
        "observed_at": "2026-09-08T14:00:00Z",
        "status": "succeeded",
        "summary": "Bounded network quality observation",
        "payload": payload,
        "content_type": "application/json",
        "original_payload_bytes": len(payload.encode("utf-8")),
    }
    values.update(overrides)
    return DiagnosticObservation(**values)  # type: ignore[arg-type]


class DiagnosticObservationTests(unittest.TestCase):
    def test_observation_is_advisory_and_fingerprint_is_deterministic(self) -> None:
        first = _observation()
        second_payload = '{"reachable":true,"latency_ms":12}'
        second = _observation(
            payload=second_payload,
            original_payload_bytes=len(second_payload.encode("utf-8")),
        )

        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.observation_id, second.observation_id)
        self.assertEqual(first.authority, "advisory")
        self.assertFalse(first.automatic_action_allowed)

    def test_observation_fingerprint_changes_with_lineage_mutation(self) -> None:
        baseline = _observation()
        changed = _observation(request_ref_sha256=_sha("3"))

        self.assertNotEqual(baseline.fingerprint, changed.fingerprint)

    def test_payload_boundary_accepts_limit_and_rejects_oversize(self) -> None:
        at_limit = "x" * MAX_DIAGNOSTIC_PAYLOAD_BYTES
        accepted = _observation(
            payload=at_limit,
            content_type="text/plain",
            original_payload_bytes=MAX_DIAGNOSTIC_PAYLOAD_BYTES,
        )
        self.assertEqual(
            accepted.validate().payload_size_bytes,
            MAX_DIAGNOSTIC_PAYLOAD_BYTES,
        )

        oversized = replace(
            accepted,
            payload=at_limit + "x",
            original_payload_bytes=MAX_DIAGNOSTIC_PAYLOAD_BYTES + 1,
        )
        with self.assertRaisesRegex(
            DiagnosticObservationError,
            "DIAGNOSTIC_PAYLOAD_BOUND_EXCEEDED",
        ):
            oversized.validate()

    def test_truncation_and_redaction_metadata_are_preserved(self) -> None:
        payload = "bounded-result"
        observation = _observation(
            payload=payload,
            content_type="text/plain",
            original_payload_bytes=10_000,
            truncated=True,
            redaction_count=2,
        ).validate()

        public = observation.canonical_dict()
        self.assertIs(public["truncated"], True)
        self.assertIs(public["redacted"], True)
        self.assertEqual(public["redaction_count"], 2)
        self.assertEqual(public["original_payload_bytes"], 10_000)

    def test_malformed_truncation_json_and_secret_material_fail_closed(self) -> None:
        payload = "bounded-result"
        with self.assertRaisesRegex(
            DiagnosticObservationError,
            "TRUNCATION_METADATA_MISMATCH",
        ):
            _observation(
                payload=payload,
                content_type="text/plain",
                original_payload_bytes=len(payload.encode("utf-8")) + 1,
            ).validate()

        malformed = "{not-json}"
        with self.assertRaisesRegex(DiagnosticObservationError, "INVALID_JSON_PAYLOAD"):
            _observation(
                payload=malformed,
                original_payload_bytes=len(malformed.encode("utf-8")),
            ).validate()

        with self.assertRaisesRegex(
            DiagnosticObservationError,
            "SECRET_MATERIAL_MUST_NOT_BE_PROMOTED",
        ):
            _observation(secret_material_detected=True).validate()

    def test_non_success_requires_explicit_error_semantics(self) -> None:
        with self.assertRaisesRegex(
            DiagnosticObservationError,
            "NON_SUCCESS_REQUIRES_ERROR_CODE",
        ):
            _observation(status="failed").validate()

        failed = _observation(status="failed", error_code="PROBE_TIMEOUT").validate()
        self.assertEqual(failed.status, "failed")
        self.assertEqual(failed.error_code, "PROBE_TIMEOUT")


if __name__ == "__main__":
    unittest.main()
