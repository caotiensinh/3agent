import json
import unittest
from dataclasses import replace

from three_agent.capability_authority import CapabilityDecision
from three_agent.security_monitoring.diagnostic_lineage import (
    DiagnosticEvidenceLineage,
    DiagnosticLineageError,
    normalize_diagnostic_lineage,
)


def _sha(char: str) -> str:
    return "sha256:" + (char * 64)


def _decision(*, allowed: bool = True, resource_ref: str = "asset/internal-host-01") -> CapabilityDecision:
    return CapabilityDecision(
        task_id="task-001",
        capability="network.quality.internal",
        resource_kind="asset",
        resource_ref=resource_ref,
        effect="network_read",
        allowed=allowed,
        reason_code="CAPABILITY_ALLOWED" if allowed else "CAPABILITY_DENIED",
        authority_fingerprint=_sha("a"),
    )


def _lineage(**overrides: object) -> DiagnosticEvidenceLineage:
    values: dict[str, object] = {
        "decision": _decision(),
        "task_ref_sha256": _sha("1"),
        "request_ref_sha256": _sha("2"),
        "source_tool": "network_quality_probe",
        "observation_fingerprint": _sha("3"),
        "evidence_fingerprint": _sha("4"),
    }
    values.update(overrides)
    return normalize_diagnostic_lineage(**values)  # type: ignore[arg-type]


class DiagnosticLineageTests(unittest.TestCase):
    def test_lineage_is_deterministic_and_ordered(self) -> None:
        first = _lineage()
        second = _lineage()

        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(
            tuple(node.kind for node in first.nodes),
            (
                "task",
                "request",
                "capability_tool",
                "invocation_decision",
                "observation",
                "evidence",
            ),
        )
        self.assertEqual(first.provenance_status, "complete")
        self.assertEqual(first.trust_status, "unverified")
        self.assertEqual(first.authority, "advisory")
        self.assertFalse(first.automatic_action_allowed)

    def test_lineage_mutation_changes_identity(self) -> None:
        baseline = _lineage()
        request_changed = _lineage(request_ref_sha256=_sha("5"))
        observation_changed = _lineage(observation_fingerprint=_sha("6"))

        self.assertNotEqual(baseline.fingerprint, request_changed.fingerprint)
        self.assertNotEqual(baseline.fingerprint, observation_changed.fingerprint)

    def test_parent_tamper_and_orphan_nodes_fail_closed(self) -> None:
        baseline = _lineage()
        tampered_nodes = list(baseline.nodes)
        tampered_nodes[3] = replace(tampered_nodes[3], parent_sha256=_sha("f"))
        tampered = replace(baseline, nodes=tuple(tampered_nodes))
        with self.assertRaisesRegex(DiagnosticLineageError, "LINEAGE_PARENT_CHILD_MISMATCH"):
            tampered.validate()

        orphaned = replace(baseline, nodes=baseline.nodes[:-1])
        with self.assertRaisesRegex(
            DiagnosticLineageError,
            "LINEAGE_ORPHAN_OR_NODE_COUNT_MISMATCH",
        ):
            orphaned.validate()

    def test_denied_invocation_cannot_produce_lineage(self) -> None:
        with self.assertRaisesRegex(
            DiagnosticLineageError,
            "LINEAGE_REQUIRES_ALLOWED_INVOCATION",
        ):
            _lineage(decision=_decision(allowed=False))

    def test_raw_resource_and_payload_are_not_duplicated(self) -> None:
        raw_resource = "credential/private-runtime-handle"
        lineage = _lineage(decision=_decision(resource_ref=raw_resource))
        serialized = json.dumps(lineage.canonical_dict(), sort_keys=True)

        self.assertNotIn(raw_resource, serialized)
        self.assertNotIn("payload", serialized)
        self.assertIn("invocation_decision", serialized)

    def test_lineage_cannot_self_attest_trust_or_authority(self) -> None:
        baseline = _lineage()
        with self.assertRaisesRegex(DiagnosticLineageError, "LINEAGE_CANNOT_SELF_ATTEST_TRUST"):
            replace(baseline, trust_status="verified").validate()
        with self.assertRaisesRegex(DiagnosticLineageError, "LINEAGE_CANNOT_GRANT_AUTHORITY"):
            replace(baseline, automatic_action_allowed=True).validate()


if __name__ == "__main__":
    unittest.main()
