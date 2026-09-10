from __future__ import annotations

import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.lateral_movement_trace import (
    LateralMovementObservation,
    trace_lateral_movement,
)


def row(
    event_id: str,
    *,
    src: str,
    dst: str,
    channel: str = "rdp",
    authenticated: bool = True,
    remote_process_created: bool = False,
    privileged_context: bool = False,
    process_ref: str | None = None,
    minute: int = 0,
) -> LateralMovementObservation:
    return LateralMovementObservation(
        event_id=event_id,
        src_asset_ref=src,
        dst_asset_ref=dst,
        user_ref="user:sha256:aaaa",
        channel=channel,
        observed_at=f"2026-09-03T00:{minute:02d}:00Z",
        evidence_ref=f"evidence:{event_id}",
        authenticated=authenticated,
        remote_process_created=remote_process_created,
        privileged_context=privileged_context,
        process_ref=process_ref,
    )


class LateralMovementTraceTests(unittest.TestCase):
    def test_builds_evidence_backed_multi_hop_chain_inside_authorized_scope(self) -> None:
        assessment = trace_lateral_movement(
            (
                row("a-auth", src="asset:a", dst="asset:b", minute=1),
                row("a-proc", src="asset:a", dst="asset:b", remote_process_created=True, process_ref="process:b:100", minute=2),
                row("b-auth", src="asset:b", dst="asset:c", channel="winrm", minute=3),
                row("b-proc", src="asset:b", dst="asset:c", channel="winrm", remote_process_created=True, privileged_context=True, process_ref="process:c:200", minute=4),
            ),
            authorized_asset_refs=("asset:a", "asset:b", "asset:c"),
        )
        self.assertEqual(
            [(edge.src_asset_ref, edge.dst_asset_ref) for edge in assessment.edges],
            [("asset:a", "asset:b"), ("asset:b", "asset:c")],
        )
        self.assertEqual(assessment.chains, (("asset:a", "asset:b", "asset:c"),))
        self.assertTrue(all(len(edge.reasons) >= 2 for edge in assessment.edges))
        self.assertEqual(assessment.authority, "advisory")
        self.assertTrue(assessment.fingerprint.startswith("sha256:"))

    def test_single_remote_auth_does_not_become_lateral_edge(self) -> None:
        assessment = trace_lateral_movement(
            (row("auth-only", src="asset:a", dst="asset:b"),),
            authorized_asset_refs=("asset:a", "asset:b"),
        )
        self.assertEqual(assessment.edges, ())
        self.assertEqual(assessment.chains, ())

    def test_refuses_asset_scope_expansion_instead_of_discovering_targets(self) -> None:
        with self.assertRaisesRegex(MonitoringContractError, "authorized asset scope"):
            trace_lateral_movement(
                (row("outside", src="asset:a", dst="asset:unknown"),),
                authorized_asset_refs=("asset:a", "asset:b"),
            )

    def test_remote_process_requires_typed_process_reference(self) -> None:
        invalid = row("no-process", src="asset:a", dst="asset:b", remote_process_created=True, process_ref=None)
        with self.assertRaisesRegex(MonitoringContractError, "process_ref"):
            invalid.validate()

    def test_rejects_self_edges_invalid_channel_and_unbounded_hops(self) -> None:
        with self.assertRaisesRegex(MonitoringContractError, "distinct"):
            row("self", src="asset:a", dst="asset:a").validate()
        with self.assertRaisesRegex(MonitoringContractError, "unsupported lateral movement channel"):
            row("bad-channel", src="asset:a", dst="asset:b", channel="custom-shell").validate()
        with self.assertRaisesRegex(MonitoringContractError, "max_hops"):
            trace_lateral_movement((), authorized_asset_refs=("asset:a",), max_hops=99)


if __name__ == "__main__":
    unittest.main()
