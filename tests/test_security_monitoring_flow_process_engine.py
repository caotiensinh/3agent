from __future__ import annotations

import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.flow_process_attribution import FlowTupleEvidence, SocketProcessObservation
from three_agent.security_monitoring.flow_process_engine import (
    DeterministicFlowProcessAttributor,
    FlowProcessAttributionConfig,
)


def flow(
    *,
    event_id: str = "flow-1",
    at: str = "2026-09-01T14:00:00Z",
    src_ip: str = "192.0.2.10",
    src_port: int = 50123,
    dst_ip: str = "198.51.100.20",
    dst_port: int = 443,
) -> FlowTupleEvidence:
    return FlowTupleEvidence.build(
        event_id=event_id,
        observed_at=at,
        protocol="tcp",
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=dst_ip,
        destination_port=dst_port,
        evidence_ref=f"evidence:{event_id}",
    )


def socket(
    *,
    evidence: str = "evidence:socket-1",
    at: str = "2026-09-01T14:00:01Z",
    local_ip: str = "192.0.2.10",
    local_port: int = 50123,
    remote_ip: str = "198.51.100.20",
    remote_port: int = 443,
    process: str = "browser.exe",
    user: str | None = "alice",
    asset: str = "workstation-01",
) -> SocketProcessObservation:
    return SocketProcessObservation.build(
        approved_asset_id=asset,
        observed_at=at,
        protocol="tcp",
        local_ip=local_ip,
        local_port=local_port,
        remote_ip=remote_ip,
        remote_port=remote_port,
        process_image=process,
        user=user,
        evidence_ref=evidence,
    )


class FlowProcessAttributionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = DeterministicFlowProcessAttributor(
            FlowProcessAttributionConfig(max_time_skew_seconds=5)
        )

    def test_exact_direct_socket_attributes_flow_to_one_process(self) -> None:
        result = self.engine.attribute(flows=(flow(),), socket_observations=(socket(),))[0]
        self.assertEqual(result.status, "attributed")
        self.assertEqual(result.candidate_identity_count, 1)
        self.assertEqual(result.asset_refs, ("asset:workstation-01",))
        self.assertEqual(len(result.process_refs), 1)
        self.assertEqual(len(result.user_refs), 1)
        self.assertEqual(result.match_directions, ("direct",))
        self.assertEqual(result.closest_delta_microseconds, 1_000_000)
        self.assertEqual(result.socket_evidence_refs, ("evidence:socket-1",))
        self.assertEqual(result.authority, "advisory")

    def test_reverse_sensor_direction_attributes_same_socket(self) -> None:
        inbound = flow(
            event_id="flow-inbound",
            src_ip="198.51.100.20",
            src_port=443,
            dst_ip="192.0.2.10",
            dst_port=50123,
        )
        result = self.engine.attribute(flows=(inbound,), socket_observations=(socket(),))[0]
        self.assertEqual(result.status, "attributed")
        self.assertEqual(result.match_directions, ("reverse",))

    def test_multiple_snapshots_for_same_identity_are_not_ambiguous(self) -> None:
        observations = (
            socket(evidence="evidence:socket-1", at="2026-09-01T13:59:59Z"),
            socket(evidence="evidence:socket-2", at="2026-09-01T14:00:02Z"),
        )
        result = self.engine.attribute(flows=(flow(),), socket_observations=observations)[0]
        self.assertEqual(result.status, "attributed")
        self.assertEqual(result.candidate_identity_count, 1)
        self.assertEqual(
            result.socket_evidence_refs,
            ("evidence:socket-1", "evidence:socket-2"),
        )
        self.assertEqual(result.closest_delta_microseconds, 1_000_000)

    def test_multiple_processes_on_same_tuple_are_ambiguous_not_guessed(self) -> None:
        observations = (
            socket(evidence="evidence:socket-a", process="browser.exe", user="alice"),
            socket(evidence="evidence:socket-b", process="updater.exe", user="alice"),
        )
        result = self.engine.attribute(flows=(flow(),), socket_observations=observations)[0]
        self.assertEqual(result.status, "ambiguous")
        self.assertEqual(result.candidate_identity_count, 2)
        self.assertEqual(len(result.process_refs), 2)
        self.assertEqual(result.asset_refs, ("asset:workstation-01",))
        self.assertEqual(len(result.socket_evidence_refs), 2)

    def test_same_process_but_different_user_binding_is_ambiguous(self) -> None:
        observations = (
            socket(evidence="evidence:socket-a", process="service.exe", user="alice"),
            socket(evidence="evidence:socket-b", process="service.exe", user="bob"),
        )
        result = self.engine.attribute(flows=(flow(),), socket_observations=observations)[0]
        self.assertEqual(result.status, "ambiguous")
        self.assertEqual(result.candidate_identity_count, 2)
        self.assertEqual(len(result.process_refs), 1)
        self.assertEqual(len(result.user_refs), 2)

    def test_outside_time_window_is_unmatched(self) -> None:
        result = self.engine.attribute(
            flows=(flow(),),
            socket_observations=(socket(at="2026-09-01T14:00:06Z"),),
        )[0]
        self.assertEqual(result.status, "unmatched")
        self.assertEqual(result.candidate_identity_count, 0)
        self.assertEqual(result.process_refs, ())
        self.assertEqual(result.socket_evidence_refs, ())
        self.assertIsNone(result.closest_delta_microseconds)

    def test_wrong_tuple_is_unmatched(self) -> None:
        result = self.engine.attribute(
            flows=(flow(),),
            socket_observations=(socket(remote_port=8443),),
        )[0]
        self.assertEqual(result.status, "unmatched")

    def test_shuffled_inputs_produce_byte_identical_assessments(self) -> None:
        flows = (flow(event_id="flow-1"), flow(event_id="flow-2", src_port=50124))
        sockets = (
            socket(evidence="evidence:s1"),
            socket(evidence="evidence:s2", local_port=50124, process="other.exe"),
        )
        left = self.engine.attribute(flows=flows, socket_observations=sockets)
        right = self.engine.attribute(flows=reversed(flows), socket_observations=reversed(sockets))
        self.assertEqual(tuple(item.to_json() for item in left), tuple(item.to_json() for item in right))
        self.assertEqual(tuple(item.fingerprint for item in left), tuple(item.fingerprint for item in right))

    def test_exact_duplicate_flow_and_socket_are_deduplicated(self) -> None:
        f = flow()
        s = socket()
        result = self.engine.attribute(flows=(f, f), socket_observations=(s, s))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].status, "attributed")
        self.assertEqual(result[0].socket_evidence_refs, ("evidence:socket-1",))

    def test_conflicting_duplicate_flow_event_id_fails_closed(self) -> None:
        with self.assertRaises(MonitoringContractError):
            self.engine.attribute(
                flows=(flow(), flow(dst_port=8443)),
                socket_observations=(),
            )

    def test_conflicting_socket_evidence_ref_fails_closed(self) -> None:
        with self.assertRaises(MonitoringContractError):
            self.engine.attribute(
                flows=(flow(),),
                socket_observations=(
                    socket(evidence="evidence:same", process="browser.exe"),
                    socket(evidence="evidence:same", process="other.exe"),
                ),
            )

    def test_bounds_and_config_fail_closed(self) -> None:
        with self.assertRaises(MonitoringContractError):
            FlowProcessAttributionConfig(max_time_skew_seconds=301).validate()
        with self.assertRaises(MonitoringContractError):
            FlowProcessAttributionConfig(max_flows=10, max_assessments=9).validate()

        small = DeterministicFlowProcessAttributor(
            FlowProcessAttributionConfig(
                max_time_skew_seconds=5,
                max_flows=1,
                max_socket_observations=1,
                max_assessments=1,
            )
        )
        with self.assertRaises(MonitoringContractError):
            small.attribute(
                flows=(flow(event_id="flow-1"), flow(event_id="flow-2", src_port=50124)),
                socket_observations=(),
            )
        with self.assertRaises(MonitoringContractError):
            small.attribute(
                flows=(flow(),),
                socket_observations=(socket(evidence="evidence:s1"), socket(evidence="evidence:s2")),
            )

    def test_assessment_payload_contains_no_raw_endpoint_or_process_identity(self) -> None:
        result = self.engine.attribute(flows=(flow(),), socket_observations=(socket(),))[0]
        payload = result.to_json()
        for raw in ("192.0.2.10", "198.51.100.20", "browser.exe", "alice"):
            self.assertNotIn(raw, payload)


if __name__ == "__main__":
    unittest.main()
