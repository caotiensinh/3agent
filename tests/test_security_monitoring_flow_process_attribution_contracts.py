from __future__ import annotations

import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.flow_process_attribution import (
    FlowTupleEvidence,
    SocketProcessObservation,
    endpoint_ref,
)


class FlowProcessEvidenceContractTests(unittest.TestCase):
    def test_endpoint_normalization_is_deterministic_and_hides_raw_endpoint(self) -> None:
        left = endpoint_ref(protocol="TCP", ip="2001:0db8::1", port=443)
        right = endpoint_ref(protocol="tcp", ip="2001:db8::1", port=443)
        self.assertEqual(left, right)
        self.assertTrue(left.startswith("endpoint:tcp:sha256:"))
        self.assertEqual(len(left), len("endpoint:tcp:sha256:") + 64)
        self.assertNotIn("2001:db8::1", left)

    def test_flow_tuple_retains_only_hashed_endpoints_and_event_evidence(self) -> None:
        flow = FlowTupleEvidence.build(
            event_id="event-flow-1",
            observed_at="2026-09-01T14:00:00+00:00",
            protocol="tcp",
            source_ip="192.0.2.10",
            source_port=50123,
            destination_ip="198.51.100.20",
            destination_port=443,
            evidence_ref="evidence:flow-1",
        )
        payload = flow.to_json()
        self.assertEqual(flow.observed_at, "2026-09-01T14:00:00Z")
        self.assertEqual(flow.protocol, "tcp")
        self.assertNotIn("192.0.2.10", payload)
        self.assertNotIn("198.51.100.20", payload)
        self.assertNotIn('"source_port"', payload)
        self.assertNotIn('"destination_port"', payload)
        self.assertEqual(flow.authority, "evidence_only")

    def test_socket_process_observation_hashes_endpoint_process_and_user(self) -> None:
        item = SocketProcessObservation.build(
            approved_asset_id="workstation-01",
            observed_at="2026-09-01T14:00:01Z",
            protocol="tcp",
            local_ip="192.0.2.10",
            local_port=50123,
            remote_ip="198.51.100.20",
            remote_port=443,
            process_image=r"C:\Program Files\Browser\browser.exe",
            user="DOMAIN\\alice",
            evidence_ref="evidence:socket-1",
        )
        payload = item.to_json()
        self.assertEqual(item.asset_ref, "asset:workstation-01")
        self.assertTrue(item.process_ref.startswith("entity:process:sha256:"))
        self.assertTrue(str(item.user_ref).startswith("entity:user:sha256:"))
        for raw in (
            "192.0.2.10",
            "198.51.100.20",
            r"C:\Program Files\Browser\browser.exe",
            "DOMAIN\\alice",
        ):
            self.assertNotIn(raw, payload)
        self.assertNotIn('"local_port"', payload)
        self.assertNotIn('"remote_port"', payload)
        self.assertEqual(item.authority, "evidence_only")

    def test_same_exact_socket_builds_byte_identical_contract(self) -> None:
        kwargs = dict(
            approved_asset_id="workstation-01",
            observed_at="2026-09-01T14:00:01Z",
            protocol="udp",
            local_ip="192.0.2.10",
            local_port=5353,
            remote_ip="224.0.0.251",
            remote_port=5353,
            process_image="mdns-service",
            evidence_ref="evidence:socket-1",
        )
        left = SocketProcessObservation.build(**kwargs)
        right = SocketProcessObservation.build(**kwargs)
        self.assertEqual(left.to_json(), right.to_json())
        self.assertEqual(left.fingerprint, right.fingerprint)

    def test_flow_and_socket_exact_direction_share_endpoint_hashes(self) -> None:
        flow = FlowTupleEvidence.build(
            event_id="event-flow-1",
            observed_at="2026-09-01T14:00:00Z",
            protocol="tcp",
            source_ip="192.0.2.10",
            source_port=50123,
            destination_ip="198.51.100.20",
            destination_port=443,
            evidence_ref="evidence:flow-1",
        )
        socket = SocketProcessObservation.build(
            approved_asset_id="workstation-01",
            observed_at="2026-09-01T14:00:01Z",
            protocol="tcp",
            local_ip="192.0.2.10",
            local_port=50123,
            remote_ip="198.51.100.20",
            remote_port=443,
            process_image="browser.exe",
            evidence_ref="evidence:socket-1",
        )
        self.assertEqual(flow.source_endpoint_ref, socket.local_endpoint_ref)
        self.assertEqual(flow.destination_endpoint_ref, socket.remote_endpoint_ref)

    def test_reverse_direction_can_be_compared_without_raw_identifiers(self) -> None:
        flow = FlowTupleEvidence.build(
            event_id="event-flow-inbound",
            observed_at="2026-09-01T14:00:00Z",
            protocol="tcp",
            source_ip="198.51.100.20",
            source_port=443,
            destination_ip="192.0.2.10",
            destination_port=50123,
            evidence_ref="evidence:flow-inbound",
        )
        socket = SocketProcessObservation.build(
            approved_asset_id="workstation-01",
            observed_at="2026-09-01T14:00:01Z",
            protocol="tcp",
            local_ip="192.0.2.10",
            local_port=50123,
            remote_ip="198.51.100.20",
            remote_port=443,
            process_image="browser.exe",
            evidence_ref="evidence:socket-1",
        )
        self.assertEqual(flow.source_endpoint_ref, socket.remote_endpoint_ref)
        self.assertEqual(flow.destination_endpoint_ref, socket.local_endpoint_ref)

    def test_invalid_endpoint_protocol_port_and_ip_fail_closed(self) -> None:
        with self.assertRaises(MonitoringContractError):
            endpoint_ref(protocol="icmp", ip="192.0.2.10", port=1)
        with self.assertRaises(MonitoringContractError):
            endpoint_ref(protocol="tcp", ip="not-an-ip", port=443)
        with self.assertRaises(MonitoringContractError):
            endpoint_ref(protocol="tcp", ip="192.0.2.10", port=0)
        with self.assertRaises(MonitoringContractError):
            endpoint_ref(protocol="tcp", ip="192.0.2.10", port=True)

    def test_contract_authority_and_typed_refs_fail_closed(self) -> None:
        flow = FlowTupleEvidence.build(
            event_id="event-flow-1",
            observed_at="2026-09-01T14:00:00Z",
            protocol="tcp",
            source_ip="192.0.2.10",
            source_port=50123,
            destination_ip="198.51.100.20",
            destination_port=443,
            evidence_ref="evidence:flow-1",
        )
        with self.assertRaises(MonitoringContractError):
            FlowTupleEvidence(**{**flow.__dict__, "authority": "network_read"}).validate()

        socket = SocketProcessObservation.build(
            approved_asset_id="workstation-01",
            observed_at="2026-09-01T14:00:01Z",
            protocol="tcp",
            local_ip="192.0.2.10",
            local_port=50123,
            remote_ip="198.51.100.20",
            remote_port=443,
            process_image="browser.exe",
            evidence_ref="evidence:socket-1",
        )
        with self.assertRaises(MonitoringContractError):
            SocketProcessObservation(**{**socket.__dict__, "process_ref": "browser.exe"}).validate()
        with self.assertRaises(MonitoringContractError):
            SocketProcessObservation(**{**socket.__dict__, "asset_ref": "candidate-123"}).validate()
        with self.assertRaises(MonitoringContractError):
            SocketProcessObservation(**{**socket.__dict__, "authority": "execute_readonly"}).validate()


if __name__ == "__main__":
    unittest.main()
