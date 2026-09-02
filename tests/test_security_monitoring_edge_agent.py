from __future__ import annotations

import inspect
import json
import unittest
from dataclasses import replace

import three_agent.security_monitoring.edge_agent as edge_module
from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.edge_agent import (
    BoundedEdgeEnvelopeQueue,
    EdgeAgentDescriptor,
    EdgeBackpressure,
    EdgeCollectionRequest,
    EdgeEvidenceItem,
    EdgeQueuePolicy,
    authorize_edge_request,
    build_edge_envelope,
    seal_edge_envelope,
    verify_edge_envelope,
)


def digest(char: str) -> str:
    return "sha256:" + char * 64


def descriptor() -> EdgeAgentDescriptor:
    return EdgeAgentDescriptor(
        agent_id="edge-rd-01",
        asset_ref="asset:workstation-01",
        allowed_capabilities=("local_net_read", "fixed_readonly_adapter"),
        policy_fingerprint=digest("a"),
        config_fingerprint=digest("b"),
        auth_key_id="edge-key-01",
    ).validate()


def request(
    *,
    asset_ref: str = "asset:workstation-01",
    capability: str = "local_net_read",
    policy_fingerprint: str = digest("a"),
    config_fingerprint: str = digest("b"),
    max_records: int = 10,
    max_payload_bytes: int = 4096,
) -> EdgeCollectionRequest:
    return EdgeCollectionRequest(
        request_id="edge-request-01",
        agent_id="edge-rd-01",
        asset_ref=asset_ref,
        capability=capability,
        issued_at="2026-09-01T14:00:00Z",
        expires_at="2026-09-01T14:10:00Z",
        policy_fingerprint=policy_fingerprint,
        config_fingerprint=config_fingerprint,
        max_records=max_records,
        max_payload_bytes=max_payload_bytes,
    ).validate()


def item(sequence: int, *, size: int = 128) -> EdgeEvidenceItem:
    return EdgeEvidenceItem(
        sequence=sequence,
        evidence_ref=f"evidence:edge-{sequence}",
        observed_at=f"2026-09-01T14:00:{sequence:02d}Z",
        payload_sha256=digest("c" if sequence % 2 == 0 else "d"),
        payload_bytes=size,
    ).validate()


class EdgeAgentContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.descriptor = descriptor()
        self.request = request()
        self.key = b"k" * 32

    def test_descriptor_allows_only_narrow_local_read_capabilities(self) -> None:
        self.assertEqual(
            self.descriptor.allowed_capabilities,
            ("fixed_readonly_adapter", "local_net_read"),
        )
        for forbidden in ("icmp_echo", "tcp_connect", "snmpv3_read", "shell", "pcap", "remediate"):
            with self.assertRaises(MonitoringContractError):
                replace(self.descriptor, allowed_capabilities=(forbidden,)).validate()

    def test_request_has_no_target_host_port_command_or_secret_fields(self) -> None:
        rendered = self.request.to_dict()
        self.assertEqual(rendered["authority"], "read_only")
        for forbidden in ("host", "port", "command", "shell", "credential", "password", "token", "secret"):
            self.assertNotIn(forbidden, rendered)

    def test_request_must_bind_exact_agent_asset_capability_policy_and_config(self) -> None:
        accepted = authorize_edge_request(
            descriptor=self.descriptor,
            request=self.request,
            evaluated_at="2026-09-01T14:05:00Z",
        )
        self.assertEqual(accepted.request_id, self.request.request_id)

        with self.assertRaisesRegex(PermissionError, "EDGE_ASSET_NOT_APPROVED"):
            authorize_edge_request(
                descriptor=self.descriptor,
                request=request(asset_ref="asset:unknown-asset"),
                evaluated_at="2026-09-01T14:05:00Z",
            )
        with self.assertRaisesRegex(PermissionError, "EDGE_POLICY_FINGERPRINT_MISMATCH"):
            authorize_edge_request(
                descriptor=self.descriptor,
                request=request(policy_fingerprint=digest("e")),
                evaluated_at="2026-09-01T14:05:00Z",
            )
        with self.assertRaisesRegex(PermissionError, "EDGE_CONFIG_FINGERPRINT_MISMATCH"):
            authorize_edge_request(
                descriptor=self.descriptor,
                request=request(config_fingerprint=digest("f")),
                evaluated_at="2026-09-01T14:05:00Z",
            )
        with self.assertRaisesRegex(PermissionError, "EDGE_REQUEST_EXPIRED_OR_NOT_YET_VALID"):
            authorize_edge_request(
                descriptor=self.descriptor,
                request=self.request,
                evaluated_at="2026-09-01T15:00:00Z",
            )

    def test_request_lifetime_and_resource_bounds_fail_closed(self) -> None:
        with self.assertRaises(MonitoringContractError):
            replace(self.request, expires_at="2026-09-01T16:00:01Z").validate()
        with self.assertRaises(MonitoringContractError):
            replace(self.request, max_records=0).validate()
        with self.assertRaises(MonitoringContractError):
            replace(self.request, max_payload_bytes=16 * 1024 * 1024 + 1).validate()
        with self.assertRaises(MonitoringContractError):
            replace(self.request, capability="tcp_connect").validate()

    def test_envelope_contains_hashes_and_refs_not_raw_payload(self) -> None:
        envelope = build_edge_envelope(
            descriptor=self.descriptor,
            request=self.request,
            evaluated_at="2026-09-01T14:05:00Z",
            created_at="2026-09-01T14:05:00Z",
            items=(item(0), item(1)),
        )
        rendered = envelope.to_json().lower()
        self.assertEqual(envelope.first_sequence, 0)
        self.assertEqual(envelope.last_sequence, 1)
        self.assertEqual(envelope.payload_bytes, 256)
        self.assertEqual(envelope.authority, "evidence_only")
        self.assertNotIn("raw_payload", rendered)
        self.assertNotIn("password", rendered)
        self.assertNotIn("token", rendered)

    def test_envelope_requires_ordered_contiguous_sequence_and_request_bounds(self) -> None:
        with self.assertRaises(MonitoringContractError):
            build_edge_envelope(
                descriptor=self.descriptor,
                request=self.request,
                evaluated_at="2026-09-01T14:05:00Z",
                created_at="2026-09-01T14:05:00Z",
                items=(item(0), item(2)),
            )
        with self.assertRaises(MonitoringContractError):
            build_edge_envelope(
                descriptor=self.descriptor,
                request=request(max_records=1),
                evaluated_at="2026-09-01T14:05:00Z",
                created_at="2026-09-01T14:05:00Z",
                items=(item(0), item(1)),
            )
        with self.assertRaises(MonitoringContractError):
            build_edge_envelope(
                descriptor=self.descriptor,
                request=request(max_payload_bytes=100),
                evaluated_at="2026-09-01T14:05:00Z",
                created_at="2026-09-01T14:05:00Z",
                items=(item(0),),
            )

    def test_hmac_authentication_detects_wrong_key_and_tampering(self) -> None:
        envelope = build_edge_envelope(
            descriptor=self.descriptor,
            request=self.request,
            evaluated_at="2026-09-01T14:05:00Z",
            created_at="2026-09-01T14:05:00Z",
            items=(item(0),),
        )
        sealed = seal_edge_envelope(
            envelope=envelope,
            auth_key_id=self.descriptor.auth_key_id,
            authentication_key=self.key,
        )
        self.assertTrue(
            verify_edge_envelope(
                sealed=sealed,
                descriptor=self.descriptor,
                authentication_key=self.key,
            )
        )
        self.assertFalse(
            verify_edge_envelope(
                sealed=sealed,
                descriptor=self.descriptor,
                authentication_key=b"x" * 32,
            )
        )

        tampered_envelope = replace(envelope, created_at="2026-09-01T14:05:01Z").validate()
        tampered = replace(sealed, envelope=tampered_envelope).validate()
        self.assertFalse(
            verify_edge_envelope(
                sealed=tampered,
                descriptor=self.descriptor,
                authentication_key=self.key,
            )
        )

    def test_authentication_key_is_never_serialized_and_key_length_is_bounded(self) -> None:
        envelope = build_edge_envelope(
            descriptor=self.descriptor,
            request=self.request,
            evaluated_at="2026-09-01T14:05:00Z",
            created_at="2026-09-01T14:05:00Z",
            items=(item(0),),
        )
        sealed = seal_edge_envelope(
            envelope=envelope,
            auth_key_id=self.descriptor.auth_key_id,
            authentication_key=self.key,
        )
        rendered = json.dumps(sealed.to_dict(), sort_keys=True)
        self.assertNotIn(self.key.decode("ascii"), rendered)
        with self.assertRaises(MonitoringContractError):
            seal_edge_envelope(
                envelope=envelope,
                auth_key_id=self.descriptor.auth_key_id,
                authentication_key=b"short",
            )

    def test_offline_queue_enforces_hash_chain_sequence_and_backpressure(self) -> None:
        first_envelope = build_edge_envelope(
            descriptor=self.descriptor,
            request=self.request,
            evaluated_at="2026-09-01T14:05:00Z",
            created_at="2026-09-01T14:05:00Z",
            items=(item(0),),
        )
        first = seal_edge_envelope(
            envelope=first_envelope,
            auth_key_id=self.descriptor.auth_key_id,
            authentication_key=self.key,
        )
        second_envelope = build_edge_envelope(
            descriptor=self.descriptor,
            request=self.request,
            evaluated_at="2026-09-01T14:05:00Z",
            created_at="2026-09-01T14:05:01Z",
            items=(item(1),),
            previous_envelope_fingerprint=first_envelope.fingerprint,
        )
        second = seal_edge_envelope(
            envelope=second_envelope,
            auth_key_id=self.descriptor.auth_key_id,
            authentication_key=self.key,
        )

        queue = BoundedEdgeEnvelopeQueue(
            descriptor=self.descriptor,
            policy=EdgeQueuePolicy(max_envelopes=2, max_total_payload_bytes=256),
        )
        queue.append(first, authentication_key=self.key)
        queue.append(second, authentication_key=self.key)
        self.assertEqual(queue.pending_count, 2)
        self.assertEqual(queue.pending_payload_bytes, 256)
        self.assertEqual(queue.peek(limit=1), (first,))
        self.assertEqual(queue.ack(count=1), (first_envelope.fingerprint,))
        self.assertEqual(queue.pending_count, 1)
        self.assertEqual(queue.ack(count=1), (second_envelope.fingerprint,))
        self.assertEqual(queue.pending_count, 0)

        full = BoundedEdgeEnvelopeQueue(
            descriptor=self.descriptor,
            policy=EdgeQueuePolicy(max_envelopes=1, max_total_payload_bytes=1024),
        )
        full.append(first, authentication_key=self.key)
        with self.assertRaisesRegex(EdgeBackpressure, "EDGE_QUEUE_BACKPRESSURE"):
            full.append(second, authentication_key=self.key)

    def test_queue_rejects_bad_authentication_and_chain_discontinuity(self) -> None:
        first_envelope = build_edge_envelope(
            descriptor=self.descriptor,
            request=self.request,
            evaluated_at="2026-09-01T14:05:00Z",
            created_at="2026-09-01T14:05:00Z",
            items=(item(0),),
        )
        first = seal_edge_envelope(
            envelope=first_envelope,
            auth_key_id=self.descriptor.auth_key_id,
            authentication_key=self.key,
        )
        queue = BoundedEdgeEnvelopeQueue(descriptor=self.descriptor)
        with self.assertRaisesRegex(MonitoringContractError, "authentication failed"):
            queue.append(first, authentication_key=b"z" * 32)

        queue.append(first, authentication_key=self.key)
        broken_envelope = build_edge_envelope(
            descriptor=self.descriptor,
            request=self.request,
            evaluated_at="2026-09-01T14:05:00Z",
            created_at="2026-09-01T14:05:02Z",
            items=(item(1),),
            previous_envelope_fingerprint=digest("f"),
        )
        broken = seal_edge_envelope(
            envelope=broken_envelope,
            auth_key_id=self.descriptor.auth_key_id,
            authentication_key=self.key,
        )
        with self.assertRaisesRegex(MonitoringContractError, "hash chain discontinuity"):
            queue.append(broken, authentication_key=self.key)

    def test_module_has_no_network_cloud_shell_capture_or_remediation_authority(self) -> None:
        source = inspect.getsource(edge_module).lower()
        for forbidden in (
            "import socket",
            "subprocess",
            "urlopen",
            "requests.",
            "tcpdump",
            "scapy",
            "firewall",
            "quarantine_host",
            "kill_process",
            "run(command",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
