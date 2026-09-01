from __future__ import annotations

import json
import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.entity_context import (
    MAX_ENTITY_REFERENCES,
    EventEntityContext,
    EventEntityReference,
    approved_asset_ref,
    opaque_entity_ref,
)


class EventEntityContextTests(unittest.TestCase):
    def test_sensitive_values_are_typed_fingerprints_and_never_serialized_raw(self):
        values = {
            "ip": "192.0.2.10",
            "dns": "Login.Example.COM.",
            "user": "CORP\\alice",
            "process": "/usr/bin/curl",
            "service": "tcp:443",
        }
        refs = (
            EventEntityReference.opaque(kind="ip", role="source_ip", value=values["ip"]),
            EventEntityReference.opaque(kind="dns", role="dns_query", value=values["dns"]),
            EventEntityReference.opaque(kind="user", role="auth_user", value=values["user"]),
            EventEntityReference.opaque(kind="process", role="process_image", value=values["process"]),
            EventEntityReference.opaque(kind="service", role="service", value=values["service"]),
        )
        context = EventEntityContext(event_id="evt-entity-001", references=refs).validate()
        rendered = json.dumps(context.public_dict(), sort_keys=True)
        for raw in values.values():
            self.assertNotIn(raw, rendered)
        self.assertNotIn("alice", rendered.lower())
        self.assertNotIn("example.com", rendered.lower())
        self.assertNotIn("/usr/bin", rendered.lower())
        for reference in refs:
            self.assertRegex(reference.entity_ref, rf"^entity:{reference.kind}:sha256:[0-9a-f]{{64}}$")

    def test_entity_normalization_is_deterministic_without_broad_identity_inference(self):
        self.assertEqual(
            opaque_entity_ref("ip", "2001:0db8::1"),
            opaque_entity_ref("ip", "2001:db8:0:0:0:0:0:1"),
        )
        self.assertEqual(
            opaque_entity_ref("dns", "EXAMPLE.COM."),
            opaque_entity_ref("dns", "example.com"),
        )
        self.assertNotEqual(
            opaque_entity_ref("user", "Alice"),
            opaque_entity_ref("user", "alice"),
        )

    def test_only_approved_asset_ids_can_remain_explicit(self):
        ref = EventEntityReference.approved_asset(role="asset", asset_id="switch-rd-01")
        self.assertEqual(ref.entity_ref, "asset:switch-rd-01")
        self.assertEqual(approved_asset_ref("switch-rd-01"), "asset:switch-rd-01")
        with self.assertRaises(MonitoringContractError):
            EventEntityReference(kind="ip", role="source_ip", entity_ref="192.0.2.10").validate()
        with self.assertRaises(MonitoringContractError):
            EventEntityReference(kind="asset", role="asset", entity_ref="asset:bad id").validate()

    def test_role_kind_binding_is_fail_closed(self):
        with self.assertRaises(MonitoringContractError):
            EventEntityReference.opaque(kind="dns", role="source_ip", value="example.com")
        with self.assertRaises(MonitoringContractError):
            EventEntityReference.opaque(kind="credential", role="auth_user", value="secret")
        with self.assertRaises(MonitoringContractError):
            EventEntityReference(kind="user", role="password", entity_ref=opaque_entity_ref("user", "alice")).validate()

    def test_context_is_deduplicated_sorted_and_bounded(self):
        source = EventEntityReference.opaque(kind="ip", role="source_ip", value="192.0.2.1")
        destination = EventEntityReference.opaque(kind="ip", role="destination_ip", value="198.51.100.2")
        context = EventEntityContext(
            event_id="evt-bounded",
            references=(destination, source, source),
        ).validate()
        self.assertEqual(len(context.references), 2)
        self.assertEqual(context.references, tuple(sorted(context.references)))
        self.assertEqual(context.refs_for_role("source_ip"), (source.entity_ref,))

        refs = tuple(
            EventEntityReference.opaque(kind="dns", role="dns_query", value=f"host-{index}.example")
            for index in range(MAX_ENTITY_REFERENCES + 1)
        )
        with self.assertRaises(MonitoringContractError):
            EventEntityContext(event_id="evt-too-many", references=refs).validate()

    def test_control_characters_and_malformed_ip_fail_closed(self):
        with self.assertRaises(MonitoringContractError):
            opaque_entity_ref("user", "alice\nadmin")
        with self.assertRaises(MonitoringContractError):
            opaque_entity_ref("ip", "not-an-ip")


if __name__ == "__main__":
    unittest.main()
