from __future__ import annotations

import json
import unittest

from three_agent.security_monitoring.contracts import AssetInventoryRecord, MonitoringContractError
from three_agent.security_monitoring.dhcp_ip_triage import (
    MAX_DHCP_OBSERVATIONS,
    DeterministicDhcpIpTriage,
    DhcpIpObservation,
)
from three_agent.security_monitoring.entity_context import opaque_entity_ref


def _asset(asset_id: str, host: str, *, enabled: bool = True) -> AssetInventoryRecord:
    return AssetInventoryRecord(
        asset_id=asset_id,
        role="workstation",
        management_host=host,
        collector_capabilities=("local_net_read",),
        enabled=enabled,
    )


def _obs(
    *,
    snapshot: str = "snap-001",
    asset: str = "pc-01",
    client: str = "client-a",
    state: str = "bound",
    assigned: str | None = "192.0.2.10",
    subnet: str | None = "192.0.2.0/24",
    gateway: str | None = "192.0.2.1",
    marker: str = "a",
) -> DhcpIpObservation:
    return DhcpIpObservation(
        snapshot_id=snapshot,
        asset_id=asset,
        observed_at="2026-09-03T00:00:00Z",
        client_ref=opaque_entity_ref("interface", client),
        lease_state=state,
        assigned_ip=assigned,
        subnet_cidr=subnet,
        gateway_ip=gateway,
        evidence_ref="sha256:" + marker * 64,
    )


class DeterministicDhcpIpTriageTests(unittest.TestCase):
    def test_clean_bound_snapshot_has_no_findings(self) -> None:
        triage = DeterministicDhcpIpTriage([_asset("pc-01", "192.0.2.101")])
        self.assertEqual(triage.triage([_obs()]), ())

    def test_duplicate_ip_claim_requires_same_snapshot_and_distinct_clients(self) -> None:
        triage = DeterministicDhcpIpTriage(
            [
                _asset("pc-01", "192.0.2.101"),
                _asset("pc-02", "192.0.2.102"),
            ]
        )
        findings = triage.triage(
            [
                _obs(asset="pc-01", client="client-a", assigned="192.0.2.55", marker="a"),
                _obs(asset="pc-02", client="client-b", assigned="192.0.2.55", marker="b"),
                _obs(snapshot="snap-002", asset="pc-02", client="client-b", assigned="192.0.2.55", marker="c"),
            ]
        )

        duplicate = [item for item in findings if item.finding_code == "IP_DUPLICATE_ADDRESS_CLAIM"]
        self.assertEqual(len(duplicate), 1)
        self.assertEqual(duplicate[0].snapshot_id, "snap-001")
        self.assertEqual(duplicate[0].asset_refs, ("asset:pc-01", "asset:pc-02"))
        self.assertEqual(duplicate[0].authority, "advisory")
        self.assertFalse(duplicate[0].network_executed)
        self.assertFalse(duplicate[0].discovery_performed)
        self.assertFalse(duplicate[0].remediation_executed)

        rendered = json.dumps(duplicate[0].public_dict(), sort_keys=True)
        self.assertNotIn("192.0.2.55", rendered)
        self.assertIn("entity:ip:sha256:", rendered)

    def test_lease_and_address_state_findings_are_deterministic(self) -> None:
        triage = DeterministicDhcpIpTriage(
            [
                _asset("pc-01", "192.0.2.101"),
                _asset("pc-02", "192.0.2.102"),
                _asset("pc-03", "192.0.2.103"),
                _asset("pc-04", "192.0.2.104"),
            ]
        )
        observations = [
            _obs(asset="pc-01", client="a", state="missing", assigned=None, subnet=None, gateway=None, marker="a"),
            _obs(asset="pc-02", client="b", state="expired", assigned="192.0.2.20", subnet=None, gateway=None, marker="b"),
            _obs(asset="pc-03", client="c", assigned="169.254.10.20", subnet="169.254.0.0/16", gateway=None, marker="c"),
            _obs(asset="pc-04", client="d", assigned="192.0.3.40", subnet="192.0.2.0/24", gateway="192.0.4.1", marker="d"),
        ]

        first = triage.triage(observations)
        second = triage.triage(reversed(observations))

        self.assertEqual(first, second)
        self.assertEqual(
            {item.finding_code for item in first},
            {
                "DHCP_LEASE_MISSING",
                "DHCP_LEASE_EXPIRED",
                "IP_LINK_LOCAL_FALLBACK",
                "IP_ASSIGNED_OUTSIDE_SUBNET",
                "IP_GATEWAY_OUTSIDE_SUBNET",
            },
        )

    def test_observation_requires_enabled_approved_asset(self) -> None:
        triage = DeterministicDhcpIpTriage(
            [
                _asset("pc-01", "192.0.2.101"),
                _asset("pc-02", "192.0.2.102", enabled=False),
            ]
        )

        with self.assertRaisesRegex(MonitoringContractError, "enabled approved inventory"):
            triage.triage([_obs(asset="pc-02")])

        with self.assertRaisesRegex(MonitoringContractError, "enabled approved inventory"):
            triage.triage([_obs(asset="unknown-01")])

    def test_conflicting_logical_snapshot_observation_fails_closed(self) -> None:
        triage = DeterministicDhcpIpTriage([_asset("pc-01", "192.0.2.101")])
        client = "same-client"

        with self.assertRaisesRegex(MonitoringContractError, "conflicting snapshot content"):
            triage.triage(
                [
                    _obs(asset="pc-01", client=client, assigned="192.0.2.10", marker="a"),
                    _obs(asset="pc-01", client=client, assigned="192.0.2.11", marker="b"),
                ]
            )

    def test_missing_lease_cannot_smuggle_address_metadata(self) -> None:
        with self.assertRaisesRegex(MonitoringContractError, "must not carry address metadata"):
            _obs(state="missing", assigned="192.0.2.10", subnet=None, gateway=None).validate()

    def test_observation_iterator_stops_at_hard_bound(self) -> None:
        triage = DeterministicDhcpIpTriage([_asset("pc-01", "192.0.2.101")])
        observation = _obs()

        def too_many():
            for _ in range(MAX_DHCP_OBSERVATIONS + 1):
                yield observation
            raise AssertionError("observation iterator consumed past hard bound")

        with self.assertRaisesRegex(MonitoringContractError, "observation bound exceeded"):
            triage.triage(too_many())


if __name__ == "__main__":
    unittest.main()
