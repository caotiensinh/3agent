from __future__ import annotations

import unittest

from three_agent.security_monitoring.contracts import AssetInventoryRecord, MonitoringContractError
from three_agent.security_monitoring.plan import CollectorWorkItem, compile_collection_plan
from three_agent.security_monitoring.policy import MonitoringPolicy, MonitoringPolicyEngine
from three_agent.security_monitoring.rule_compiler import DeterministicRuleCompiler
from three_agent.security_monitoring.rule_contracts import RulePredicates, RuleSource
from three_agent.security_monitoring.work_clustering import (
    bind_rule_to_authorized_work,
    cluster_authorized_rule_work,
)


def asset(asset_id: str = "switch-01", host: str = "192.0.2.10") -> AssetInventoryRecord:
    return AssetInventoryRecord(
        asset_id=asset_id,
        role="switch",
        management_host=host,
        collector_capabilities=("local_net_read", "tcp_connect"),
        allowed_tcp_ports=(443,),
    ).validate()


def plan(rule_id: str, *, capability: str = "local_net_read", enabled: bool = True):
    source = RuleSource(
        rule_id=rule_id,
        rule_version=1,
        enabled=enabled,
        predicates=RulePredicates(source_type="suricata_eve"),
        required_capabilities=(capability,),
    ).validate()
    return DeterministicRuleCompiler().compile((source,))[0]


class AuthorizedWorkClusteringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.asset = asset()
        self.policy = MonitoringPolicyEngine(MonitoringPolicy())
        work = compile_collection_plan((self.asset,), policy=MonitoringPolicy())
        self.local_work = next(item for item in work if item.capability == "local_net_read")

    def test_two_rules_share_one_exact_authorized_collection(self) -> None:
        left = bind_rule_to_authorized_work(
            plan=plan("RULE_A"),
            work=self.local_work,
            asset=self.asset,
            policy_engine=self.policy,
        )
        right = bind_rule_to_authorized_work(
            plan=plan("RULE_B"),
            work=self.local_work,
            asset=self.asset,
            policy_engine=self.policy,
        )
        clusters = cluster_authorized_rule_work((right, left))
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0].work.work_id, self.local_work.work_id)
        self.assertEqual(clusters[0].rule_ids, ("RULE_A", "RULE_B"))
        self.assertEqual(clusters[0].policy_fingerprint, self.policy.policy.fingerprint)

    def test_binding_order_does_not_change_cluster_serialization(self) -> None:
        bindings = tuple(
            bind_rule_to_authorized_work(
                plan=plan(rule_id),
                work=self.local_work,
                asset=self.asset,
                policy_engine=self.policy,
            )
            for rule_id in ("RULE_A", "RULE_B")
        )
        left = cluster_authorized_rule_work(bindings)
        right = cluster_authorized_rule_work(reversed(bindings))
        self.assertEqual(tuple(item.to_json() for item in left), tuple(item.to_json() for item in right))
        self.assertEqual(tuple(item.fingerprint for item in left), tuple(item.fingerprint for item in right))

    def test_policy_denial_cannot_be_clustered_as_authorized_work(self) -> None:
        tcp_work = CollectorWorkItem(
            work_id="work-explicit-tcp",
            asset_id=self.asset.asset_id,
            capability="tcp_connect",
            target_host=self.asset.management_host,
            target_port=443,
        )
        with self.assertRaises(PermissionError) as captured:
            bind_rule_to_authorized_work(
                plan=plan("TCP_RULE", capability="tcp_connect"),
                work=tcp_work,
                asset=self.asset,
                policy_engine=self.policy,
            )
        self.assertEqual(str(captured.exception), "ACTIVE_LIVENESS_DISABLED")

    def test_rule_cannot_bind_work_it_did_not_require(self) -> None:
        with self.assertRaises(MonitoringContractError):
            bind_rule_to_authorized_work(
                plan=plan("DNS_RULE"),
                work=CollectorWorkItem(
                    work_id="work-tcp",
                    asset_id=self.asset.asset_id,
                    capability="tcp_connect",
                    target_host=self.asset.management_host,
                    target_port=443,
                ),
                asset=self.asset,
                policy_engine=MonitoringPolicyEngine(MonitoringPolicy(allow_active_liveness=True)),
            )

    def test_disabled_rule_cannot_request_work(self) -> None:
        with self.assertRaises(MonitoringContractError):
            bind_rule_to_authorized_work(
                plan=plan("DISABLED", enabled=False),
                work=self.local_work,
                asset=self.asset,
                policy_engine=self.policy,
            )

    def test_same_work_id_with_conflicting_inventory_work_fails_closed(self) -> None:
        other_asset = asset("switch-02", "192.0.2.11")
        other_work = CollectorWorkItem(
            work_id=self.local_work.work_id,
            asset_id=other_asset.asset_id,
            capability="local_net_read",
            target_host=other_asset.management_host,
        )
        first = bind_rule_to_authorized_work(
            plan=plan("RULE_A"),
            work=self.local_work,
            asset=self.asset,
            policy_engine=self.policy,
        )
        second = bind_rule_to_authorized_work(
            plan=plan("RULE_B"),
            work=other_work,
            asset=other_asset,
            policy_engine=self.policy,
        )
        with self.assertRaises(MonitoringContractError):
            cluster_authorized_rule_work((first, second))

    def test_binding_and_cluster_bounds_fail_closed(self) -> None:
        binding = bind_rule_to_authorized_work(
            plan=plan("RULE_A"),
            work=self.local_work,
            asset=self.asset,
            policy_engine=self.policy,
        )
        with self.assertRaises(MonitoringContractError):
            cluster_authorized_rule_work((binding, binding), max_bindings=1)
        with self.assertRaises(MonitoringContractError):
            cluster_authorized_rule_work((binding,), max_clusters=0)


if __name__ == "__main__":
    unittest.main()
