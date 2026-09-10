from __future__ import annotations

import json
import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.rule_contracts import (
    RULE_SOURCE_SCHEMA,
    RulePredicates,
    RuleSource,
    parse_rule_source,
)


class RuleSourceContractTests(unittest.TestCase):
    def payload(self, **overrides):
        source = {
            "schema_version": RULE_SOURCE_SCHEMA,
            "rule_id": "DNS_SIGNAL_V1",
            "rule_version": 1,
            "enabled": True,
            "predicates": {
                "source_type": "suricata_eve",
                "category": "suricata.dns",
                "min_severity": "low",
            },
            "required_capabilities": ["local_net_read"],
        }
        source.update(overrides)
        return source

    def test_equivalent_json_order_produces_identical_canonical_rule(self) -> None:
        payload = self.payload()
        left = parse_rule_source(json.dumps(payload))
        right = parse_rule_source(
            json.dumps(
                {
                    "required_capabilities": ["local_net_read"],
                    "predicates": {
                        "min_severity": "low",
                        "category": "suricata.dns",
                        "source_type": "suricata_eve",
                    },
                    "enabled": True,
                    "rule_version": 1,
                    "rule_id": "DNS_SIGNAL_V1",
                    "schema_version": RULE_SOURCE_SCHEMA,
                }
            )
        )
        self.assertEqual(left.to_json(), right.to_json())
        self.assertEqual(left.fingerprint, right.fingerprint)

    def test_rule_requirements_do_not_contain_targets_or_authorization(self) -> None:
        rule = parse_rule_source(json.dumps(self.payload()))
        serialized = rule.to_dict()
        self.assertNotIn("target_host", serialized)
        self.assertNotIn("target_port", serialized)
        self.assertNotIn("credential_ref", serialized)
        self.assertNotIn("allowed", serialized)
        self.assertEqual(rule.required_capabilities, ("local_net_read",))

    def test_unknown_or_duplicate_capability_fails_closed(self) -> None:
        with self.assertRaises(MonitoringContractError):
            parse_rule_source(json.dumps(self.payload(required_capabilities=["shell_exec"])))
        with self.assertRaises(MonitoringContractError):
            parse_rule_source(json.dumps(self.payload(required_capabilities=["local_net_read", "local_net_read"])))

    def test_unknown_missing_and_duplicate_json_fields_fail_closed(self) -> None:
        payload = self.payload()
        payload["target_host"] = "192.0.2.1"
        with self.assertRaises(MonitoringContractError):
            parse_rule_source(json.dumps(payload))

        missing = self.payload()
        del missing["enabled"]
        with self.assertRaises(MonitoringContractError):
            parse_rule_source(json.dumps(missing))

        duplicate = (
            '{"schema_version":"workspace-security-monitoring/rule-source-v1",'
            '"rule_id":"A","rule_id":"B","rule_version":1,"enabled":true,'
            '"predicates":{"source_type":"suricata_eve","category":null,"min_severity":null},'
            '"required_capabilities":[]}'
        )
        with self.assertRaises(MonitoringContractError):
            parse_rule_source(duplicate)

    def test_predicate_schema_is_strict_and_nonempty(self) -> None:
        payload = self.payload(
            predicates={"source_type": None, "category": None, "min_severity": None}
        )
        with self.assertRaises(MonitoringContractError):
            parse_rule_source(json.dumps(payload))

        unknown = self.payload(
            predicates={
                "source_type": "suricata_eve",
                "category": None,
                "min_severity": None,
                "script": "do something",
            }
        )
        with self.assertRaises(MonitoringContractError):
            parse_rule_source(json.dumps(unknown))

    def test_invalid_schema_types_and_oversized_source_fail_closed(self) -> None:
        with self.assertRaises(MonitoringContractError):
            parse_rule_source(json.dumps(self.payload(rule_version=True)))
        with self.assertRaises(MonitoringContractError):
            parse_rule_source(json.dumps(self.payload(enabled="yes")))
        with self.assertRaises(MonitoringContractError):
            parse_rule_source(json.dumps(self.payload(schema_version="workspace-security-monitoring/rule-source-v999")))
        with self.assertRaises(MonitoringContractError):
            parse_rule_source(b"\xff")
        with self.assertRaises(MonitoringContractError):
            parse_rule_source(" " * (64 * 1024 + 1))

    def test_direct_contract_normalizes_capability_order(self) -> None:
        rule = RuleSource(
            rule_id="CAP_ORDER_V1",
            rule_version=1,
            enabled=True,
            predicates=RulePredicates(source_type="zeek_json"),
            required_capabilities=("snmpv3_read", "local_net_read"),
        ).validate()
        self.assertEqual(rule.required_capabilities, ("local_net_read", "snmpv3_read"))


if __name__ == "__main__":
    unittest.main()
