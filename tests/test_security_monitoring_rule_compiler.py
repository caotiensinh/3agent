from __future__ import annotations

import unittest

from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError
from three_agent.security_monitoring.rule_compiler import DeterministicRuleCompiler
from three_agent.security_monitoring.rule_contracts import RulePredicates, RuleSource


_DIGEST = "sha256:" + "d" * 64


def rule(
    rule_id: str,
    *,
    enabled: bool = True,
    category: str | None = "suricata.dns",
    min_severity: str | None = "low",
    capabilities: tuple[str, ...] = ("local_net_read",),
) -> RuleSource:
    return RuleSource(
        rule_id=rule_id,
        rule_version=1,
        enabled=enabled,
        predicates=RulePredicates(
            source_type="suricata_eve",
            category=category,
            min_severity=min_severity,
        ),
        required_capabilities=capabilities,
    ).validate()


def event(*, category: str = "suricata.dns", severity: str = "medium") -> CanonicalEvent:
    return CanonicalEvent(
        event_id="event-1",
        source_id="sensor-01",
        source_type="suricata_eve",
        observed_at="2026-09-01T14:00:00Z",
        category=category,
        severity=severity,
        message_sha256=_DIGEST,
        parser_version="parser-v1",
        evidence_ref="evidence:1",
    ).validate()


class RuleCompilerTests(unittest.TestCase):
    def test_input_order_does_not_change_compiled_serialization(self) -> None:
        compiler = DeterministicRuleCompiler()
        left = compiler.compile((rule("B_RULE"), rule("A_RULE", category="suricata.flow")))
        right = compiler.compile((rule("A_RULE", category="suricata.flow"), rule("B_RULE")))
        self.assertEqual(tuple(item.to_json() for item in left), tuple(item.to_json() for item in right))
        self.assertEqual(tuple(item.fingerprint for item in left), tuple(item.fingerprint for item in right))
        self.assertEqual(tuple(item.rule_id for item in left), ("A_RULE", "B_RULE"))

    def test_compiled_plan_reuses_existing_event_rule_semantics(self) -> None:
        plan = DeterministicRuleCompiler().compile((rule("DNS_RULE"),))[0]
        self.assertTrue(plan.matches(event(severity="medium")))
        self.assertFalse(plan.matches(event(category="suricata.flow", severity="medium")))
        self.assertFalse(plan.matches(event(severity="info")))

    def test_extractor_returns_only_normalized_metadata_and_evidence(self) -> None:
        plan = DeterministicRuleCompiler().compile((
            rule("DNS_RULE", capabilities=("snmpv3_read", "local_net_read")),
        ))[0]
        receipt = plan.extract(event())
        self.assertIsNotNone(receipt)
        assert receipt is not None
        payload = receipt.to_dict()
        self.assertEqual(payload["required_capabilities"], ["local_net_read", "snmpv3_read"])
        self.assertEqual(payload["evidence_ref"], "evidence:1")
        self.assertNotIn("message", payload)
        self.assertNotIn("target_host", payload)
        self.assertNotIn("credential_ref", payload)
        self.assertNotIn("allowed", payload)
        self.assertEqual(payload["authority"], "advisory")

    def test_disabled_rule_is_compiled_but_cannot_match(self) -> None:
        plan = DeterministicRuleCompiler().compile((rule("DISABLED", enabled=False),))[0]
        self.assertFalse(plan.matches(event()))
        self.assertIsNone(plan.extract(event()))

    def test_duplicate_rule_ids_and_compilation_bound_fail_closed(self) -> None:
        compiler = DeterministicRuleCompiler()
        with self.assertRaises(MonitoringContractError):
            compiler.compile((rule("DUP"), rule("DUP")))
        small = DeterministicRuleCompiler(max_rules=1)
        with self.assertRaises(MonitoringContractError):
            small.compile((rule("A"), rule("B")))

    def test_source_version_changes_compiled_fingerprint(self) -> None:
        one = rule("VERSIONED")
        two = RuleSource(
            rule_id="VERSIONED",
            rule_version=2,
            enabled=True,
            predicates=RulePredicates(
                source_type="suricata_eve",
                category="suricata.dns",
                min_severity="low",
            ),
            required_capabilities=("local_net_read",),
        ).validate()
        compiler = DeterministicRuleCompiler()
        self.assertNotEqual(compiler.compile((one,))[0].fingerprint, compiler.compile((two,))[0].fingerprint)


if __name__ == "__main__":
    unittest.main()
