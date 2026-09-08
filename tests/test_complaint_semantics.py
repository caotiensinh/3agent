import unittest

from three_agent.adaptive_diagnostic_router import (
    select_office_it_tool_metadata,
    select_pc_diagnostic_tool_metadata,
)
from three_agent.diagnostics.complaint_semantics import normalize_complaint_semantics


class ComplaintSemanticsTests(unittest.TestCase):
    def test_customer_causal_claim_is_not_a_symptom_fact(self):
        semantics = normalize_complaint_semantics("Máy bị đơ, chắc GPU hỏng")

        self.assertIn("perceived_unresponsiveness", semantics.canonical_symptoms)
        self.assertIn("gpu_failure", semantics.customer_hypotheses)
        self.assertNotIn("gpu_failure", semantics.canonical_symptoms)
        self.assertEqual(semantics.raw_text, "Máy bị đơ, chắc GPU hỏng")

    def test_network_wording_normalizes_without_claiming_nic_failure(self):
        semantics = normalize_complaint_semantics("Máy bị mất mạng")

        self.assertEqual(
            semantics.canonical_symptoms,
            ("expected_network_access_unavailable",),
        )
        self.assertEqual(semantics.customer_hypotheses, ())

    def test_restart_and_update_claim_remain_separate(self):
        semantics = normalize_complaint_semantics(
            "Máy tự khởi động lại, chắc Windows Update làm hỏng"
        )

        self.assertIn("unexpected_restart", semantics.canonical_symptoms)
        self.assertIn("windows_update_regression", semantics.customer_hypotheses)

    def test_office_router_uses_normalized_symptom_for_windows_evidence(self):
        result = select_office_it_tool_metadata(
            "Máy bị đơ, chắc GPU hỏng",
            platform_name="Windows",
            mode="quick",
            max_tools=2,
        )

        selected = result.selected_ids()
        self.assertIn("windows.event.system", selected)
        self.assertTrue(set(selected).issubset({
            "windows.event.system",
            "windows.event.application",
        }))

    def test_pc_router_reuses_cross_platform_runtime_for_linux_freeze(self):
        result = select_pc_diagnostic_tool_metadata(
            "Máy bị đơ",
            platform_name="Linux",
            mode="quick",
            max_tools=3,
        )

        self.assertIn("system.resource.snapshot", result.selected_ids())

    def test_pc_router_expands_layperson_network_wording_to_bounded_reads(self):
        result = select_pc_diagnostic_tool_metadata(
            "Máy bị mất mạng",
            platform_name="Linux",
            mode="quick",
            max_tools=4,
        )

        selected = set(result.selected_ids())
        self.assertIn("network.interface.snapshot", selected)
        self.assertTrue(selected.intersection({
            "network.ipconfig.snapshot",
            "network.dns.snapshot",
            "network.route.snapshot",
        }))


if __name__ == "__main__":
    unittest.main()
