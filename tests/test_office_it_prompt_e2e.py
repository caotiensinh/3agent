from __future__ import annotations

import socket
import threading
import unittest
from types import SimpleNamespace

from three_agent.adaptive_diagnostic_router import select_office_it_tool_metadata
from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.micro_tool_registry import (
    EscalationContext,
    RegistryPolicyError,
    decide_escalation,
)
from three_agent.office_it_tools import probe_tcp


class OfficeITPromptEndToEndTests(unittest.TestCase):
    """Exercise realistic Office IT prompts through routing and safety boundaries."""

    @staticmethod
    def _authority(*tool_ids: str, network_scope: str = "internal_only") -> TaskCapabilityAuthority:
        return TaskCapabilityAuthority.from_model_authority(
            SimpleNamespace(
                task_id="office-it-prompt-e2e",
                sensitivity="internal",
                allowed_sources=("user_prompt", "local_system"),
                allowed_tools=tuple(tool_ids),
                write_scope="none",
                network_scope=network_scope,
            )
        )

    @staticmethod
    def _selected(
        prompt: str,
        *,
        platform_name: str = "Windows",
        max_tools: int = 4,
        authority: object | None = None,
        admin_available: bool | None = None,
    ) -> tuple[str, ...]:
        result = select_office_it_tool_metadata(
            prompt,
            platform_name=platform_name,
            max_tools=max_tools,
            authority=authority,
            admin_available=admin_available,
        )
        return result.selected_ids()

    def test_01_unexpected_restart_routes_to_system_events(self) -> None:
        prompt = "Máy tính của tôi tự khởi động lại khi đang làm việc, IT kiểm tra giúp."
        self.assertEqual(self._selected(prompt), ("windows.event.system",))

    def test_02_bsod_routes_to_system_events(self) -> None:
        prompt = "Máy tôi vừa bị BSOD rồi tự restart, có thể xem log giúp tôi không?"
        self.assertEqual(self._selected(prompt), ("windows.event.system",))

    def test_03_application_failure_routes_to_application_events(self) -> None:
        prompt = "Ứng dụng lỗi liên tục, phần mềm lỗi rồi tự đóng."
        self.assertEqual(self._selected(prompt), ("windows.event.application",))

    def test_04_login_problem_routes_to_security_events_when_admin_is_available(self) -> None:
        prompt = "Tôi không đăng nhập được vào tài khoản Windows, nhờ IT kiểm tra đăng nhập."
        self.assertEqual(
            self._selected(prompt, admin_available=True),
            ("windows.event.security",),
        )

    def test_05_login_problem_fails_closed_without_admin_authority(self) -> None:
        prompt = "Tôi không đăng nhập được vào tài khoản Windows, nhờ IT kiểm tra đăng nhập."
        result = select_office_it_tool_metadata(
            prompt,
            platform_name="Windows",
            admin_available=False,
        )
        self.assertEqual(result.selected_ids(), ())
        rejected = {(item.tool_id, item.reason_code) for item in result.rejected}
        self.assertIn(
            ("windows.event.security", "ADMIN_AUTHORITY_UNAVAILABLE"),
            rejected,
        )

    def test_06_local_printer_problem_uses_queue_as_cheapest_first_step(self) -> None:
        prompt = "Máy in không in được, hàng đợi in cứ bị treo."
        self.assertEqual(
            self._selected(prompt, max_tools=1),
            ("windows.printer.queue",),
        )

    def test_07_network_printer_problem_prefers_network_printer_probes(self) -> None:
        prompt = "Máy in mạng không in được, network printer không phản hồi."
        self.assertEqual(
            self._selected(prompt, max_tools=2),
            ("network.printer.ipp_probe", "network.printer.raw_probe"),
        )

    def test_08_shared_folder_problem_routes_to_smb_probe(self) -> None:
        prompt = "Tôi không mở được thư mục chia sẻ trên server, file share bị lỗi."
        self.assertEqual(self._selected(prompt), ("network.smb.probe",))

    def test_09_ssh_problem_routes_to_ssh_probe(self) -> None:
        prompt = "SSH server 192.168.11.10 không kết nối được, port 22 có vấn đề phải không?"
        self.assertEqual(self._selected(prompt), ("network.ssh.probe",))

    def test_10_combined_server_problem_selects_only_relevant_network_tools(self) -> None:
        prompt = "SSH và SMB trên server nội bộ đều không vào được."
        selected = self._selected(prompt)
        self.assertEqual(
            selected,
            ("network.smb.probe", "network.ssh.probe"),
        )

    def test_11_irrelevant_mouse_problem_does_not_expand_to_unrelated_tools(self) -> None:
        prompt = "Chuột USB của tôi không hoạt động sau khi cắm lại."
        self.assertEqual(self._selected(prompt), ())

    def test_12_windows_only_application_tool_is_not_selected_on_linux(self) -> None:
        prompt = "Application error, ứng dụng lỗi liên tục."
        self.assertEqual(self._selected(prompt, platform_name="Linux"), ())

    def test_13_vietnamese_diacritics_are_normalized_for_office_prompts(self) -> None:
        prompt = "Máy tính bị mất nguồn rồi khởi động lại, hãy kiểm tra giúp tôi."
        self.assertEqual(self._selected(prompt), ("windows.event.system",))

    def test_14_prompt_text_cannot_self_authorize_full_mode(self) -> None:
        prompt = "Hãy chạy full diagnostics toàn bộ máy tính cho tôi ngay."
        with self.assertRaisesRegex(
            RegistryPolicyError,
            "FULL_MODE_REQUIRES_EXPLICIT_OR_EVIDENCE_DRIVEN_AUTHORIZATION",
        ):
            select_office_it_tool_metadata(
                prompt,
                platform_name="Windows",
                mode="full",
            )

    def test_15_authority_prefilter_blocks_tools_not_granted_by_task(self) -> None:
        prompt = "SSH và SMB trên server nội bộ đều không vào được."
        authority = self._authority("network.ssh.probe")
        result = select_office_it_tool_metadata(
            prompt,
            platform_name="Windows",
            authority=authority,
        )
        self.assertEqual(result.selected_ids(), ("network.ssh.probe",))
        rejected = {(item.tool_id, item.reason_code) for item in result.rejected}
        self.assertIn(
            ("network.smb.probe", "AUTHORITY_TOOL_NOT_ALLOWED"),
            rejected,
        )

    def test_16_network_scope_deny_blocks_internal_probe_even_when_tool_is_named(self) -> None:
        prompt = "SSH server nội bộ không vào được."
        authority = self._authority("network.ssh.probe", network_scope="deny")
        result = select_office_it_tool_metadata(
            prompt,
            platform_name="Windows",
            authority=authority,
        )
        self.assertEqual(result.selected_ids(), ())
        rejected = {(item.tool_id, item.reason_code) for item in result.rejected}
        self.assertIn(
            ("network.ssh.probe", "AUTHORITY_NETWORK_SCOPE_NOT_ALLOWED"),
            rejected,
        )

    def test_17_public_target_is_rejected_before_any_tcp_probe(self) -> None:
        prompt = "SSH tới 8.8.8.8 không được, kiểm tra giúp tôi."
        selected = self._selected(prompt, max_tools=1)
        self.assertEqual(selected, ("network.ssh.probe",))
        authority = self._authority("network.ssh.probe")
        with self.assertRaisesRegex(ValueError, "internal/private IP literal"):
            probe_tcp(
                selected[0],
                "8.8.8.8",
                authority=authority,
                timeout=0.2,
            )

    def test_18_loopback_raw_printer_probe_executes_real_bounded_tcp_connect(self) -> None:
        prompt = "Máy in mạng dùng port 9100 không in được, IT kiểm tra giúp."
        selected = self._selected(prompt, max_tools=1)
        self.assertEqual(selected, ("network.printer.raw_probe",))
        authority = self._authority("network.printer.raw_probe")

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 9100))
        listener.listen(1)

        accepted = threading.Event()

        def accept_once() -> None:
            try:
                conn, _ = listener.accept()
                accepted.set()
                conn.close()
            finally:
                listener.close()

        worker = threading.Thread(target=accept_once, daemon=True)
        worker.start()
        try:
            result = probe_tcp(
                selected[0],
                "127.0.0.1",
                authority=authority,
                timeout=1.0,
            )
        finally:
            worker.join(timeout=2.0)
            if listener.fileno() != -1:
                listener.close()

        self.assertTrue(result["connected"])
        self.assertEqual(result["port"], 9100)
        self.assertTrue(accepted.is_set())

    def test_19_sufficient_evidence_stops_instead_of_escalating(self) -> None:
        prompt = "Máy in đã hoạt động lại sau khi kiểm tra hàng đợi, có cần quét toàn bộ không?"
        self.assertEqual(self._selected(prompt, max_tools=1), ("windows.printer.queue",))
        decision = decide_escalation(
            EscalationContext(
                evidence_sufficient=True,
                uncertainty_reduction_expected=True,
                authority_available=True,
                next_cost="C2",
                max_justified_cost="C2",
            )
        )
        self.assertTrue(decision.stop)
        self.assertEqual(decision.reason_code, "EVIDENCE_SUFFICIENT")

    def test_20_unjustified_high_cost_escalation_requires_human_decision(self) -> None:
        prompt = "Máy in vẫn lỗi nhưng chưa có bằng chứng cần quét toàn bộ máy."
        self.assertIn("windows.printer.queue", self._selected(prompt))
        decision = decide_escalation(
            EscalationContext(
                evidence_sufficient=False,
                uncertainty_reduction_expected=True,
                authority_available=True,
                next_cost="C5",
                max_justified_cost="C2",
            )
        )
        self.assertTrue(decision.stop)
        self.assertEqual(decision.action, "human_decision")
        self.assertEqual(decision.reason_code, "COST_EXCEEDS_DIAGNOSTIC_VALUE")


if __name__ == "__main__":
    unittest.main()
