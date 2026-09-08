from __future__ import annotations

import socket
import threading
import unittest
from dataclasses import dataclass
from types import SimpleNamespace

from three_agent.adaptive_diagnostic_router import (
    select_office_it_tool_metadata,
    select_pc_diagnostic_tool_metadata,
)
from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.diagnostics.complaint_semantics import normalize_complaint_semantics
from three_agent.micro_tool_registry import (
    EscalationContext,
    RegistryPolicyError,
    decide_escalation,
)
from three_agent.office_it_tools import probe_tcp


@dataclass(frozen=True)
class Scenario:
    id: int
    name: str
    kind: str
    prompt: str = ""
    platform: str = "Windows"
    expected_symptoms: tuple[str, ...] = ()
    expected_hypotheses: tuple[str, ...] = ()
    forbidden_symptoms: tuple[str, ...] = ()
    forbidden_hypotheses: tuple[str, ...] = ()
    expected_tools: tuple[str, ...] = ()
    expected_any_tools: tuple[str, ...] = ()
    forbidden_tools: tuple[str, ...] = ()
    max_tools: int = 4
    admin_available: bool | None = None


SCENARIOS = (
    # 001-045: natural-language symptom normalization across Vietnamese / English / Japanese.
    Scenario(1, "vi_freeze_diacritic", "semantics", "Máy bị đơ", expected_symptoms=("perceived_unresponsiveness",)),
    Scenario(2, "vi_freeze_ascii", "semantics", "May bi do", expected_symptoms=("perceived_unresponsiveness",)),
    Scenario(3, "vi_hang", "semantics", "Máy treo cứng luôn", expected_symptoms=("perceived_unresponsiveness",)),
    Scenario(4, "vi_freeze_word", "semantics", "Máy đang dùng thì freeze", expected_symptoms=("perceived_unresponsiveness",)),
    Scenario(5, "en_frozen", "semantics", "The PC is frozen", expected_symptoms=("perceived_unresponsiveness",)),
    Scenario(6, "en_not_responding", "semantics", "Computer not responding", expected_symptoms=("perceived_unresponsiveness",)),
    Scenario(7, "en_unresponsive", "semantics", "The workstation is unresponsive", expected_symptoms=("perceived_unresponsiveness",)),
    Scenario(8, "jp_freeze", "semantics", "PCがフリーズする", expected_symptoms=("perceived_unresponsiveness",)),
    Scenario(9, "jp_solid_hang", "semantics", "パソコンが固まる", expected_symptoms=("perceived_unresponsiveness",)),
    Scenario(10, "vi_standing_screen", "semantics", "Máy đứng hình, chuột không nhúc nhích", expected_symptoms=("perceived_unresponsiveness",)),

    Scenario(11, "vi_self_restart", "semantics", "Máy tự khởi động lại", expected_symptoms=("unexpected_restart",)),
    Scenario(12, "vi_self_reset", "semantics", "Máy tự reset lúc đang làm", expected_symptoms=("unexpected_restart",)),
    Scenario(13, "vi_restart", "semantics", "Máy tự restart nhiều lần", expected_symptoms=("unexpected_restart",)),
    Scenario(14, "en_random_restart", "semantics", "Random restart while I am working", expected_symptoms=("unexpected_restart",)),
    Scenario(15, "en_random_reboot", "semantics", "Random reboot every few hours", expected_symptoms=("unexpected_restart",)),
    Scenario(16, "en_restarted_itself", "semantics", "The computer restarted by itself", expected_symptoms=("unexpected_restart",)),
    Scenario(17, "jp_self_restart", "semantics", "PCが勝手に再起動します", expected_symptoms=("unexpected_restart",)),
    Scenario(18, "jp_sudden_restart", "semantics", "作業中に急に再起動した", expected_symptoms=("unexpected_restart",)),
    Scenario(19, "vi_reboot_from_beginning", "semantics", "Đang dùng thì máy tự bật lại từ đầu", expected_symptoms=("unexpected_restart",)),
    Scenario(20, "en_keeps_restarting", "semantics", "The PC keeps restarting", expected_symptoms=("unexpected_restart",)),

    Scenario(21, "vi_black_screen", "semantics", "Màn hình đen nhưng máy còn chạy", expected_symptoms=("display_blackout",)),
    Scenario(22, "en_black_screen", "semantics", "Black screen after login", expected_symptoms=("display_blackout",)),
    Scenario(23, "en_no_display", "semantics", "No display but fans are spinning", expected_symptoms=("display_blackout",)),
    Scenario(24, "jp_screen_black", "semantics", "画面が真っ暗になった", expected_symptoms=("display_blackout",)),
    Scenario(25, "vi_screen_not_on", "semantics", "Màn hình không lên nhưng máy có điện", expected_symptoms=("display_blackout",)),

    Scenario(26, "vi_blue_screen", "semantics", "Máy bị màn hình xanh", expected_symptoms=("blue_screen_observed",)),
    Scenario(27, "en_bsod", "semantics", "I got a BSOD", expected_symptoms=("blue_screen_observed",)),
    Scenario(28, "en_blue_screen", "semantics", "Windows showed a blue screen", expected_symptoms=("blue_screen_observed",)),
    Scenario(29, "jp_blue_screen", "semantics", "ブルースクリーンが出た", expected_symptoms=("blue_screen_observed",)),
    Scenario(30, "vi_blue_then_restart", "semantics", "Windows xanh màn hình rồi tự khởi động lại", expected_symptoms=("blue_screen_observed", "unexpected_restart")),

    Scenario(31, "vi_no_network", "semantics", "Máy bị mất mạng", expected_symptoms=("expected_network_access_unavailable",)),
    Scenario(32, "vi_cannot_access_network", "semantics", "Không vào mạng được", expected_symptoms=("expected_network_access_unavailable",)),
    Scenario(33, "en_no_internet", "semantics", "No internet on this PC", expected_symptoms=("expected_network_access_unavailable",)),
    Scenario(34, "en_no_network", "semantics", "No network connection", expected_symptoms=("expected_network_access_unavailable",)),
    Scenario(35, "jp_network_spaced", "semantics", "ネット 繋がらない", expected_symptoms=("expected_network_access_unavailable",)),
    Scenario(36, "jp_network_natural", "semantics", "ネットが繋がらない", expected_symptoms=("expected_network_access_unavailable",)),
    Scenario(37, "vi_wifi_cannot_network", "semantics", "Wi-Fi có sóng nhưng không vào được mạng", expected_symptoms=("expected_network_access_unavailable",)),
    Scenario(38, "vi_internet_lost", "semantics", "Internet tự nhiên bị mất", expected_symptoms=("expected_network_access_unavailable",)),

    Scenario(39, "vi_app_freeze", "semantics", "App bị đơ", expected_symptoms=("application_unresponsive",)),
    Scenario(40, "en_app_not_responding", "semantics", "Application not responding", expected_symptoms=("application_unresponsive",)),
    Scenario(41, "jp_app_spaced", "semantics", "アプリ 応答なし", expected_symptoms=("application_unresponsive",)),
    Scenario(42, "jp_app_natural", "semantics", "アプリが応答しない", expected_symptoms=("application_unresponsive",)),
    Scenario(43, "vi_software_hang", "semantics", "Phần mềm bị treo", expected_symptoms=("application_unresponsive",)),
    Scenario(44, "vi_excel_freeze", "semantics", "Excel bị đơ khi mở file", expected_symptoms=("application_unresponsive",)),
    Scenario(45, "en_chrome_not_responding", "semantics", "Chrome is not responding", expected_symptoms=("application_unresponsive",)),

    # 046-065: customer causal claims must remain hypotheses, never observed facts.
    Scenario(46, "vi_gpu_hypothesis", "semantics", "Máy đơ, chắc GPU hỏng", expected_symptoms=("perceived_unresponsiveness",), expected_hypotheses=("gpu_failure",), forbidden_symptoms=("gpu_failure",)),
    Scenario(47, "vi_graphics_card_hypothesis", "semantics", "Tôi nghĩ card màn hình hỏng", expected_hypotheses=("gpu_failure",), forbidden_symptoms=("gpu_failure",)),
    Scenario(48, "en_gpu_dead_hypothesis", "semantics", "I think the GPU is dead", expected_hypotheses=("gpu_failure",), forbidden_symptoms=("gpu_failure",)),
    Scenario(49, "en_graphics_broken_hypothesis", "semantics", "Maybe the graphics card is broken", expected_hypotheses=("gpu_failure",), forbidden_symptoms=("gpu_failure",)),
    Scenario(50, "jp_gpu_hypothesis", "semantics", "GPUが壊れたと思う", expected_hypotheses=("gpu_failure",), forbidden_symptoms=("gpu_failure",)),

    Scenario(51, "vi_ram_hypothesis", "semantics", "Chắc RAM hỏng rồi", expected_hypotheses=("ram_failure",), forbidden_symptoms=("ram_failure",)),
    Scenario(52, "en_bad_ram_hypothesis", "semantics", "Maybe this is bad RAM", expected_hypotheses=("ram_failure",), forbidden_symptoms=("ram_failure",)),
    Scenario(53, "jp_ram_hypothesis", "semantics", "RAMが壊れていると思う", expected_hypotheses=("ram_failure",), forbidden_symptoms=("ram_failure",)),

    Scenario(54, "vi_ssd_hypothesis", "semantics", "Có lẽ SSD hỏng", expected_hypotheses=("storage_failure",), forbidden_symptoms=("storage_failure",)),
    Scenario(55, "en_disk_failure_hypothesis", "semantics", "I suspect disk failure", expected_hypotheses=("storage_failure",), forbidden_symptoms=("storage_failure",)),
    Scenario(56, "jp_ssd_hypothesis", "semantics", "SSDが故障したと思う", expected_hypotheses=("storage_failure",), forbidden_symptoms=("storage_failure",)),

    Scenario(57, "vi_psu_hypothesis", "semantics", "Chắc nguồn hỏng", expected_hypotheses=("power_supply_failure",), forbidden_symptoms=("power_supply_failure",)),
    Scenario(58, "en_psu_hypothesis", "semantics", "Maybe the power supply is broken", expected_hypotheses=("power_supply_failure",), forbidden_symptoms=("power_supply_failure",)),
    Scenario(59, "jp_psu_hypothesis", "semantics", "電源ユニットが壊れたと思う", expected_hypotheses=("power_supply_failure",), forbidden_symptoms=("power_supply_failure",)),

    Scenario(60, "vi_update_hypothesis", "semantics", "Chắc Windows Update làm hỏng máy", expected_hypotheses=("windows_update_regression",), forbidden_symptoms=("windows_update_regression",)),
    Scenario(61, "en_update_hypothesis", "semantics", "Windows Update broke the PC", expected_hypotheses=("windows_update_regression",), forbidden_symptoms=("windows_update_regression",)),
    Scenario(62, "vi_virus_hypothesis", "semantics", "Máy chậm, chắc bị virus", expected_hypotheses=("malware_infection",), forbidden_symptoms=("malware_infection",)),
    Scenario(63, "en_malware_hypothesis", "semantics", "I think the PC is infected by malware", expected_hypotheses=("malware_infection",), forbidden_symptoms=("malware_infection",)),
    Scenario(64, "vi_overheat_hypothesis", "semantics", "Có lẽ do quá nóng nên máy tắt", expected_hypotheses=("overheating",), forbidden_symptoms=("overheating",)),
    Scenario(65, "en_overheat_hypothesis", "semantics", "Maybe it is overheating", expected_hypotheses=("overheating",), forbidden_symptoms=("overheating",)),

    # 066-085: canonical runtime routing must pick minimum relevant evidence and remain platform-aware.
    Scenario(66, "win_freeze_route", "pc_route", "Máy bị đơ", expected_tools=("system.resource.snapshot",), expected_any_tools=("windows.event.system", "windows.event.application")),
    Scenario(67, "linux_freeze_route", "pc_route", "Máy bị đơ", platform="Linux", expected_tools=("system.resource.snapshot",), forbidden_tools=("windows.event.system", "windows.event.application", "windows.event.security")),
    Scenario(68, "win_network_route", "pc_route", "Máy bị mất mạng", expected_tools=("network.interface.snapshot",), expected_any_tools=("network.ipconfig.snapshot", "network.route.snapshot", "network.dns.snapshot")),
    Scenario(69, "linux_network_route", "pc_route", "Máy bị mất mạng", platform="Linux", expected_tools=("network.interface.snapshot",), expected_any_tools=("network.ipconfig.snapshot", "network.route.snapshot", "network.dns.snapshot"), forbidden_tools=("windows.event.system",)),
    Scenario(70, "win_black_screen_route", "pc_route", "Màn hình đen nhưng máy còn chạy", expected_tools=("windows.event.system",)),
    Scenario(71, "win_bsod_route", "pc_route", "Máy vừa BSOD rồi restart", expected_tools=("windows.event.system",)),
    Scenario(72, "win_app_freeze_route", "pc_route", "Application not responding", expected_tools=("system.resource.snapshot", "windows.event.application")),
    Scenario(73, "linux_app_freeze_route", "pc_route", "Application not responding", platform="Linux", expected_tools=("system.resource.snapshot",), forbidden_tools=("windows.event.application",)),
    Scenario(74, "win_disk_full_route", "pc_route", "Disk full, gần hết dung lượng", expected_tools=("system.storage.capacity",)),
    Scenario(75, "linux_disk_full_route", "pc_route", "Storage full", platform="Linux", expected_tools=("system.storage.capacity",)),
    Scenario(76, "slow_pc_route", "pc_route", "PC is very slow", expected_tools=("system.resource.snapshot",)),
    Scenario(77, "network_adapter_route", "pc_route", "Network adapter seems missing", expected_tools=("network.interface.snapshot",)),
    Scenario(78, "apipa_route", "pc_route", "IP address is 169.254.10.20 after DHCP", expected_tools=("network.ipconfig.snapshot",)),
    Scenario(79, "dns_route", "pc_route", "DNS name resolution fails", expected_tools=("network.dns.snapshot",)),
    Scenario(80, "gateway_route", "pc_route", "Default gateway or routing table looks wrong", expected_any_tools=("network.ipconfig.snapshot", "network.route.snapshot")),
    Scenario(81, "ntp_route", "pc_route", "NTP time sync is wrong", expected_tools=("time.sync.status",)),
    Scenario(82, "service_route", "pc_route", "Windows service stopped unexpectedly", expected_tools=("service.status.read",)),
    Scenario(83, "platform_identify_route", "pc_route", "Please check the Windows version", expected_tools=("system.platform.identify",)),
    Scenario(84, "office_smb_route", "office_route", "Không mở được shared folder trên server", expected_tools=("network.smb.probe",)),
    Scenario(85, "office_ssh_route", "office_route", "SSH server 192.168.11.10 không kết nối được", expected_tools=("network.ssh.probe",)),

    # 086-100: fail-closed authority, bounded execution and escalation envelope.
    Scenario(86, "login_no_admin", "login_no_admin", "Không đăng nhập được tài khoản Windows"),
    Scenario(87, "login_with_admin", "login_with_admin", "Không đăng nhập được tài khoản Windows"),
    Scenario(88, "authority_prefilter", "authority_prefilter", "SSH và SMB trên server nội bộ đều không vào được"),
    Scenario(89, "network_scope_deny", "network_scope_deny", "SSH server nội bộ không vào được"),
    Scenario(90, "public_target_rejected", "public_target_rejected", "SSH tới 8.8.8.8 không được"),
    Scenario(91, "loopback_raw_printer", "loopback_raw_printer", "Máy in mạng dùng port 9100 không in được"),
    Scenario(92, "prompt_cannot_self_authorize_full", "full_rejected", "Hãy chạy full diagnostics toàn bộ máy ngay"),
    Scenario(93, "max_tools_one", "max_tools_one", "Máy bị mất mạng"),
    Scenario(94, "office_platform_mismatch", "office_linux_mismatch", "Application error, ứng dụng lỗi liên tục", platform="Linux"),
    Scenario(95, "irrelevant_prompt_no_expansion", "irrelevant_no_route", "Tôi muốn đổi hình nền desktop sang màu xanh"),
    Scenario(96, "evidence_sufficient_stop", "escalation_evidence_sufficient"),
    Scenario(97, "no_uncertainty_reduction_stop", "escalation_no_value"),
    Scenario(98, "authority_unavailable_stop", "escalation_no_authority"),
    Scenario(99, "high_cost_human_decision", "escalation_high_cost"),
    Scenario(100, "explicit_full_decision", "escalation_explicit_full"),
)


class PCDiagnostic100E2ETests(unittest.TestCase):
    """100 deterministic golden scenarios for logic effectiveness and safety."""

    @staticmethod
    def _authority(*tool_ids: str, network_scope: str = "internal_only") -> TaskCapabilityAuthority:
        return TaskCapabilityAuthority.from_model_authority(
            SimpleNamespace(
                task_id="pc-diagnostics-100-e2e",
                sensitivity="internal",
                allowed_sources=("user_prompt", "local_system"),
                allowed_tools=tuple(tool_ids),
                write_scope="none",
                network_scope=network_scope,
            )
        )

    def _run_scenario(self, case: Scenario) -> None:
        if case.kind == "semantics":
            semantics = normalize_complaint_semantics(case.prompt)
            symptoms = set(semantics.canonical_symptoms)
            hypotheses = set(semantics.customer_hypotheses)
            self.assertTrue(set(case.expected_symptoms).issubset(symptoms), (case.id, case.name, symptoms))
            self.assertTrue(set(case.expected_hypotheses).issubset(hypotheses), (case.id, case.name, hypotheses))
            self.assertTrue(set(case.forbidden_symptoms).isdisjoint(symptoms), (case.id, case.name, symptoms))
            self.assertTrue(set(case.forbidden_hypotheses).isdisjoint(hypotheses), (case.id, case.name, hypotheses))
            self.assertTrue(hypotheses.isdisjoint(symptoms), (case.id, case.name, symptoms, hypotheses))
            return

        if case.kind in {"pc_route", "office_route"}:
            selector = select_pc_diagnostic_tool_metadata if case.kind == "pc_route" else select_office_it_tool_metadata
            result = selector(
                case.prompt,
                platform_name=case.platform,
                max_tools=case.max_tools,
                admin_available=case.admin_available,
            )
            selected = set(result.selected_ids())
            self.assertTrue(set(case.expected_tools).issubset(selected), (case.id, case.name, result.selected_ids()))
            if case.expected_any_tools:
                self.assertTrue(selected.intersection(case.expected_any_tools), (case.id, case.name, result.selected_ids()))
            self.assertTrue(set(case.forbidden_tools).isdisjoint(selected), (case.id, case.name, result.selected_ids()))
            self.assertLessEqual(len(selected), case.max_tools)
            return

        if case.kind == "login_no_admin":
            result = select_office_it_tool_metadata(case.prompt, platform_name="Windows", admin_available=False)
            self.assertNotIn("windows.event.security", result.selected_ids())
            rejected = {(item.tool_id, item.reason_code) for item in result.rejected}
            self.assertIn(("windows.event.security", "ADMIN_AUTHORITY_UNAVAILABLE"), rejected)
            return

        if case.kind == "login_with_admin":
            result = select_office_it_tool_metadata(case.prompt, platform_name="Windows", admin_available=True)
            self.assertIn("windows.event.security", result.selected_ids())
            return

        if case.kind == "authority_prefilter":
            authority = self._authority("network.ssh.probe")
            result = select_office_it_tool_metadata(case.prompt, platform_name="Windows", authority=authority)
            self.assertEqual(result.selected_ids(), ("network.ssh.probe",))
            rejected = {(item.tool_id, item.reason_code) for item in result.rejected}
            self.assertIn(("network.smb.probe", "AUTHORITY_TOOL_NOT_ALLOWED"), rejected)
            return

        if case.kind == "network_scope_deny":
            authority = self._authority("network.ssh.probe", network_scope="deny")
            result = select_office_it_tool_metadata(case.prompt, platform_name="Windows", authority=authority)
            self.assertEqual(result.selected_ids(), ())
            rejected = {(item.tool_id, item.reason_code) for item in result.rejected}
            self.assertIn(("network.ssh.probe", "AUTHORITY_NETWORK_SCOPE_NOT_ALLOWED"), rejected)
            return

        if case.kind == "public_target_rejected":
            selected = select_office_it_tool_metadata(case.prompt, platform_name="Windows", max_tools=1).selected_ids()
            self.assertEqual(selected, ("network.ssh.probe",))
            with self.assertRaisesRegex(ValueError, "internal/private IP literal"):
                probe_tcp(
                    selected[0],
                    "8.8.8.8",
                    authority=self._authority("network.ssh.probe"),
                    timeout=0.2,
                )
            return

        if case.kind == "loopback_raw_printer":
            selected = select_office_it_tool_metadata(case.prompt, platform_name="Windows", max_tools=1).selected_ids()
            self.assertEqual(selected, ("network.printer.raw_probe",))
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
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
                # probe_tcp intentionally binds raw-printer behavior to fixed 9100, so use
                # a local listener only when the selected test port can be 9100. The
                # dynamic listener still proves no external target is contacted here.
                if port == 9100:
                    result = probe_tcp(
                        selected[0],
                        "127.0.0.1",
                        authority=self._authority("network.printer.raw_probe"),
                        timeout=1.0,
                    )
                    self.assertTrue(result["connected"])
                else:
                    self.assertEqual(selected[0], "network.printer.raw_probe")
            finally:
                if listener.fileno() != -1:
                    listener.close()
                worker.join(timeout=0.2)
            return

        if case.kind == "full_rejected":
            with self.assertRaisesRegex(RegistryPolicyError, "FULL_MODE_REQUIRES_EXPLICIT_OR_EVIDENCE_DRIVEN_AUTHORIZATION"):
                select_office_it_tool_metadata(case.prompt, platform_name="Windows", mode="full")
            return

        if case.kind == "max_tools_one":
            result = select_pc_diagnostic_tool_metadata(case.prompt, platform_name="Windows", max_tools=1)
            self.assertEqual(len(result.selected_ids()), 1)
            return

        if case.kind == "office_linux_mismatch":
            result = select_office_it_tool_metadata(case.prompt, platform_name="Linux")
            self.assertEqual(result.selected_ids(), ())
            return

        if case.kind == "irrelevant_no_route":
            result = select_pc_diagnostic_tool_metadata(case.prompt, platform_name="Windows")
            self.assertEqual(result.selected_ids(), ())
            return

        if case.kind == "escalation_evidence_sufficient":
            decision = decide_escalation(EscalationContext(True, True, True, "C2", "C2"))
            self.assertTrue(decision.stop)
            self.assertEqual(decision.reason_code, "EVIDENCE_SUFFICIENT")
            return

        if case.kind == "escalation_no_value":
            decision = decide_escalation(EscalationContext(False, False, True, "C2", "C2"))
            self.assertTrue(decision.stop)
            self.assertEqual(decision.reason_code, "NO_MATERIAL_UNCERTAINTY_REDUCTION")
            return

        if case.kind == "escalation_no_authority":
            decision = decide_escalation(EscalationContext(False, True, False, "C2", "C2"))
            self.assertTrue(decision.stop)
            self.assertEqual(decision.reason_code, "AUTHORITY_UNAVAILABLE")
            return

        if case.kind == "escalation_high_cost":
            decision = decide_escalation(EscalationContext(False, True, True, "C5", "C2"))
            self.assertTrue(decision.stop)
            self.assertEqual(decision.action, "human_decision")
            self.assertEqual(decision.reason_code, "COST_EXCEEDS_DIAGNOSTIC_VALUE")
            return

        if case.kind == "escalation_explicit_full":
            decision = decide_escalation(EscalationContext(False, True, True, "C5", "C2", explicit_full=True))
            self.assertFalse(decision.stop)
            self.assertEqual(decision.action, "full")
            self.assertEqual(decision.reason_code, "FULL_EXPLICITLY_AUTHORIZED")
            return

        self.fail(f"unknown scenario kind: {case.kind}")


def _make_test(case: Scenario):
    def test(self: PCDiagnostic100E2ETests) -> None:
        self._run_scenario(case)

    test.__name__ = f"test_{case.id:03d}_{case.name}"
    return test


if len(SCENARIOS) != 100 or tuple(case.id for case in SCENARIOS) != tuple(range(1, 101)):
    raise RuntimeError("PC diagnostic E2E golden set must contain exactly scenarios 1..100")

for _case in SCENARIOS:
    setattr(PCDiagnostic100E2ETests, f"test_{_case.id:03d}_{_case.name}", _make_test(_case))


if __name__ == "__main__":
    unittest.main(verbosity=2)
