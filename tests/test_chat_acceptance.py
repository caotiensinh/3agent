from __future__ import annotations

import unittest
from types import SimpleNamespace

from three_agent.chat_acceptance import (
    CHAT_ACCEPTANCE_CORPUS,
    AcceptanceCase,
    contract_summary,
    corpus_sha256,
    corpus_validation_errors,
    endpoint_is_local,
    evaluate_answer,
    run_live_case,
    select_cases,
)


GOOD_ANSWERS = {
    "vi_dns_diagnosis": (
        "Nguyên nhân có khả năng nhất là lỗi phân giải tên DNS; hãy chạy "
        "`nslookup example.com` để kiểm tra."
    ),
    "en_http_404_one_sentence": (
        "HTTP 404 means the requested resource was not found on the server."
    ),
    "ja_network_three_bullets": (
        "- IPアドレスとインターフェース状態を確認します。\n"
        "- ルートとデフォルトゲートウェイを確認します。\n"
        "- DNSの名前解決を確認します。"
    ),
    "vi_https_port_number": "443",
    "en_https_json_only": '{"protocol":"HTTPS","port":443}',
    "ja_linux_ip_code_only": "```bash\nip addr\n```",
    "en_bind_three_bullets": (
        "- The port is already in use by another process.\n"
        "- The process lacks permission or the required privilege.\n"
        "- The configured IP address is not available on the interface."
    ),
    "vi_preserve_model_identifier": (
        "WORKSPACE_LLM_MODEL dùng để chỉ định mô hình LLM mà WorkSpace sử dụng."
    ),
    "ja_ping_traceroute_normal_chat": (
        "ping は宛先への到達性と応答時間を確認し、traceroute は宛先までの経路上の"
        "各ホップを確認します。"
    ),
    "en_translation_one_line": "The service started successfully.",
    "vi_port_8080_two_steps": (
        "- Kiểm tra cổng 8080 bằng `ss -lntp` để xác nhận tiến trình có lắng nghe hay không.\n"
        "- Kiểm tra cấu hình dịch vụ và khởi động lại tiến trình nếu cần."
    ),
    "en_listening_socket_command_only": "ss -lnt",
}


class ChatAcceptanceCorpusTests(unittest.TestCase):
    def test_repository_corpus_is_valid_and_every_case_has_a_good_fixture(self) -> None:
        self.assertEqual(corpus_validation_errors(), ())
        self.assertEqual(
            {case.case_id for case in CHAT_ACCEPTANCE_CORPUS},
            set(GOOD_ANSWERS),
        )
        for case in CHAT_ACCEPTANCE_CORPUS:
            with self.subTest(case=case.case_id):
                result = evaluate_answer(case, GOOD_ANSWERS[case.case_id])
                self.assertTrue(result.passed, result.failures)

    def test_corpus_hash_is_stable_for_same_semantics(self) -> None:
        self.assertEqual(corpus_sha256(), corpus_sha256(tuple(CHAT_ACCEPTANCE_CORPUS)))
        self.assertTrue(corpus_sha256().startswith("sha256:"))

    def test_contract_mode_never_claims_live_model_execution(self) -> None:
        summary = contract_summary(CHAT_ACCEPTANCE_CORPUS[:2])
        self.assertTrue(summary["valid"])
        self.assertFalse(summary["live_model_executed"])
        self.assertEqual(summary["selected_case_count"], 2)

    def test_case_selection_rejects_unknown_ids(self) -> None:
        with self.assertRaises(ValueError):
            select_cases(["not_a_real_case"])


class ChatAcceptanceEvaluatorTests(unittest.TestCase):
    @staticmethod
    def _case(case_id: str) -> AcceptanceCase:
        return next(case for case in CHAT_ACCEPTANCE_CORPUS if case.case_id == case_id)

    def test_wrong_language_prose_fails(self) -> None:
        result = evaluate_answer(
            self._case("en_http_404_one_sentence"),
            "HTTP 404 は要求されたリソースが見つからないことを示します。",
        )
        self.assertFalse(result.passed)
        self.assertIn("direct_chat:target_language_mismatch", result.failures)

    def test_missing_required_concept_fails_even_when_language_is_correct(self) -> None:
        result = evaluate_answer(
            self._case("en_http_404_one_sentence"),
            "HTTP 404 is an HTTP status indicating an error.",
        )
        self.assertFalse(result.passed)
        self.assertTrue(any(item.startswith("missing_required_group:") for item in result.failures))

    def test_research_wrapper_leak_fails(self) -> None:
        result = evaluate_answer(
            self._case("en_http_404_one_sentence"),
            "# WorkSpace Report\nThe requested resource was not found on the server.",
        )
        self.assertFalse(result.passed)
        self.assertIn("direct_chat:workflow_wrapper_leak", result.failures)

    def test_json_object_requires_declared_keys(self) -> None:
        result = evaluate_answer(
            self._case("en_https_json_only"),
            '{"protocol":"HTTPS","value":443}',
        )
        self.assertFalse(result.passed)
        self.assertTrue(any(item.startswith("format:missing_json_keys:") for item in result.failures))

    def test_exact_bullet_count_is_enforced(self) -> None:
        case = self._case("en_bind_three_bullets")
        answer = (
            "- The port is already in use.\n"
            "- The process lacks permission and the configured IP address is unavailable."
        )
        result = evaluate_answer(case, answer)
        self.assertFalse(result.passed)
        self.assertIn("format:bullet_count:2_not_3", result.failures)


class ChatAcceptanceEndpointTests(unittest.TestCase):
    def test_local_and_private_model_endpoints_are_allowed(self) -> None:
        for url in (
            "http://localhost:11434",
            "http://127.0.0.1:11434",
            "http://192.168.11.188:11434",
            "http://10.0.0.5:11434",
            "http://[::1]:11434",
            "http://169.254.10.2:11434",
        ):
            with self.subTest(url=url):
                self.assertTrue(endpoint_is_local(url))

    def test_public_or_hostname_model_endpoints_are_rejected_without_dns_resolution(self) -> None:
        for url in (
            "https://ollama.example.com",
            "http://8.8.8.8:11434",
            "ftp://127.0.0.1:11434",
            "http://0.0.0.0:11434",
            "not-a-url",
        ):
            with self.subTest(url=url):
                self.assertFalse(endpoint_is_local(url))


class FakeLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def generate(self, system_prompt, user_prompt, **kwargs):
        self.calls.append((system_prompt, user_prompt, kwargs))
        return self.responses.pop(0)


class ChatAcceptanceLivePathTests(unittest.TestCase):
    def test_live_case_uses_same_bounded_format_repair_contract(self) -> None:
        case = next(case for case in CHAT_ACCEPTANCE_CORPUS if case.case_id == "vi_https_port_number")
        fake = SimpleNamespace(llm=FakeLLM(["Cổng mặc định là 443.", "443"]))
        result, answer = run_live_case(fake, case)
        self.assertTrue(result.passed, result.failures)
        self.assertEqual(result.attempts, 2)
        self.assertEqual(answer, "443")
        self.assertEqual(len(fake.llm.calls), 2)
        self.assertIn("response format/language/routing validator", fake.llm.calls[1][0])
        self.assertEqual(fake.llm.calls[0][2]["trust_domain"], "workspace-local-chat")
        self.assertEqual(fake.llm.calls[0][2]["template_version"], "workspace.chat.direct.v1")


if __name__ == "__main__":
    unittest.main()
