from __future__ import annotations

import ast
import inspect
import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from three_agent import network_lanl_operator_handoff as handoff
from three_agent import network_lanl_publisher_access as access

ROOT = Path(__file__).resolve().parents[1]
ACCESS_PROFILE = ROOT / "evaluation" / "network_v3_02e_lanl_publisher_access_v1.json"
WORKFLOW = ROOT / ".github" / "workflows" / "lanl-operator-handoff-contract.yml"


def load_profile() -> dict:
    return json.loads(ACCESS_PROFILE.read_text(encoding="utf-8"))


def exact_handles() -> list[str]:
    return [
        "https://csr.lanl.gov/data/auth.txt.gz",
        "https://csr.lanl.gov/data/proc.txt.gz",
        "https://csr.lanl.gov/data/flows.txt.gz",
        "https://csr.lanl.gov/data/dns.txt.gz",
        "https://csr.lanl.gov/data/redteam.txt.gz",
    ]


def prompt_from(values: list[object], prompts: list[str] | None = None):
    queue = iter(values)

    def prompt(text: str) -> str:
        if prompts is not None:
            prompts.append(text)
        value = next(queue)
        if isinstance(value, BaseException):
            raise value
        return value  # type: ignore[return-value]

    return prompt


class LANLOperatorHandoffTests(unittest.TestCase):
    def test_valid_exact_five_handles_are_ready_and_prompt_order_is_safe(self) -> None:
        prompts: list[str] = []
        raw = exact_handles()
        decision = handoff.collect_and_validate_handles(
            load_profile(),
            interactive_tty=True,
            prompt_secret=prompt_from(raw, prompts),
        )
        self.assertEqual(decision.readiness, access.READY)
        self.assertEqual(decision.failed_gate_ids, ())
        self.assertIsNotNone(decision.receipt)
        self.assertEqual(
            prompts,
            [
                "LANL auth (auth.txt.gz) publisher access URL: ",
                "LANL process (proc.txt.gz) publisher access URL: ",
                "LANL flow (flows.txt.gz) publisher access URL: ",
                "LANL dns (dns.txt.gz) publisher access URL: ",
                "LANL redteam (redteam.txt.gz) publisher access URL: ",
            ],
        )
        combined_prompts = "\n".join(prompts)
        for value in raw:
            self.assertNotIn(value, combined_prompts)

    def test_non_tty_fails_security_before_prompt(self) -> None:
        prompt = Mock(side_effect=AssertionError("prompt must not run"))
        with self.assertRaises(access.LANLPublisherAccessError) as caught:
            handoff.collect_and_validate_handles(
                load_profile(), interactive_tty=False, prompt_secret=prompt
            )
        self.assertEqual(caught.exception.readiness, access.FAIL_SECURITY)
        self.assertEqual(caught.exception.gate_id, handoff.HANDOFF_TTY_REQUIRED)
        prompt.assert_not_called()

    def test_eof_before_first_value_is_not_enough(self) -> None:
        with patch.object(handoff, "evaluate_access_handles") as validator:
            decision = handoff.collect_and_validate_handles(
                load_profile(),
                interactive_tty=True,
                prompt_secret=prompt_from([EOFError()]),
            )
        self.assertEqual(decision.readiness, access.NOT_ENOUGH)
        self.assertEqual(decision.failed_gate_ids, (handoff.HANDOFF_CANCELLED,))
        self.assertIsNone(decision.receipt)
        validator.assert_not_called()

    def test_eof_after_partial_values_is_not_enough_without_partial_validation(self) -> None:
        with patch.object(handoff, "evaluate_access_handles") as validator:
            decision = handoff.collect_and_validate_handles(
                load_profile(),
                interactive_tty=True,
                prompt_secret=prompt_from(
                    ["https://csr.lanl.gov/data/auth.txt.gz", EOFError()]
                ),
            )
        self.assertEqual(decision.readiness, access.NOT_ENOUGH)
        self.assertIsNone(decision.receipt)
        validator.assert_not_called()

    def test_empty_value_is_cancelled_without_partial_validation(self) -> None:
        with patch.object(handoff, "evaluate_access_handles") as validator:
            decision = handoff.collect_and_validate_handles(
                load_profile(),
                interactive_tty=True,
                prompt_secret=prompt_from([""]),
            )
        self.assertEqual(decision.readiness, access.NOT_ENOUGH)
        validator.assert_not_called()

    def test_reviewed_validator_is_called_once_after_all_five_handles(self) -> None:
        with patch.object(
            handoff,
            "evaluate_access_handles",
            wraps=access.evaluate_access_handles,
        ) as validator:
            decision = handoff.collect_and_validate_handles(
                load_profile(),
                interactive_tty=True,
                prompt_secret=prompt_from(exact_handles()),
            )
        self.assertEqual(decision.readiness, access.READY)
        validator.assert_called_once()
        supplied = validator.call_args.args[0]
        self.assertEqual(tuple(supplied), access.SOURCE_FAMILIES)

    def _hard_failure(self, replacement: str, readiness: str, gate: str) -> None:
        values = exact_handles()
        values[0] = replacement
        with self.assertRaises(access.LANLPublisherAccessError) as caught:
            handoff.collect_and_validate_handles(
                load_profile(),
                interactive_tty=True,
                prompt_secret=prompt_from(values),
            )
        self.assertEqual(caught.exception.readiness, readiness)
        self.assertEqual(caught.exception.gate_id, gate)
        self.assertNotIn(replacement, str(caught.exception))

    def test_mirror_fails_provenance(self) -> None:
        self._hard_failure(
            "https://mirror.example/auth.txt.gz",
            access.FAIL_PROVENANCE,
            "LANL_MIRROR_OR_ALTERNATE_HOST",
        )

    def test_embedded_userinfo_fails_security(self) -> None:
        self._hard_failure(
            "https://user:password@csr.lanl.gov/data/auth.txt.gz",
            access.FAIL_SECURITY,
            "LANL_ACCESS_HANDLE_HAS_CREDENTIAL_AUTHORITY",
        )

    def test_query_or_fragment_fails_security(self) -> None:
        self._hard_failure(
            "https://csr.lanl.gov/data/auth.txt.gz?token=secret",
            access.FAIL_SECURITY,
            "LANL_UNREVIEWED_QUERY_OR_FRAGMENT",
        )

    def test_wrong_family_filename_fails_provenance(self) -> None:
        self._hard_failure(
            "https://csr.lanl.gov/data/proc.txt.gz",
            access.FAIL_PROVENANCE,
            "LANL_FILENAME_MISMATCH",
        )

    def _invoke_main(self, values: list[object]) -> tuple[int, str, str]:
        out = io.StringIO()
        err = io.StringIO()
        fake_stdin = Mock()
        fake_stdin.isatty.return_value = True
        with (
            patch.object(handoff.sys, "stdin", fake_stdin),
            patch.object(handoff.getpass, "getpass", side_effect=values),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            rc = handoff.main(["--profile", str(ACCESS_PROFILE)])
        return rc, out.getvalue(), err.getvalue()

    def test_success_stdout_and_stderr_never_contain_raw_handles(self) -> None:
        raw = exact_handles()
        rc, stdout, stderr = self._invoke_main(list(raw))
        self.assertEqual(rc, 0)
        payload = json.loads(stdout)
        self.assertEqual(payload["readiness"], access.READY)
        self.assertEqual(set(payload), access.DURABLE_ALLOWED_KEYS)
        for value in raw:
            self.assertNotIn(value, stdout)
            self.assertNotIn(value, stderr)

    def test_failure_stdout_and_stderr_never_contain_raw_handle(self) -> None:
        raw = exact_handles()
        secret = "https://user:password@csr.lanl.gov/data/auth.txt.gz"
        raw[0] = secret
        rc, stdout, stderr = self._invoke_main(list(raw))
        self.assertEqual(rc, 1)
        payload = json.loads(stdout)
        self.assertEqual(payload["readiness"], access.FAIL_SECURITY)
        self.assertEqual(payload["gate_id"], "LANL_ACCESS_HANDLE_HAS_CREDENTIAL_AUTHORITY")
        for value in raw:
            self.assertNotIn(value, stdout)
            self.assertNotIn(value, stderr)

    def test_cancel_stdout_is_safe_and_returns_two(self) -> None:
        raw = "https://csr.lanl.gov/data/auth.txt.gz"
        rc, stdout, stderr = self._invoke_main([raw, EOFError()])
        self.assertEqual(rc, 2)
        payload = json.loads(stdout)
        self.assertEqual(payload["readiness"], access.NOT_ENOUGH)
        self.assertEqual(payload["failed_gate_ids"], [handoff.HANDOFF_CANCELLED])
        self.assertNotIn(raw, stdout + stderr)

    def test_parser_has_no_raw_handle_argument_surface(self) -> None:
        parser = handoff.build_parser()
        options = {
            option
            for action in parser._actions
            for option in action.option_strings
        }
        self.assertEqual(options, {"-h", "--help", "--profile"})
        forbidden = ("url", "handle", "token", "cookie", "email", "purpose", "credential")
        for option in options:
            lowered = option.casefold()
            for word in forbidden:
                self.assertNotIn(word, lowered)

    def test_module_has_no_network_subprocess_model_browser_or_env_authority(self) -> None:
        source = inspect.getsource(handoff)
        tree = ast.parse(source)
        forbidden_modules = {
            "requests",
            "urllib.request",
            "socket",
            "httpx",
            "boto3",
            "subprocess",
            "openai",
            "ollama",
            "selenium",
            "playwright",
            "os",
        }
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotEqual(node.func.id, "input")
        self.assertFalse(imported & forbidden_modules)
        self.assertNotIn("os.environ", source)
        self.assertNotIn("getenv(", source)

    def test_production_main_binds_prompt_to_getpass(self) -> None:
        source = inspect.getsource(handoff.main)
        self.assertIn("prompt_secret=getpass.getpass", source)
        self.assertNotIn("input(", source)

    def test_handle_container_references_are_released_in_finally(self) -> None:
        source = inspect.getsource(handoff.collect_and_validate_handles)
        tree = ast.parse(source)
        tries = [node for node in ast.walk(tree) if isinstance(node, ast.Try)]
        self.assertTrue(tries)
        found_clear = False
        found_reset = False
        for node in tries:
            for item in node.finalbody:
                if (
                    isinstance(item, ast.Expr)
                    and isinstance(item.value, ast.Call)
                    and isinstance(item.value.func, ast.Attribute)
                    and isinstance(item.value.func.value, ast.Name)
                    and item.value.func.value.id == "handles"
                    and item.value.func.attr == "clear"
                ):
                    found_clear = True
                if isinstance(item, ast.Assign):
                    if any(isinstance(target, ast.Name) and target.id == "current_handle" for target in item.targets):
                        found_reset = isinstance(item.value, ast.Constant) and item.value.value is None
        self.assertTrue(found_clear)
        self.assertTrue(found_reset)


class LANLOperatorHandoffWorkflowContractTests(unittest.TestCase):
    def test_workflow_is_exact_head_and_has_no_lanl_network_or_acquisition_step(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("github.event.pull_request.head.sha", text)
        self.assertIn("persist-credentials: false", text)
        for forbidden in (
            "csr.lanl.gov",
            "curl ",
            "wget ",
            "Invoke-WebRequest",
            "aws s3",
            "requests.",
            "boto3",
            "--handles-json",
            "secrets.",
        ):
            self.assertNotIn(forbidden, text)

    def test_workflow_runs_targeted_harness_and_non_tty_fail_closed_check(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("tests.test_network_lanl_operator_handoff", text)
        self.assertIn("LANL_OPERATOR_HANDOFF_TTY_REQUIRED", text)
        self.assertIn("NOT_ENOUGH_REAL_SOURCE_EVIDENCE", text)
        self.assertIn("PYTHONPATH=src", text)


if __name__ == "__main__":
    unittest.main()
