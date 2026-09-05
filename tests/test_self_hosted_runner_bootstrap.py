from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "configure_self_hosted_runner.py"
SPEC = importlib.util.spec_from_file_location("configure_self_hosted_runner", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SelfHostedRunnerBootstrapTests(unittest.TestCase):
    def _runner_dir(self, root: Path) -> Path:
        runner = root / "actions-runner"
        runner.mkdir()
        for name in ("config.sh", "svc.sh"):
            path = runner / name
            path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            path.chmod(0o755)
        return runner

    def test_missing_token_fails_closed_without_subprocess(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner_dir(Path(tmp))
            calls = []
            payload, rc = MODULE.bootstrap_runner(
                runner_dir=runner,
                token="",
                system_name="Linux",
                machine="x86_64",
                effective_uid=1000,
                environ={},
                run_process=lambda *args: calls.append(args) or 0,
            )
            self.assertEqual(rc, 2)
            self.assertEqual(payload["status"], "TOKEN_MISSING")
            self.assertEqual(calls, [])

    def test_configuration_uses_secret_env_and_fixed_r9_label(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner_dir(Path(tmp))
            calls = []
            token = "test-registration-secret"

            def fake_run(argv, cwd, env):
                calls.append((list(argv), cwd, dict(env)))
                (runner / ".runner").write_text("configured\n", encoding="utf-8")
                return 0

            payload, rc = MODULE.bootstrap_runner(
                runner_dir=runner,
                token=token,
                system_name="Linux",
                machine="x86_64",
                effective_uid=1000,
                environ={"ACTIONS_RUNNER_TOKEN": token, "PATH": os.environ.get("PATH", "")},
                run_process=fake_run,
            )
            self.assertEqual(rc, 0)
            self.assertEqual(payload["status"], "CONFIGURED")
            argv, _, child_env = calls[0]
            self.assertIn("--unattended", argv)
            self.assertEqual(argv[argv.index("--url") + 1], MODULE.REPO_URL)
            self.assertEqual(argv[argv.index("--labels") + 1], "r9")
            self.assertNotIn("--replace", argv)
            self.assertNotIn("--token", argv)
            self.assertNotIn(token, argv)
            self.assertNotIn("ACTIONS_RUNNER_TOKEN", child_env)
            self.assertEqual(child_env["ACTIONS_RUNNER_INPUT_TOKEN"], token)
            marker = json.loads(
                (runner / ".workspace-r9-bootstrap.json").read_text(encoding="utf-8")
            )
            self.assertFalse(marker["contains_secret"])
            self.assertNotIn(token, json.dumps(marker))

    def test_existing_unverified_runner_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner_dir(Path(tmp))
            (runner / ".runner").write_text("preexisting\n", encoding="utf-8")
            calls = []
            payload, rc = MODULE.bootstrap_runner(
                runner_dir=runner,
                token="secret",
                system_name="Linux",
                machine="x86_64",
                effective_uid=1000,
                environ={},
                run_process=lambda *args: calls.append(args) or 0,
            )
            self.assertEqual(rc, 2)
            self.assertEqual(payload["status"], "EXISTING_CONFIGURATION_UNVERIFIED")
            self.assertFalse(payload["replace_existing_runner"])
            self.assertEqual(calls, [])

    def test_default_configuration_does_not_install_or_start_service(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner_dir(Path(tmp))
            calls = []

            def fake_run(argv, cwd, env):
                calls.append(list(argv))
                (runner / ".runner").write_text("configured\n", encoding="utf-8")
                return 0

            payload, rc = MODULE.bootstrap_runner(
                runner_dir=runner,
                token="secret",
                system_name="Linux",
                machine="x86_64",
                effective_uid=1000,
                environ={},
                run_process=fake_run,
            )
            self.assertEqual(rc, 0)
            self.assertFalse(payload["service_install_requested"])
            self.assertEqual(len(calls), 1)
            self.assertTrue(calls[0][0].endswith("config.sh"))

    def test_root_invocation_is_refused_before_runner_or_token_access(self) -> None:
        calls = []
        payload, rc = MODULE.bootstrap_runner(
            runner_dir=Path("/does/not/matter"),
            token="secret",
            system_name="Linux",
            machine="x86_64",
            effective_uid=0,
            environ={},
            run_process=lambda *args: calls.append(args) or 0,
        )
        self.assertEqual(rc, 2)
        self.assertEqual(payload["status"], "HELPER_MUST_RUN_UNPRIVILEGED")
        self.assertEqual(calls, [])

    def test_explicit_service_install_uses_noninteractive_sudo_only_for_service(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner_dir(Path(tmp))
            calls = []
            token = "secret"

            def fake_run(argv, cwd, env):
                calls.append((list(argv), dict(env)))
                if str(argv[0]).endswith("config.sh"):
                    (runner / ".runner").write_text("configured\n", encoding="utf-8")
                if list(argv)[-1] == "install":
                    (runner / ".service").write_text("actions.runner.example.service\n", encoding="utf-8")
                return 0

            payload, rc = MODULE.bootstrap_runner(
                runner_dir=runner,
                token=token,
                install_service=True,
                system_name="Linux",
                machine="x86_64",
                effective_uid=1000,
                environ={"ACTIONS_RUNNER_TOKEN": token},
                run_process=fake_run,
                readiness_probe=lambda: {
                    "status": "READY",
                    "runner_listener_count": 1,
                    "github_reachable": True,
                    "api_github_reachable": True,
                },
            )
            self.assertEqual(rc, 0)
            self.assertEqual(payload["status"], "READY")
            self.assertTrue(payload["service_installed_now"])
            self.assertTrue(calls[0][0][0].endswith("config.sh"))
            self.assertEqual(calls[1][0], ["sudo", "-n", "true"])
            self.assertEqual(calls[2][0][0:2], ["sudo", "-n"])
            self.assertEqual(calls[2][0][-1], "install")
            self.assertEqual(calls[3][0][-1], "start")
            self.assertEqual(calls[4][0][-1], "status")
            for argv, env in calls[1:]:
                self.assertNotIn(token, argv)
                self.assertNotIn("ACTIONS_RUNNER_TOKEN", env)
                self.assertNotIn("ACTIONS_RUNNER_INPUT_TOKEN", env)
            self.assertNotIn(token, json.dumps(payload))

    def test_service_privilege_failure_is_explicit_and_non_mutating(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner_dir(Path(tmp))
            calls = []

            def fake_run(argv, cwd, env):
                calls.append(list(argv))
                if str(argv[0]).endswith("config.sh"):
                    (runner / ".runner").write_text("configured\n", encoding="utf-8")
                    return 0
                if list(argv) == ["sudo", "-n", "true"]:
                    return 1
                self.fail(f"unexpected privileged command: {argv}")

            payload, rc = MODULE.bootstrap_runner(
                runner_dir=runner,
                token="secret",
                install_service=True,
                system_name="Linux",
                machine="x86_64",
                effective_uid=1000,
                environ={},
                run_process=fake_run,
            )
            self.assertEqual(rc, 4)
            self.assertEqual(payload["status"], "SERVICE_PRIVILEGE_REQUIRED")
            self.assertTrue(payload["configuration_performed"])
            self.assertFalse(payload["service_mutation_performed"])
            self.assertEqual(len(calls), 2)

    def test_marker_backed_rerun_uses_existing_service_without_token_or_reinstall(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner_dir(Path(tmp))
            (runner / ".runner").write_text("configured\n", encoding="utf-8")
            (runner / ".service").write_text("actions.runner.example.service\n", encoding="utf-8")
            MODULE._write_marker(runner)
            calls = []

            def fake_run(argv, cwd, env):
                calls.append(list(argv))
                return 0

            payload, rc = MODULE.bootstrap_runner(
                runner_dir=runner,
                token="",
                install_service=True,
                system_name="Linux",
                machine="x86_64",
                effective_uid=1000,
                environ={},
                run_process=fake_run,
                readiness_probe=lambda: {"status": "READY"},
            )
            self.assertEqual(rc, 0)
            self.assertEqual(payload["status"], "READY")
            self.assertFalse(payload["service_installed_now"])
            self.assertEqual(calls[0], ["sudo", "-n", "true"])
            self.assertEqual(calls[1][-1], "start")
            self.assertEqual(calls[2][-1], "status")
            self.assertFalse(any(call[-1] == "install" for call in calls))

    def test_marker_backed_rerun_installs_missing_service_without_new_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner_dir(Path(tmp))
            (runner / ".runner").write_text("configured\n", encoding="utf-8")
            MODULE._write_marker(runner)
            calls = []

            def fake_run(argv, cwd, env):
                calls.append(list(argv))
                return 0

            payload, rc = MODULE.bootstrap_runner(
                runner_dir=runner,
                token="",
                install_service=True,
                system_name="Linux",
                machine="x86_64",
                effective_uid=1000,
                environ={},
                run_process=fake_run,
                readiness_probe=lambda: {"status": "READY"},
            )
            self.assertEqual(rc, 0)
            self.assertEqual(payload["status"], "READY")
            self.assertTrue(payload["service_installed_now"])
            self.assertEqual(calls[0], ["sudo", "-n", "true"])
            self.assertEqual([call[-1] for call in calls[1:]], ["install", "start", "status"])

    def test_config_failure_is_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner_dir(Path(tmp))
            secret = "never-echo-this"
            payload, rc = MODULE.bootstrap_runner(
                runner_dir=runner,
                token=secret,
                system_name="Linux",
                machine="x86_64",
                effective_uid=1000,
                environ={},
                run_process=lambda *_args: 17,
            )
            rendered = json.dumps(payload)
            self.assertEqual(rc, 2)
            self.assertEqual(payload["status"], "CONFIGURATION_FAILED")
            self.assertEqual(payload["configuration_return_code"], 17)
            self.assertNotIn(secret, rendered)

    def test_unsupported_host_fails_before_token_or_runner_access(self) -> None:
        payload, rc = MODULE.bootstrap_runner(
            runner_dir=Path("/does/not/matter"),
            token="secret",
            system_name="Windows",
            machine="AMD64",
            effective_uid=1000,
            environ={},
        )
        self.assertEqual(rc, 2)
        self.assertEqual(payload["status"], "UNSUPPORTED_HOST")

    def test_cli_has_no_token_option(self) -> None:
        parser = MODULE.build_parser()
        stderr = io.StringIO()
        with self.assertRaises(SystemExit), redirect_stderr(stderr):
            parser.parse_args(["--runner-dir", "/tmp/runner", "--token", "secret"])
        self.assertIn("unrecognized arguments", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
