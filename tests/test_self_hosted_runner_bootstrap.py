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
                environ={},
                run_process=fake_run,
            )
            self.assertEqual(rc, 0)
            self.assertFalse(payload["service_install_requested"])
            self.assertEqual(len(calls), 1)
            self.assertTrue(calls[0][0].endswith("config.sh"))

    def test_explicit_service_install_runs_install_start_status_and_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner_dir(Path(tmp))
            calls = []

            def fake_run(argv, cwd, env):
                calls.append(list(argv))
                if str(argv[0]).endswith("config.sh"):
                    (runner / ".runner").write_text("configured\n", encoding="utf-8")
                return 0

            payload, rc = MODULE.bootstrap_runner(
                runner_dir=runner,
                token="secret",
                install_service=True,
                system_name="Linux",
                machine="x86_64",
                environ={},
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
            self.assertEqual(
                [call[1:] for call in calls[1:]],
                [["install"], ["start"], ["status"]],
            )
            self.assertNotIn("secret", json.dumps(payload))

    def test_marker_backed_rerun_can_install_service_without_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner_dir(Path(tmp))
            (runner / ".runner").write_text("configured\n", encoding="utf-8")
            MODULE._write_marker(runner)
            calls = []
            responses = iter([1, 0, 0, 0])

            def fake_run(argv, cwd, env):
                calls.append(list(argv))
                return next(responses)

            payload, rc = MODULE.bootstrap_runner(
                runner_dir=runner,
                token="",
                install_service=True,
                system_name="Linux",
                machine="x86_64",
                environ={},
                run_process=fake_run,
                readiness_probe=lambda: {"status": "READY"},
            )
            self.assertEqual(rc, 0)
            self.assertEqual(payload["status"], "READY")
            self.assertEqual(
                [call[1:] for call in calls],
                [["status"], ["install"], ["start"], ["status"]],
            )

    def test_config_failure_is_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner_dir(Path(tmp))
            secret = "never-echo-this"
            payload, rc = MODULE.bootstrap_runner(
                runner_dir=runner,
                token=secret,
                system_name="Linux",
                machine="x86_64",
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
