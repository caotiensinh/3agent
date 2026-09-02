from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "install_self_hosted_r9_runner.py"
SPEC = importlib.util.spec_from_file_location("install_self_hosted_r9_runner", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def completed(argv, rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(argv, rc, stdout=stdout, stderr=stderr)


class SelfHostedR9RunnerInstallerTests(unittest.TestCase):
    def test_selects_exact_official_linux_x64_asset_and_digest(self) -> None:
        digest = "a" * 64
        release = {
            "tag_name": "v2.400.0",
            "assets": [
                {
                    "name": "actions-runner-linux-x64-2.400.0.tar.gz",
                    "browser_download_url": (
                        "https://github.com/actions/runner/releases/download/"
                        "v2.400.0/actions-runner-linux-x64-2.400.0.tar.gz"
                    ),
                    "digest": f"sha256:{digest}",
                }
            ],
        }
        asset = MODULE._select_linux_x64_asset(release)
        self.assertEqual(asset["version"], "2.400.0")
        self.assertEqual(asset["sha256"], digest)

    def test_release_asset_without_sha256_digest_is_rejected(self) -> None:
        release = {
            "tag_name": "v2.400.0",
            "assets": [
                {
                    "name": "actions-runner-linux-x64-2.400.0.tar.gz",
                    "browser_download_url": (
                        "https://github.com/actions/runner/releases/download/"
                        "v2.400.0/actions-runner-linux-x64-2.400.0.tar.gz"
                    ),
                    "digest": None,
                }
            ],
        }
        with self.assertRaises(ValueError):
            MODULE._select_linux_x64_asset(release)

    def test_non_official_asset_url_is_rejected(self) -> None:
        release = {
            "tag_name": "v2.400.0",
            "assets": [
                {
                    "name": "actions-runner-linux-x64-2.400.0.tar.gz",
                    "browser_download_url": "https://example.invalid/actions-runner.tar.gz",
                    "digest": "sha256:" + "b" * 64,
                }
            ],
        }
        with self.assertRaises(ValueError):
            MODULE._select_linux_x64_asset(release)

    def test_sha256_verification_helper_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "asset"
            path.write_bytes(b"workspace-runner")
            self.assertEqual(
                MODULE._sha256(path),
                "806f73619e8e7bfab499189eeeec02155584e567eda822149f46d35c99c9c24d",
            )

    def test_safe_extract_rejects_parent_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "bad.tar.gz"
            content = root / "payload"
            content.write_text("bad", encoding="utf-8")
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(content, arcname="../escape")
            with self.assertRaises(ValueError):
                MODULE._safe_extract_runner_archive(archive, root / "runner")
            self.assertFalse((root / "escape").exists())

    def test_safe_extract_rejects_symlink_members(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "bad-link.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                info = tarfile.TarInfo("link")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                bundle.addfile(info)
            with self.assertRaises(ValueError):
                MODULE._safe_extract_runner_archive(archive, root / "runner")

    def test_managed_runner_id_requires_our_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = Path(tmp)
            (runner / ".runner").write_text('{"agentId": 42}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                MODULE._load_managed_runner_id(runner)

            (runner / MODULE.MANAGED_MARKER).write_text(
                json.dumps(
                    {
                        "schema": MODULE.MANAGED_MARKER_SCHEMA,
                        "repository_url": MODULE.REPO_URL,
                        "custom_label": "r9",
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(MODULE._load_managed_runner_id(runner), 42)

    def test_unverified_existing_runner_package_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = Path(tmp) / "runner"
            runner.mkdir()
            config = runner / "config.sh"
            config.write_text("#!/bin/sh\n", encoding="utf-8")
            config.chmod(0o755)
            with self.assertRaises(FileExistsError):
                MODULE._prepare_runner_package(
                    runner,
                    command_runner=lambda *_args: self.fail("network must not be used"),
                    environ={},
                )

    def test_two_rtx5090_adds_full_e2e_label(self) -> None:
        self.assertEqual(MODULE._desired_custom_labels(0), ["r9"])
        self.assertEqual(MODULE._desired_custom_labels(1), ["r9"])
        self.assertEqual(MODULE._desired_custom_labels(2), ["r9", "rtx5090"])

    def test_gh_environment_strips_debug_and_runner_tokens(self) -> None:
        env = MODULE._gh_env(
            {
                "PATH": "/bin",
                "GH_DEBUG": "api",
                "GH_TRACE": "1",
                "ACTIONS_RUNNER_TOKEN": "secret-a",
                "ACTIONS_RUNNER_INPUT_TOKEN": "secret-b",
            }
        )
        self.assertEqual(env, {"PATH": "/bin"})

    def test_integration_keeps_registration_token_out_of_output_and_commands(self) -> None:
        secret = "registration-secret-never-print"
        with tempfile.TemporaryDirectory() as tmp:
            runner = Path(tmp) / "runner"
            runner.mkdir()
            config = runner / "config.sh"
            config.write_text("#!/bin/sh\n", encoding="utf-8")
            config.chmod(0o755)
            (runner / MODULE.PACKAGE_MARKER).write_text(
                json.dumps(
                    {
                        "schema": MODULE.PACKAGE_MARKER_SCHEMA,
                        "source_repository": "actions/runner",
                        "version": "2.400.0",
                        "asset_name": "actions-runner-linux-x64-2.400.0.tar.gz",
                        "asset_sha256": "c" * 64,
                        "digest_verified": True,
                    }
                ),
                encoding="utf-8",
            )
            calls = []
            seen_bootstrap_tokens = []

            def fake_command(argv, env=None, capture_output=True):
                argv = list(argv)
                calls.append((argv, dict(env or {})))
                if argv[:3] == ["gh", "auth", "status"]:
                    return completed(argv)
                if argv[:2] == ["sudo", "-v"]:
                    return completed(argv)
                if "registration-token" in " ".join(argv):
                    return completed(argv, stdout=json.dumps({"token": secret}))
                if argv and argv[0] == "nvidia-smi":
                    return completed(argv, stdout="NVIDIA GeForce RTX 5090\nNVIDIA GeForce RTX 5090\n")
                if argv[:2] == ["gh", "api"] and any(
                    part.endswith("/actions/runners/77") for part in argv
                ):
                    return completed(
                        argv,
                        stdout=json.dumps(
                            {
                                "status": "online",
                                "labels": [
                                    {"name": "self-hosted"},
                                    {"name": "Linux"},
                                    {"name": "X64"},
                                    {"name": "r9"},
                                    {"name": "rtx5090"},
                                ],
                            }
                        ),
                    )
                self.fail(f"unexpected command: {argv}")

            class FakeBootstrap:
                @staticmethod
                def bootstrap_runner(**kwargs):
                    seen_bootstrap_tokens.append(kwargs["token"])
                    (runner / ".runner").write_text('{"agentId": 77}\n', encoding="utf-8")
                    (runner / MODULE.MANAGED_MARKER).write_text(
                        json.dumps(
                            {
                                "schema": MODULE.MANAGED_MARKER_SCHEMA,
                                "repository_url": MODULE.REPO_URL,
                                "custom_label": "r9",
                            }
                        ),
                        encoding="utf-8",
                    )
                    return {"status": "READY"}, 0

            labels = []
            with mock.patch.object(MODULE.shutil, "which", return_value="/usr/bin/tool"):
                payload, rc = MODULE.install_runner(
                    runner_dir=runner,
                    runner_name="workspace-r9",
                    system_name="Linux",
                    machine="x86_64",
                    effective_uid=1000,
                    environ={"PATH": "/usr/bin", "GH_DEBUG": "api"},
                    command_runner=fake_command,
                    bootstrap_module=FakeBootstrap,
                    label_sync=lambda runner_id, desired: labels.append((runner_id, list(desired))),
                    sleep=lambda _seconds: None,
                )

            self.assertEqual(rc, 0)
            self.assertEqual(payload["status"], "READY")
            self.assertTrue(payload["server_registration_verified"])
            self.assertEqual(payload["desired_custom_labels"], ["r9", "rtx5090"])
            self.assertEqual(labels, [(77, ["r9", "rtx5090"])])
            self.assertEqual(seen_bootstrap_tokens, [secret])
            rendered = json.dumps(payload)
            self.assertNotIn(secret, rendered)
            for argv, env in calls:
                self.assertNotIn(secret, argv)
                self.assertNotIn(secret, env.values())
                self.assertNotIn("GH_DEBUG", env)

    def test_root_is_refused_before_gh_or_sudo(self) -> None:
        calls = []
        payload, rc = MODULE.install_runner(
            runner_dir=Path("/does/not/matter"),
            runner_name="workspace-r9",
            system_name="Linux",
            machine="x86_64",
            effective_uid=0,
            command_runner=lambda *args: calls.append(args),
        )
        self.assertEqual(rc, 2)
        self.assertEqual(payload["status"], "HELPER_MUST_RUN_UNPRIVILEGED")
        self.assertEqual(calls, [])

    def test_cli_does_not_accept_registration_token(self) -> None:
        parser = MODULE.build_parser()
        stderr = io.StringIO()
        with self.assertRaises(SystemExit), redirect_stderr(stderr):
            parser.parse_args(["--token", "secret"])
        self.assertIn("unrecognized arguments", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
