from __future__ import annotations

import inspect
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import three_agent.security_monitoring.incident_capture as incident_capture
from three_agent.security_monitoring.contracts import AssetInventoryRecord, MonitoringContractError
from three_agent.security_monitoring.incident_capture import (
    CAPTURE_CONFIRMATION,
    RECEIPT_SCHEMA,
    IncidentCapturePolicy,
    approve_capture_request,
    cleanup_expired_captures,
    compile_capture_plan,
    execute_capture_approval,
    persist_capture_approval,
    prepare_capture_request,
    verify_capture_approval,
)
from three_agent.security_monitoring.policy import MonitoringPolicy
from three_agent.security_monitoring.runtime_config import MonitoringRuntimeConfig


NOW = datetime(2026, 8, 30, 16, 0, tzinfo=timezone.utc)


def runtime_config(root: Path, *, host: str = "192.0.2.10") -> MonitoringRuntimeConfig:
    return MonitoringRuntimeConfig(
        enabled=True,
        allow_real_network=False,
        database_path=(root / "monitoring.sqlite3").resolve(),
        secret_directory=None,
        policy=MonitoringPolicy(),
        assets=(
            AssetInventoryRecord(
                asset_id="switch-1",
                role="switch",
                management_host=host,
                collector_capabilities=(),
                allowed_tcp_ports=(),
                data_class="confidential",
                enabled=True,
            ),
        ),
    ).validate()


def enabled_policy(root: Path) -> IncidentCapturePolicy:
    approvals = root / "approvals"
    captures = root / "captures"
    approvals.mkdir()
    captures.mkdir()
    tool = root / "tcpdump"
    tool.write_text("synthetic-test-placeholder", encoding="utf-8")
    return IncidentCapturePolicy(
        enabled=True,
        approved_interfaces=("span0",),
        approval_root=approvals.resolve(),
        capture_root=captures.resolve(),
        tcpdump_path=tool.resolve(),
        max_duration_seconds=60,
        max_capture_bytes=2 * 1024 * 1024,
        max_retention_ttl_seconds=3600,
        approval_valid_seconds=300,
        snaplen=1024,
    ).validate()


def request_payload() -> dict[str, object]:
    return {
        "interface": "span0",
        "asset_ids": ["switch-1"],
        "ports": [443],
        "duration_seconds": 15,
        "max_bytes": 512 * 1024,
        "retention_ttl_seconds": 600,
        "purpose": "incident-INC-2026-001",
    }


class CaptureContractTests(unittest.TestCase):
    def test_default_policy_is_disabled_and_requires_no_capture_runtime(self):
        policy = IncidentCapturePolicy.from_environment({})
        self.assertFalse(policy.enabled)
        self.assertEqual(policy.approved_interfaces, ())
        self.assertEqual(policy.snaplen, 2048)

    def test_request_accepts_only_approved_interface_inventory_and_bounded_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = enabled_policy(root)
            config = runtime_config(root)
            request = prepare_capture_request(
                request_payload(), policy=policy, config=config, now=NOW
            )
            self.assertEqual(request.interface, "span0")
            self.assertEqual(request.asset_ids, ("switch-1",))
            self.assertEqual(request.ports, (443,))
            self.assertTrue(request.request_id.startswith("pcap-"))

            bad = dict(request_payload())
            bad["interface"] = "eth0"
            with self.assertRaises(PermissionError):
                prepare_capture_request(bad, policy=policy, config=config, now=NOW)
            bad = dict(request_payload())
            bad["asset_ids"] = ["unknown-device"]
            with self.assertRaises(PermissionError):
                prepare_capture_request(bad, policy=policy, config=config, now=NOW)
            bad = dict(request_payload())
            bad["filter"] = "ip or arp"
            with self.assertRaises(MonitoringContractError):
                prepare_capture_request(bad, policy=policy, config=config, now=NOW)

    def test_hostname_inventory_is_rejected_to_prevent_dns_broadening(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = enabled_policy(root)
            config = runtime_config(root, host="switch.example.internal")
            with self.assertRaises(MonitoringContractError):
                prepare_capture_request(request_payload(), policy=policy, config=config, now=NOW)

    def test_filter_is_compiled_from_inventory_not_user_bpf_and_packet_budget_is_hard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = enabled_policy(root)
            config = runtime_config(root)
            request = prepare_capture_request(request_payload(), policy=policy, config=config, now=NOW)
            plan = compile_capture_plan(request, policy=policy, config=config)
            self.assertEqual(
                plan.filter_tokens,
                ("(", "host", "192.0.2.10", ")", "and", "(", "port", "443", ")"),
            )
            self.assertRegex(plan.filter_sha256, r"^sha256:[0-9a-f]{64}$")
            upper_bound = 24 + plan.max_packets * (policy.snaplen + 16)
            self.assertLessEqual(upper_bound, request.max_bytes)
            self.assertGreater(plan.max_packets, 0)

    def test_admin_approval_is_metadata_only_hash_bound_and_short_lived(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = enabled_policy(root)
            config = runtime_config(root)
            approval = approve_capture_request(
                request_payload(),
                approver_user_id="usr_0123456789abcdef",
                policy=policy,
                config=config,
                now=NOW,
            )
            public = approval.public_dict()
            self.assertNotIn("approved_by_sha256", public)
            self.assertNotIn("filter_expression", public)
            self.assertNotIn("192.0.2.10", json.dumps(public))
            self.assertEqual(
                datetime.fromisoformat(approval.approval_expires_at) - NOW,
                timedelta(seconds=policy.approval_valid_seconds),
            )
            path = persist_capture_approval(approval, policy=policy)
            stored = path.read_text(encoding="utf-8")
            self.assertNotIn("usr_0123456789abcdef", stored)
            self.assertNotIn("192.0.2.10", stored)
            verified = verify_capture_approval(approval, policy=policy, config=config, now=NOW)
            self.assertEqual(verified.filter_sha256, approval.filter_sha256)

    def test_expired_or_changed_policy_approval_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = enabled_policy(root)
            config = runtime_config(root)
            approval = approve_capture_request(
                request_payload(),
                approver_user_id="usr_0123456789abcdef",
                policy=policy,
                config=config,
                now=NOW,
            )
            with self.assertRaises(PermissionError):
                verify_capture_approval(
                    approval,
                    policy=policy,
                    config=config,
                    now=NOW + timedelta(seconds=policy.approval_valid_seconds + 1),
                )
            changed = IncidentCapturePolicy(
                **{
                    **policy.__dict__,
                    "max_duration_seconds": policy.max_duration_seconds - 1,
                }
            ).validate()
            with self.assertRaises(PermissionError):
                verify_capture_approval(approval, policy=changed, config=config, now=NOW)


@unittest.skipUnless(os.name == "posix", "capture execution is intentionally POSIX-only")
class CaptureExecutionTests(unittest.TestCase):
    class FakeProcess:
        def __init__(self, argv, **kwargs):
            self.argv = tuple(argv)
            self.kwargs = kwargs
            output = Path(argv[argv.index("-w") + 1])
            output.write_bytes(b"P" * 256)
            self.returncode = 0

        def wait(self, timeout=None):
            return self.returncode

        def send_signal(self, sig):
            self.returncode = 0

        def kill(self):
            self.returncode = -9

    def test_execute_uses_fixed_argv_shell_false_hash_receipt_and_one_shot_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = enabled_policy(root)
            config = runtime_config(root)
            approval = approve_capture_request(
                request_payload(),
                approver_user_id="usr_0123456789abcdef",
                policy=policy,
                config=config,
                now=NOW,
            )
            approval_path = persist_capture_approval(approval, policy=policy)
            created: list[CaptureExecutionTests.FakeProcess] = []

            def factory(argv, **kwargs):
                process = self.FakeProcess(argv, **kwargs)
                created.append(process)
                return process

            receipt = execute_capture_approval(
                approval_path,
                confirmation=CAPTURE_CONFIRMATION,
                policy=policy,
                config=config,
                now=NOW,
                popen_factory=factory,
            )
            self.assertEqual(len(created), 1)
            process = created[0]
            self.assertFalse(process.kwargs["shell"])
            self.assertEqual(process.argv[0], str(policy.tcpdump_path))
            self.assertIn("-n", process.argv)
            self.assertIn("-s", process.argv)
            self.assertIn("-c", process.argv)
            self.assertIn("span0", process.argv)
            self.assertNotIn("sh", process.argv)
            self.assertEqual(receipt.captured_bytes, 256)
            self.assertRegex(receipt.pcap_sha256, r"^sha256:[0-9a-f]{64}$")
            self.assertTrue((policy.capture_root / f"{receipt.capture_id}.pcap").is_file())
            self.assertTrue((policy.capture_root / f"{receipt.capture_id}.receipt.json").is_file())
            self.assertFalse(approval_path.exists())
            with self.assertRaises(MonitoringContractError):
                execute_capture_approval(
                    approval_path,
                    confirmation=CAPTURE_CONFIRMATION,
                    policy=policy,
                    config=config,
                    now=NOW,
                    popen_factory=factory,
                )

    def test_wrong_confirmation_never_claims_approval_or_invokes_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = enabled_policy(root)
            config = runtime_config(root)
            approval = approve_capture_request(
                request_payload(),
                approver_user_id="usr_0123456789abcdef",
                policy=policy,
                config=config,
                now=NOW,
            )
            path = persist_capture_approval(approval, policy=policy)
            calls = []
            with self.assertRaises(PermissionError):
                execute_capture_approval(
                    path,
                    confirmation="AI_SAYS_CAPTURE",
                    policy=policy,
                    config=config,
                    now=NOW,
                    popen_factory=lambda *args, **kwargs: calls.append(args),
                )
            self.assertEqual(calls, [])
            self.assertTrue(path.exists())


class CaptureRetentionAndSecurityTests(unittest.TestCase):
    def test_retention_cleanup_is_bounded_and_symlink_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = enabled_policy(root)
            capture_id = "pcap-" + "a" * 24
            pcap = policy.capture_root / f"{capture_id}.pcap"
            pcap.write_bytes(b"test")
            receipt = policy.capture_root / f"{capture_id}.receipt.json"
            receipt.write_text(
                json.dumps(
                    {
                        "schema_version": RECEIPT_SCHEMA,
                        "capture_id": capture_id,
                        "retention_expires_at": (NOW - timedelta(seconds=1)).isoformat(),
                    }
                ),
                encoding="utf-8",
            )
            deleted = cleanup_expired_captures(policy=policy, now=NOW, max_deletes=1)
            self.assertEqual(deleted, (capture_id,))
            self.assertFalse(pcap.exists())
            self.assertFalse(receipt.exists())

            if hasattr(os, "symlink"):
                capture_id = "pcap-" + "b" * 24
                target = root / "outside.pcap"
                target.write_bytes(b"outside")
                link = policy.capture_root / f"{capture_id}.pcap"
                try:
                    link.symlink_to(target)
                except OSError:
                    return
                receipt = policy.capture_root / f"{capture_id}.receipt.json"
                receipt.write_text(
                    json.dumps(
                        {
                            "schema_version": RECEIPT_SCHEMA,
                            "capture_id": capture_id,
                            "retention_expires_at": (NOW - timedelta(seconds=1)).isoformat(),
                        }
                    ),
                    encoding="utf-8",
                )
                self.assertEqual(cleanup_expired_captures(policy=policy, now=NOW), ())
                self.assertTrue(target.exists())
                self.assertTrue(receipt.exists())

    def test_capture_module_has_no_model_shell_or_packet_injection_path(self):
        source = inspect.getsource(incident_capture)
        for forbidden in (
            "OllamaClient",
            "generate_json",
            "shell=True",
            "scapy",
            "sendp(",
            "socket.socket",
            "nmap",
            "masscan",
            "iperf",
            "speedtest",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("shell=False", source)
        self.assertIn("CAPTURE_CONFIRMATION", source)


if __name__ == "__main__":
    unittest.main()
