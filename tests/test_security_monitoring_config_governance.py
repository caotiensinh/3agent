from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from three_agent.security_monitoring.config_governance import SecurityMonitoringConfigGovernance
from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.ui_config import SecurityMonitoringUIConfigManager, safe_default_payload


class SecurityMonitoringConfigGovernanceTests(unittest.TestCase):
    def setup_governance(self, root: Path) -> tuple[SecurityMonitoringUIConfigManager, SecurityMonitoringConfigGovernance]:
        manager = SecurityMonitoringUIConfigManager(root / "security_monitoring.json", path_source="test")
        governance = SecurityMonitoringConfigGovernance(
            manager,
            database_path=root / "security_monitoring_governance.sqlite3",
        )
        return manager, governance

    def test_change_requires_actor_reason_and_expected_revision(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            manager, governance = self.setup_governance(Path(td))
            payload = safe_default_payload(manager.path)
            with self.assertRaises(MonitoringContractError):
                governance.apply_change(payload, actor="", reason="approved change", expected_revision=0)
            with self.assertRaises(MonitoringContractError):
                governance.apply_change(payload, actor="admin", reason="", expected_revision=0)
            with self.assertRaises(MonitoringContractError):
                governance.apply_change(payload, actor="admin", reason="approved change", expected_revision=-1)
            self.assertFalse(manager.path.exists())

    def test_governed_change_creates_private_revision_and_valid_audit_chain(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager, governance = self.setup_governance(root)
            payload = safe_default_payload(manager.path)
            result = governance.apply_change(
                payload,
                actor="security-admin@example.internal",
                reason="Initial approved monitoring baseline",
                expected_revision=0,
            )
            self.assertEqual(result["revision"], 1)
            self.assertTrue(result["audit_chain_valid"])
            self.assertFalse(result["drift_detected"])
            state = governance.state()
            self.assertEqual(state.revision, 1)
            self.assertTrue(state.audit_chain_valid)
            self.assertFalse(state.drift_detected)
            self.assertEqual(len(governance.history()), 1)
            if os.name == "posix":
                self.assertEqual(governance.database_path.stat().st_mode & 0o777, 0o600)

    def test_stale_revision_is_rejected_without_overwriting_active_config(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager, governance = self.setup_governance(root)
            baseline = safe_default_payload(manager.path)
            governance.apply_change(
                baseline,
                actor="admin-a",
                reason="Initial baseline",
                expected_revision=0,
            )
            changed = safe_default_payload(manager.path)
            changed["policy"]["max_workers"] = 4
            governance.apply_change(
                changed,
                actor="admin-b",
                reason="Approved bounded monitoring concurrency",
                expected_revision=1,
            )
            stale = safe_default_payload(manager.path)
            stale["policy"]["max_workers"] = 2
            with self.assertRaises(MonitoringContractError):
                governance.apply_change(
                    stale,
                    actor="admin-a",
                    reason="Stale browser save must fail",
                    expected_revision=1,
                )
            active = manager.get()["config"]
            self.assertEqual(active["policy"]["max_workers"], 4)
            self.assertEqual(governance.state().revision, 2)

    def test_out_of_band_config_change_is_detected_as_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager, governance = self.setup_governance(root)
            payload = safe_default_payload(manager.path)
            governance.apply_change(payload, actor="admin", reason="Approved baseline", expected_revision=0)
            bypass = safe_default_payload(manager.path)
            bypass["policy"]["max_workers"] = 3
            manager.save(bypass)
            state = governance.state()
            self.assertTrue(state.drift_detected)
            self.assertNotEqual(state.config_sha256, state.active_config_sha256)

    def test_drift_blocks_future_governed_change_without_overwriting_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager, governance = self.setup_governance(root)
            baseline = safe_default_payload(manager.path)
            governance.apply_change(baseline, actor="admin", reason="Approved baseline", expected_revision=0)
            bypass = safe_default_payload(manager.path)
            bypass["policy"]["max_workers"] = 3
            manager.save(bypass)
            requested = safe_default_payload(manager.path)
            requested["policy"]["max_workers"] = 2
            with self.assertRaisesRegex(MonitoringContractError, "drift detected"):
                governance.apply_change(
                    requested,
                    actor="admin",
                    reason="Must not overwrite out-of-band change",
                    expected_revision=1,
                )
            self.assertEqual(manager.get()["config"]["policy"]["max_workers"], 3)
            self.assertEqual(governance.state().revision, 1)

    def test_existing_untracked_config_requires_explicit_adoption(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager, governance = self.setup_governance(root)
            existing = safe_default_payload(manager.path)
            manager.save(existing)
            changed = safe_default_payload(manager.path)
            changed["policy"]["max_workers"] = 3
            status = governance.status()
            self.assertTrue(status["adoption_required"])
            self.assertFalse(status["writes_allowed"])
            with self.assertRaisesRegex(MonitoringContractError, "explicit adoption"):
                governance.apply_change(
                    changed,
                    actor="admin",
                    reason="No silent legacy takeover",
                    expected_revision=0,
                )
            self.assertEqual(governance.history(), [])

    def test_adopt_existing_config_creates_audited_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager, governance = self.setup_governance(root)
            existing = safe_default_payload(manager.path)
            existing["policy"]["max_workers"] = 3
            manager.save(existing)
            result = governance.adopt_existing(
                actor="security-admin",
                reason="Adopt reviewed legacy configuration into governed baseline",
            )
            self.assertEqual(result["revision"], 1)
            self.assertEqual(manager.get()["config"]["policy"]["max_workers"], 3)
            status = governance.status()
            self.assertEqual(status["change_state"], "governed")
            self.assertTrue(status["writes_allowed"])
            self.assertFalse(status["drift_detected"])

    def test_audit_tampering_is_detected_and_future_change_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager, governance = self.setup_governance(root)
            payload = safe_default_payload(manager.path)
            governance.apply_change(payload, actor="admin", reason="Approved baseline", expected_revision=0)
            with closing(sqlite3.connect(governance.database_path)) as conn:
                with conn:
                    conn.execute("UPDATE audit_events SET reason='tampered' WHERE event_id=1")
            self.assertFalse(governance.verify_audit_chain())
            changed = safe_default_payload(manager.path)
            changed["policy"]["max_workers"] = 3
            with self.assertRaisesRegex(MonitoringContractError, "audit chain"):
                governance.apply_change(
                    changed,
                    actor="admin",
                    reason="Must fail closed after audit tampering",
                    expected_revision=1,
                )
            self.assertEqual(manager.get()["config"]["policy"]["max_workers"], 4)

    def test_rollback_creates_new_revision_instead_of_rewriting_history(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager, governance = self.setup_governance(root)
            first = safe_default_payload(manager.path)
            governance.apply_change(first, actor="admin", reason="Baseline", expected_revision=0)
            second = safe_default_payload(manager.path)
            second["policy"]["max_workers"] = 3
            governance.apply_change(second, actor="admin", reason="Approved capacity change", expected_revision=1)
            result = governance.rollback(
                1,
                actor="security-admin",
                reason="Rollback after change review",
                expected_revision=2,
            )
            self.assertEqual(result["revision"], 3)
            self.assertEqual(manager.get()["config"]["policy"]["max_workers"], 4)
            history = governance.history()
            self.assertEqual([item["revision"] for item in history], [3, 2, 1])
            self.assertEqual(history[0]["source_revision"], 1)
            self.assertTrue(governance.verify_audit_chain())

    def test_missing_runtime_config_after_governed_commit_is_detected_as_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager, governance = self.setup_governance(root)
            payload = safe_default_payload(manager.path)
            governance.apply_change(
                payload,
                actor="security-admin",
                reason="Establish governed production baseline",
                expected_revision=0,
            )
            manager.path.unlink()
            state = governance.state()
            self.assertEqual(state.revision, 1)
            self.assertIsNotNone(state.config_sha256)
            self.assertIsNone(state.active_config_sha256)
            self.assertTrue(state.drift_detected)
            self.assertTrue(state.audit_chain_valid)

    def test_raw_secret_is_rejected_before_governance_history_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager, governance = self.setup_governance(root)
            payload = safe_default_payload(manager.path)
            payload["password"] = "never-store-me"
            with self.assertRaises(MonitoringContractError):
                governance.apply_change(
                    payload,
                    actor="admin",
                    reason="Invalid attempted change",
                    expected_revision=0,
                )
            self.assertEqual(governance.history(), [])
            self.assertFalse(manager.path.exists())


if __name__ == "__main__":
    unittest.main()
