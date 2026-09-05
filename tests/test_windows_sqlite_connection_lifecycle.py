from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from three_agent.security_monitoring.asset_onboarding import SecurityAssetOnboardingService
from three_agent.security_monitoring.config_governance import SecurityMonitoringConfigGovernance


class _ConfigManagerStub:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def get(self) -> dict[str, object]:
        return {"config": {"database_path": str(self.database_path)}}


class WindowsSQLiteConnectionLifecycleTests(unittest.TestCase):
    def test_governance_context_releases_sqlite_handle(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            database_path = Path(td) / "governance.sqlite3"
            governance = SecurityMonitoringConfigGovernance.__new__(
                SecurityMonitoringConfigGovernance
            )
            governance.database_path = database_path

            conn = governance._connect()
            with conn as active:
                active.execute("CREATE TABLE lifecycle_probe(id INTEGER PRIMARY KEY)")

            with self.assertRaisesRegex(sqlite3.ProgrammingError, "closed database"):
                conn.execute("SELECT 1")

    def test_onboarding_readonly_context_releases_sqlite_handle(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            database_path = Path(td) / "monitoring.sqlite3"
            with closing(sqlite3.connect(database_path)) as seed:
                with seed:
                    seed.execute("CREATE TABLE lifecycle_probe(id INTEGER PRIMARY KEY)")

            service = SecurityAssetOnboardingService(_ConfigManagerStub(database_path))
            conn = service._connect_readonly()
            with conn as active:
                self.assertEqual(active.execute("SELECT COUNT(*) FROM lifecycle_probe").fetchone()[0], 0)

            with self.assertRaisesRegex(sqlite3.ProgrammingError, "closed database"):
                conn.execute("SELECT 1")


if __name__ == "__main__":
    unittest.main()
