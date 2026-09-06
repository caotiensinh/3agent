from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from three_agent.security_monitoring.operator_posture_reader import (
    _read_correlation_events_query_only,
    safe_operator_posture_summary,
)


class SecurityOperatorPostureReaderTests(unittest.TestCase):
    def test_missing_database_is_not_created_or_initialized(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "must-not-be-created.sqlite3"
            config = SimpleNamespace(database_path=database_path)

            events = _read_correlation_events_query_only(config)  # type: ignore[arg-type]
            payload = safe_operator_posture_summary(  # type: ignore[arg-type]
                config,
                now=datetime(2026, 9, 6, 3, 30, tzinfo=timezone.utc),
            )

            self.assertEqual(events, ())
            self.assertFalse(database_path.exists())
            self.assertFalse(payload["database_available"])
            self.assertEqual(payload["data_state"], "unavailable")
            self.assertEqual(payload["correlation"]["incident_graph_count"], 0)  # type: ignore[index]
            self.assertFalse(payload["flow"]["available"])  # type: ignore[index]
            self.assertFalse(payload["timeline"]["available"])  # type: ignore[index]
            authority = payload["authority"]
            assert isinstance(authority, dict)
            self.assertTrue(authority["database_read_only"])
            self.assertFalse(authority["database_write"])
            self.assertFalse(authority["network_execution"])
            self.assertFalse(authority["collector_execution"])
            self.assertFalse(authority["packet_capture_execution"])
            self.assertFalse(authority["remediation_execution"])


if __name__ == "__main__":
    unittest.main()
