from __future__ import annotations

import json
import unittest

from three_agent.security_monitoring.correlation_graph import CorrelationEvent
from three_agent.security_monitoring.enriched_parsers import ParsedCanonicalEvent
from three_agent.security_monitoring.parsers import QuarantinedRecord
from three_agent.security_monitoring.windows_evtx_adapter import parse_windows_security_event


def _raw(event_id: int, **overrides) -> str:
    payload = {
        "timestamp": "2026-09-03T00:10:00+09:00",
        "event_id": event_id,
        "asset_id": "asset-win-01",
        "user": "DOMAIN\\alice",
        "source_ip": "10.60.0.50",
    }
    if event_id in {4624, 4625}:
        payload["logon_type"] = 10
    if event_id == 4688:
        payload["process_image"] = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    payload.update(overrides)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class SecurityWindowsEVTXAdapterV019Tests(unittest.TestCase):
    def test_4624_and_4625_reuse_existing_auth_correlation_stage(self) -> None:
        success = parse_windows_security_event(source_id="evtx-security", raw_line=_raw(4624), approved_asset_id="asset-win-01")
        failure = parse_windows_security_event(source_id="evtx-security", raw_line=_raw(4625), approved_asset_id="asset-win-01")
        self.assertIsInstance(success, ParsedCanonicalEvent)
        self.assertIsInstance(failure, ParsedCanonicalEvent)
        assert isinstance(success, ParsedCanonicalEvent)
        assert isinstance(failure, ParsedCanonicalEvent)
        self.assertEqual(success.event.category, "workspace_audit.auth_success")
        self.assertEqual(failure.event.category, "workspace_audit.auth_failure")
        self.assertEqual(CorrelationEvent(success.event, success.entity_context).stage, "AUTH")
        self.assertEqual(CorrelationEvent(failure.event, failure.entity_context).stage, "AUTH")
        rendered = str(success.entity_context.public_dict())
        self.assertNotIn("DOMAIN\\alice", rendered)
        self.assertNotIn("10.60.0.50", rendered)
        self.assertIn("entity:user:sha256:", rendered)
        self.assertIn("entity:ip:sha256:", rendered)

    def test_4688_reuses_existing_process_correlation_stage_without_command_line(self) -> None:
        parsed = parse_windows_security_event(source_id="evtx-security", raw_line=_raw(4688), approved_asset_id="asset-win-01")
        self.assertIsInstance(parsed, ParsedCanonicalEvent)
        assert isinstance(parsed, ParsedCanonicalEvent)
        self.assertEqual(parsed.event.category, "workspace_audit.process_start")
        self.assertEqual(CorrelationEvent(parsed.event, parsed.entity_context).stage, "PROCESS")
        rendered = str(parsed.entity_context.public_dict())
        self.assertNotIn("powershell.exe", rendered.lower())
        self.assertIn("entity:process:sha256:", rendered)

    def test_4672_is_preserved_as_privilege_metadata_not_manufactured_auth_stage(self) -> None:
        parsed = parse_windows_security_event(source_id="evtx-security", raw_line=_raw(4672), approved_asset_id="asset-win-01")
        self.assertIsInstance(parsed, ParsedCanonicalEvent)
        assert isinstance(parsed, ParsedCanonicalEvent)
        self.assertEqual(parsed.event.category, "workspace_audit.auth_privilege")
        self.assertIsNone(CorrelationEvent(parsed.event, parsed.entity_context).stage)

    def test_asset_mismatch_unknown_fields_and_incompatible_projection_quarantine(self) -> None:
        mismatch = parse_windows_security_event(source_id="evtx-security", raw_line=_raw(4624), approved_asset_id="asset-other")
        unknown = parse_windows_security_event(
            source_id="evtx-security",
            raw_line=_raw(4624, command_line="secret-bearing command"),
            approved_asset_id="asset-win-01",
        )
        incompatible = parse_windows_security_event(
            source_id="evtx-security",
            raw_line=_raw(4688, logon_type=10),
            approved_asset_id="asset-win-01",
        )
        self.assertIsInstance(mismatch, QuarantinedRecord)
        self.assertIsInstance(unknown, QuarantinedRecord)
        self.assertIsInstance(incompatible, QuarantinedRecord)
        self.assertEqual(unknown.reason_code, "WINDOWS_EVTX_PROJECTION_INVALID")

    def test_unsupported_event_id_and_logon_type_fail_closed(self) -> None:
        unsupported = parse_windows_security_event(source_id="evtx-security", raw_line=_raw(4720), approved_asset_id="asset-win-01")
        bad_logon = parse_windows_security_event(source_id="evtx-security", raw_line=_raw(4624, logon_type=99), approved_asset_id="asset-win-01")
        self.assertIsInstance(unsupported, QuarantinedRecord)
        self.assertIsInstance(bad_logon, QuarantinedRecord)


if __name__ == "__main__":
    unittest.main()
