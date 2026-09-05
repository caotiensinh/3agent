from __future__ import annotations

from pathlib import Path

TARGET = Path("src/three_agent/security_monitoring/dfir_case_evidence.py")

OLD = '''        for expected_index, event in enumerate(self.events, start=1):
            event.validate()
            if event.event_index != expected_index or event.case_id != first.case_id or event.evidence_id != first.evidence_id:
                raise DFIRCaseEvidenceError("custody chain identity/index mismatch")
            expected_hash = None if previous is None else previous.event_sha256
            if event.previous_event_sha256 != expected_hash:
                raise DFIRCaseEvidenceError("custody previous hash mismatch")
            if previous is not None and event.occurred_at < previous.occurred_at:
                raise DFIRCaseEvidenceError("custody time cannot move backwards")
            previous = event
'''

NEW = '''        for expected_index, event in enumerate(self.events, start=1):
            expected_hash = None if previous is None else previous.event_sha256
            if event.previous_event_sha256 != expected_hash:
                raise DFIRCaseEvidenceError("custody previous hash mismatch")
            event.validate()
            if event.event_index != expected_index or event.case_id != first.case_id or event.evidence_id != first.evidence_id:
                raise DFIRCaseEvidenceError("custody chain identity/index mismatch")
            if previous is not None and event.occurred_at < previous.occurred_at:
                raise DFIRCaseEvidenceError("custody time cannot move backwards")
            previous = event
'''


def main() -> int:
    source = TARGET.read_text(encoding="utf-8")
    if NEW in source:
        print("DFIR custody validation order already canonical")
        return 0
    count = source.count(OLD)
    if count != 1:
        raise SystemExit(f"expected exactly one custody validation block, found {count}")
    TARGET.write_text(source.replace(OLD, NEW, 1), encoding="utf-8")
    print("moved custody chain-link validation before event self-hash validation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
