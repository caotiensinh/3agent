from __future__ import annotations

import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.memory_forensics_contract import (
    MemoryForensicObservation,
    assess_memory_observations,
)


def row(
    observation_id: str,
    *,
    observation_type: str,
    subject_ref: str = "process:sha256:abc123",
    indicator_present: bool = True,
    externally_corroborated: bool = False,
    raw_payload_embedded: bool = False,
    minute: int = 0,
) -> MemoryForensicObservation:
    return MemoryForensicObservation(
        observation_id=observation_id,
        asset_ref="asset:host-a",
        observation_type=observation_type,
        subject_ref=subject_ref,
        observed_at=f"2026-09-03T00:{minute:02d}:00Z",
        evidence_ref=f"evidence:{observation_id}",
        indicator_present=indicator_present,
        externally_corroborated=externally_corroborated,
        raw_payload_embedded=raw_payload_embedded,
    )


class MemoryForensicsContractTests(unittest.TestCase):
    def test_high_signal_requires_corroboration_before_candidate(self) -> None:
        single = assess_memory_observations((row("inject", observation_type="code_injection"),))
        self.assertEqual(single.candidates, ())
        correlated = assess_memory_observations(
            (
                row("inject", observation_type="code_injection", minute=1),
                row("module", observation_type="module", minute=2),
            )
        )
        self.assertEqual(len(correlated.candidates), 1)
        candidate = correlated.candidates[0]
        self.assertEqual(candidate.observation_types, ("code_injection", "module"))
        self.assertIn("multi_evidence_corroboration", candidate.reasons)
        self.assertFalse(correlated.acquisition_performed)
        self.assertEqual(correlated.authority, "advisory")
        self.assertTrue(correlated.fingerprint.startswith("sha256:"))

    def test_external_corroboration_can_support_high_signal_observation(self) -> None:
        assessment = assess_memory_observations(
            (row("yara", observation_type="yara_match", externally_corroborated=True),)
        )
        self.assertEqual(len(assessment.candidates), 1)
        self.assertIn("external_corroboration", assessment.candidates[0].reasons)

    def test_low_signal_metadata_alone_does_not_become_compromise_claim(self) -> None:
        assessment = assess_memory_observations(
            (
                row("socket", observation_type="socket", minute=1),
                row("module", observation_type="module", minute=2),
            )
        )
        self.assertEqual(assessment.candidates, ())

    def test_raw_memory_payload_and_raw_paths_are_rejected(self) -> None:
        with self.assertRaisesRegex(MonitoringContractError, "raw memory payload"):
            row("raw", observation_type="hidden_process", raw_payload_embedded=True).validate()
        with self.assertRaisesRegex(MonitoringContractError, "raw content"):
            row("path", observation_type="module", subject_ref=r"C:\\Windows\\System32\\x.dll").validate()

    def test_analyzer_contract_forbids_acquisition_authority(self) -> None:
        assessment = assess_memory_observations(())
        self.assertFalse(assessment.acquisition_performed)
        invalid = type(assessment)(candidates=(), observations_analyzed=0, acquisition_performed=True)
        with self.assertRaisesRegex(MonitoringContractError, "must not perform acquisition"):
            invalid.validate()


if __name__ == "__main__":
    unittest.main()
