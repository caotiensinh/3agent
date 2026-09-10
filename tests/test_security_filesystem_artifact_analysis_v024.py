from __future__ import annotations

import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.filesystem_artifact_analysis import (
    FilesystemArtifactObservation,
    analyze_filesystem_artifacts,
)


def row(
    observation_id: str,
    *,
    artifact_type: str,
    file_ref: str = "file:sha256:abc123",
    execution_observed: bool = False,
    recently_created: bool = False,
    deleted_or_missing: bool = False,
    timestamp_anomaly: bool = False,
    minute: int = 0,
) -> FilesystemArtifactObservation:
    return FilesystemArtifactObservation(
        observation_id=observation_id,
        asset_ref="asset:host-a",
        artifact_type=artifact_type,
        file_ref=file_ref,
        observed_at=f"2026-09-03T00:{minute:02d}:00Z",
        evidence_ref=f"evidence:{observation_id}",
        execution_observed=execution_observed,
        recently_created=recently_created,
        deleted_or_missing=deleted_or_missing,
        timestamp_anomaly=timestamp_anomaly,
    )


class FilesystemArtifactAnalysisTests(unittest.TestCase):
    def test_correlates_multiple_artifact_sources_with_execution_evidence(self) -> None:
        assessment = analyze_filesystem_artifacts(
            (
                row("prefetch", artifact_type="prefetch", execution_observed=True, minute=1),
                row("amcache", artifact_type="amcache", recently_created=True, minute=2),
            )
        )
        self.assertEqual(len(assessment.candidates), 1)
        candidate = assessment.candidates[0]
        self.assertEqual(candidate.artifact_types, ("amcache", "prefetch"))
        self.assertEqual(candidate.reasons, ("execution_observed", "multi_artifact_corroboration", "recently_created"))
        self.assertEqual(candidate.evidence_refs, ("evidence:amcache", "evidence:prefetch"))
        self.assertEqual(assessment.authority, "advisory")
        self.assertTrue(assessment.fingerprint.startswith("sha256:"))

    def test_single_weak_artifact_does_not_create_candidate(self) -> None:
        assessment = analyze_filesystem_artifacts((row("mft", artifact_type="mft", recently_created=True),))
        self.assertEqual(assessment.candidates, ())

    def test_deleted_and_timestamp_anomaly_are_preserved_as_evidence_not_payload(self) -> None:
        assessment = analyze_filesystem_artifacts(
            (row("mft", artifact_type="mft", deleted_or_missing=True, timestamp_anomaly=True),)
        )
        self.assertEqual(len(assessment.candidates), 1)
        self.assertEqual(assessment.candidates[0].reasons, ("deleted_or_missing", "timestamp_anomaly"))

    def test_raw_filesystem_paths_are_rejected(self) -> None:
        invalid = row("raw-path", artifact_type="mft", file_ref=r"C:\\Windows\\Temp\\sample.exe")
        with self.assertRaisesRegex(MonitoringContractError, "filesystem path"):
            invalid.validate()

    def test_rejects_unsupported_artifact_type_and_non_boolean_flags(self) -> None:
        with self.assertRaisesRegex(MonitoringContractError, "unsupported filesystem artifact type"):
            row("unknown", artifact_type="browser_cache").validate()
        invalid = FilesystemArtifactObservation(
            observation_id="bad-bool",
            asset_ref="asset:host-a",
            artifact_type="mft",
            file_ref="file:sha256:abc",
            observed_at="2026-09-03T00:00:00Z",
            evidence_ref="evidence:bad-bool",
            execution_observed=1,  # type: ignore[arg-type]
        )
        with self.assertRaisesRegex(MonitoringContractError, "boolean"):
            invalid.validate()


if __name__ == "__main__":
    unittest.main()
