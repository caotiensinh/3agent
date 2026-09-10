from __future__ import annotations

from .device_config_history import DeviceConfigSnapshot
from .normalized_evidence import (
    EvidenceIntegrity,
    EvidenceMetadataItem,
    EvidenceObservationWindow,
    EvidenceProvenance,
    EvidenceQuality,
    NormalizedEvidence,
)

DEVICE_CONFIG_NORMALIZER_VERSION = "device-config-normalization-v1"


def normalize_device_config_snapshot(
    snapshot: DeviceConfigSnapshot,
    *,
    sensitivity: str,
    confidence: float,
    completeness: float,
) -> NormalizedEvidence:
    """Project a metadata-only device configuration snapshot into canonical evidence.

    The adapter performs no acquisition and carries no raw configuration text,
    credentials, target host, command, or remediation authority. Evidence quality
    is explicit caller input so the adapter never invents confidence/completeness.
    """

    snapshot.validate()
    asset_ref = snapshot.asset_id if snapshot.asset_id.startswith("asset:") else f"asset:{snapshot.asset_id}"
    lineage_refs = tuple(
        dict.fromkeys((snapshot.source_record_sha256, snapshot.section_set_sha256))
    )
    return NormalizedEvidence.create(
        evidence_type="configuration_snapshot",
        source_type=snapshot.source_type,
        asset_ref=asset_ref,
        task_ref_sha256=snapshot.task_ref_sha256,
        authorization_ref_sha256=snapshot.authorization_ref_sha256,
        collected_at=snapshot.captured_at,
        observation_window=EvidenceObservationWindow(
            snapshot.captured_at,
            snapshot.captured_at,
        ),
        integrity=EvidenceIntegrity(
            content_sha256=snapshot.section_set_sha256,
            source_record_sha256=snapshot.source_record_sha256,
        ),
        sensitivity=sensitivity,
        quality=EvidenceQuality(
            confidence=confidence,
            completeness=completeness,
            flags=("metadata_only", "read_only"),
        ),
        raw_ref=snapshot.snapshot_id,
        provenance=EvidenceProvenance(
            producer=snapshot.producer,
            parser_version=DEVICE_CONFIG_NORMALIZER_VERSION,
            lineage_refs=lineage_refs,
        ),
        metadata=(
            EvidenceMetadataItem("snapshot_id", snapshot.snapshot_id),
            EvidenceMetadataItem("section_digest_ref", snapshot.section_set_sha256),
            EvidenceMetadataItem("section_count", f"metric:section-count:{len(snapshot.sections)}"),
            EvidenceMetadataItem("raw_config_retained", "policy:false"),
        ),
    )
