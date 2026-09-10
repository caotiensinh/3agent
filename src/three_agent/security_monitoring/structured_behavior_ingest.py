from __future__ import annotations

from dataclasses import dataclass

from .contracts import MonitoringContractError
from .dns_behavior import DNSBehaviorFeatures, extract_dns_behavior_features
from .dns_behavior_storage import DNSBehaviorFeatureStore
from .entity_context_storage import EventEntityContextStore
from .ingest import SourceMapping
from .parsers import QuarantinedRecord, parse_json_sensor_event
from .storage import MonitoringStore
from .structured_entity_ingest import StructuredEntityIngestReceipt, StructuredEntityIngestor


@dataclass(frozen=True)
class StructuredBehaviorIngestReceipt:
    source_id: str
    source_type: str
    status: str
    event_id: str | None
    evidence_ref: str | None
    entity_count: int
    dns_feature_status: str
    quarantine_reason: str | None = None
    schema_version: str = "workspace-security-monitoring/structured-behavior-ingest-receipt-v1"

    def validate(self) -> "StructuredBehaviorIngestReceipt":
        if self.status not in {"accepted", "quarantined"}:
            raise MonitoringContractError("unsupported structured behavior ingest status")
        if self.dns_feature_status not in {
            "persisted",
            "not_applicable",
            "not_persisted_quarantine",
        }:
            raise MonitoringContractError("unsupported DNS feature ingest status")
        if self.status == "accepted" and (self.event_id is None or self.evidence_ref is None):
            raise MonitoringContractError("accepted structured behavior receipt requires event/evidence refs")
        if self.status == "quarantined" and self.event_id is not None:
            raise MonitoringContractError("quarantined structured behavior receipt must not expose event_id")
        return self


class StructuredBehaviorIngestor:
    """Optional v0.0.4 extension that preserves the v0.0.3 ingest API unchanged.

    DNS feature extraction is completed before canonical/entity persistence so a
    malformed behavior-v1 DNS record cannot leave a newly accepted partial DNS
    event. Database-level feature persistence is replay-recoverable: the v0.0.3
    event/entity writes are idempotent and DNSBehaviorFeatureStore.put() is
    immutable/idempotent for the exact feature.
    """

    def __init__(
        self,
        *,
        store: MonitoringStore,
        entity_store: EventEntityContextStore,
        dns_store: DNSBehaviorFeatureStore,
        max_line_bytes: int = 1024 * 1024,
    ):
        self.store = store
        self.entity_store = entity_store
        self.dns_store = dns_store
        self.entity_ingestor = StructuredEntityIngestor(
            store=store,
            entity_store=entity_store,
            max_line_bytes=max_line_bytes,
        )

    def _prevalidate_dns_feature(
        self,
        *,
        source: SourceMapping,
        raw_line: str,
    ) -> DNSBehaviorFeatures | None:
        if source.source_type not in {"suricata_eve", "zeek_json"}:
            return None
        base = parse_json_sensor_event(
            source_id=source.source_id,
            source_type=source.source_type,
            raw_line=raw_line,
        )
        if isinstance(base, QuarantinedRecord):
            return None
        return extract_dns_behavior_features(
            event_id=base.event_id,
            source_type=source.source_type,
            raw_line=raw_line,
        )

    def ingest_line(
        self,
        *,
        source: SourceMapping,
        raw_line: str,
        approved_asset_id: str | None = None,
    ) -> StructuredBehaviorIngestReceipt:
        source.validate()
        # Behavior validation happens before v0.0.3 canonical/entity writes.
        feature = self._prevalidate_dns_feature(source=source, raw_line=raw_line)
        core: StructuredEntityIngestReceipt = self.entity_ingestor.ingest_line(
            source=source,
            raw_line=raw_line,
            approved_asset_id=approved_asset_id,
        )
        if core.status == "quarantined":
            return StructuredBehaviorIngestReceipt(
                source_id=core.source_id,
                source_type=core.source_type,
                status=core.status,
                event_id=None,
                evidence_ref=None,
                entity_count=0,
                dns_feature_status="not_persisted_quarantine",
                quarantine_reason=core.quarantine_reason,
            ).validate()

        if feature is not None:
            if feature.event_id != core.event_id:
                raise MonitoringContractError("DNS feature event_id does not match accepted canonical event")
            self.dns_store.initialize()
            self.dns_store.put(feature)
            feature_status = "persisted"
        else:
            feature_status = "not_applicable"

        return StructuredBehaviorIngestReceipt(
            source_id=core.source_id,
            source_type=core.source_type,
            status=core.status,
            event_id=core.event_id,
            evidence_ref=core.evidence_ref,
            entity_count=core.entity_count,
            dns_feature_status=feature_status,
            quarantine_reason=None,
        ).validate()
