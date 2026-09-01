from __future__ import annotations

from dataclasses import dataclass

from .contracts import MonitoringContractError, _compact
from .enriched_parsers import (
    ParsedCanonicalEvent,
    parse_json_sensor_event_enriched,
    parse_workspace_audit_event,
)
from .entity_context_storage import EventEntityContextStore
from .ingest import SourceMapping
from .parsers import QuarantinedRecord
from .storage import MonitoringStore


@dataclass(frozen=True)
class StructuredEntityIngestReceipt:
    source_id: str
    source_type: str
    status: str
    event_id: str | None
    evidence_ref: str | None
    entity_count: int
    quarantine_reason: str | None = None
    schema_version: str = "workspace-security-monitoring/structured-entity-ingest-receipt-v1"


class StructuredEntityIngestor:
    """Bounded local ingest for entity-aware structured security events."""

    def __init__(
        self,
        *,
        store: MonitoringStore,
        entity_store: EventEntityContextStore,
        max_line_bytes: int = 1024 * 1024,
    ):
        if not 1024 <= int(max_line_bytes) <= 8 * 1024 * 1024:
            raise MonitoringContractError("structured ingest byte bound must be within 1KiB..8MiB")
        self.store = store
        self.entity_store = entity_store
        self.max_line_bytes = int(max_line_bytes)

    def _approved_asset(self, asset_id: str | None, *, required: bool) -> str | None:
        if asset_id is None:
            if required:
                raise MonitoringContractError("workspace_audit requires trusted approved_asset_id")
            return None
        normalized = _compact(asset_id, "approved_asset_id", max_len=128)
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT enabled FROM approved_assets WHERE asset_id=?",
                (normalized,),
            ).fetchone()
        if row is None or int(row["enabled"]) != 1:
            raise MonitoringContractError("approved_asset_id is not an enabled inventory asset")
        return normalized

    def ingest_line(
        self,
        *,
        source: SourceMapping,
        raw_line: str,
        approved_asset_id: str | None = None,
    ) -> StructuredEntityIngestReceipt:
        source.validate()
        if source.source_type not in {"suricata_eve", "zeek_json", "workspace_audit"}:
            raise MonitoringContractError("structured entity ingest source_type is unsupported")
        encoded = str(raw_line).encode("utf-8", errors="replace")
        if len(encoded) > self.max_line_bytes:
            raise MonitoringContractError("structured ingest byte bound exceeded")

        self.entity_store.initialize()
        trusted_asset = self._approved_asset(
            approved_asset_id,
            required=source.source_type == "workspace_audit",
        )
        parsed: ParsedCanonicalEvent | QuarantinedRecord
        if source.source_type == "workspace_audit":
            assert trusted_asset is not None
            parsed = parse_workspace_audit_event(
                source_id=source.source_id,
                raw_line=raw_line,
                approved_asset_id=trusted_asset,
            )
        else:
            parsed = parse_json_sensor_event_enriched(
                source_id=source.source_id,
                source_type=source.source_type,
                raw_line=raw_line,
                approved_asset_id=trusted_asset,
            )

        if isinstance(parsed, QuarantinedRecord):
            self.store.add_quarantine(parsed)
            return StructuredEntityIngestReceipt(
                source_id=source.source_id,
                source_type=source.source_type,
                status="quarantined",
                event_id=None,
                evidence_ref=None,
                entity_count=0,
                quarantine_reason=parsed.reason_code,
            )

        parsed.validate()
        if not parsed.entity_context.references:
            raise MonitoringContractError("correlation-capable event must contain at least one entity reference")
        # Replay recovery is intentional: add_event is idempotent by event_id and
        # EventEntityContextStore.put is immutable/idempotent for the exact context.
        self.store.add_event(parsed.event)
        self.entity_store.put(parsed.entity_context)
        return StructuredEntityIngestReceipt(
            source_id=source.source_id,
            source_type=source.source_type,
            status="accepted",
            event_id=parsed.event.event_id,
            evidence_ref=parsed.event.evidence_ref,
            entity_count=len(parsed.entity_context.references),
        )
