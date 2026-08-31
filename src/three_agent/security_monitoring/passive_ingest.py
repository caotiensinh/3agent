from __future__ import annotations

from dataclasses import dataclass

from .log_pipeline import EvidencePartitionReceipt, EvidencePartitionWriter
from .passive_sensors import PassiveJsonlSensorAdapter, PassiveSensorHealth
from .storage import MonitoringStore


@dataclass(frozen=True)
class PassiveSensorIngestReceipt:
    source_id: str
    source_type: str
    events_accepted: int
    records_quarantined: int
    partition: EvidencePartitionReceipt | None
    health: PassiveSensorHealth
    status: str
    schema_version: str = "workspace-security-monitoring/passive-ingest-v1"


class PassiveSensorIngestor:
    """Persist one bounded passive batch using existing SQLite/evidence primitives.

    This class never owns sensor lifecycle or network access. The supplied adapter
    can only read an already-existing local JSONL file.
    """

    def __init__(self, *, store: MonitoringStore, partition_writer: EvidencePartitionWriter):
        self.store = store
        self.partition_writer = partition_writer

    def ingest(
        self,
        *,
        adapter: PassiveJsonlSensorAdapter,
        evaluated_at: str,
        partition_id: str,
    ) -> PassiveSensorIngestReceipt:
        batch = adapter.read_batch(evaluated_at=evaluated_at)
        self.store.initialize()
        for event in batch.events:
            self.store.add_event(event)
        for record in batch.quarantined:
            self.store.add_quarantine(record)
        partition = (
            self.partition_writer.write_events(partition_id=partition_id, events=batch.events)
            if batch.events
            else None
        )
        if batch.health.state == "disabled":
            status = "disabled"
        elif batch.health.state == "data_gap":
            status = "data_gap"
        elif batch.quarantined:
            status = "partial"
        else:
            status = "completed"
        return PassiveSensorIngestReceipt(
            source_id=batch.health.source_id,
            source_type=batch.health.source_type,
            events_accepted=len(batch.events),
            records_quarantined=len(batch.quarantined),
            partition=partition,
            health=batch.health,
            status=status,
        )
