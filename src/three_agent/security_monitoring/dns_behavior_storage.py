from __future__ import annotations

import sqlite3

from .contracts import MonitoringContractError
from .dns_behavior import (
    DNS_BEHAVIOR_PARSER_VERSION,
    DNS_BEHAVIOR_SCHEMA,
    DNSBehaviorFeatures,
)
from .storage import MonitoringStore

DNS_BEHAVIOR_STORAGE_VERSION = 1

_DNS_BEHAVIOR_SCHEMA = """
CREATE TABLE IF NOT EXISTS dns_behavior_features (
    event_id TEXT PRIMARY KEY,
    source_type TEXT NOT NULL,
    query_entity_ref TEXT NOT NULL,
    query_length INTEGER NOT NULL,
    label_count INTEGER NOT NULL,
    max_label_length INTEGER NOT NULL,
    shannon_entropy REAL NOT NULL,
    normalized_entropy REAL NOT NULL,
    digit_count INTEGER NOT NULL,
    hyphen_count INTEGER NOT NULL,
    answer_count INTEGER NOT NULL,
    response_code TEXT,
    query_type TEXT,
    schema_version TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    FOREIGN KEY(event_id) REFERENCES canonical_events(event_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_dns_behavior_query_ref
    ON dns_behavior_features(query_entity_ref,event_id);
CREATE INDEX IF NOT EXISTS idx_dns_behavior_response
    ON dns_behavior_features(response_code,event_id);
"""


class DNSBehaviorFeatureStore:
    """Immutable metadata-only DNS feature extension over MonitoringStore."""

    def __init__(self, store: MonitoringStore):
        self.store = store

    def initialize(self) -> None:
        self.store.initialize()
        with self.store.connect() as conn:
            conn.executescript(_DNS_BEHAVIOR_SCHEMA)
            conn.execute(
                "INSERT INTO schema_meta(key,value) VALUES('dns_behavior_schema_version',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(DNS_BEHAVIOR_STORAGE_VERSION),),
            )

    def schema_version(self) -> int:
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT value FROM schema_meta WHERE key='dns_behavior_schema_version'"
            ).fetchone()
        if row is None:
            raise RuntimeError("DNS behavior storage is not initialized")
        return int(row["value"])

    @staticmethod
    def _from_row(row: sqlite3.Row) -> DNSBehaviorFeatures:
        if row["schema_version"] != DNS_BEHAVIOR_SCHEMA:
            raise MonitoringContractError("stored DNS behavior schema is invalid")
        if row["parser_version"] != DNS_BEHAVIOR_PARSER_VERSION:
            raise MonitoringContractError("stored DNS behavior parser version is invalid")
        return DNSBehaviorFeatures(
            event_id=row["event_id"],
            source_type=row["source_type"],
            query_entity_ref=row["query_entity_ref"],
            query_length=int(row["query_length"]),
            label_count=int(row["label_count"]),
            max_label_length=int(row["max_label_length"]),
            shannon_entropy=float(row["shannon_entropy"]),
            normalized_entropy=float(row["normalized_entropy"]),
            digit_count=int(row["digit_count"]),
            hyphen_count=int(row["hyphen_count"]),
            answer_count=int(row["answer_count"]),
            response_code=row["response_code"],
            query_type=row["query_type"],
            schema_version=row["schema_version"],
            parser_version=row["parser_version"],
        ).validate()

    def put(self, feature: DNSBehaviorFeatures) -> None:
        validated = feature.validate()
        with self.store.connect() as conn:
            event = conn.execute(
                "SELECT source_type,category FROM canonical_events WHERE event_id=?",
                (validated.event_id,),
            ).fetchone()
            if event is None:
                raise MonitoringContractError("DNS behavior feature requires existing canonical event")
            if event["source_type"] != validated.source_type:
                raise MonitoringContractError("DNS behavior source_type does not match canonical event")
            expected_category = (
                "suricata.dns" if validated.source_type == "suricata_eve" else "zeek.dns"
            )
            if event["category"] != expected_category:
                raise MonitoringContractError("DNS behavior feature requires canonical DNS event")

            entity = conn.execute(
                "SELECT 1 FROM event_entities "
                "WHERE event_id=? AND kind='dns' AND role='dns_query' AND entity_ref=?",
                (validated.event_id, validated.query_entity_ref),
            ).fetchone()
            if entity is None:
                raise MonitoringContractError(
                    "DNS behavior query reference must match persisted event entity context"
                )

            existing_row = conn.execute(
                "SELECT * FROM dns_behavior_features WHERE event_id=?",
                (validated.event_id,),
            ).fetchone()
            if existing_row is not None:
                existing = self._from_row(existing_row)
                if existing != validated:
                    raise MonitoringContractError("DNS behavior feature mutation is forbidden")
                return

            try:
                conn.execute(
                    """
                    INSERT INTO dns_behavior_features(
                        event_id,source_type,query_entity_ref,query_length,label_count,
                        max_label_length,shannon_entropy,normalized_entropy,digit_count,
                        hyphen_count,answer_count,response_code,query_type,schema_version,
                        parser_version
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        validated.event_id,
                        validated.source_type,
                        validated.query_entity_ref,
                        validated.query_length,
                        validated.label_count,
                        validated.max_label_length,
                        validated.shannon_entropy,
                        validated.normalized_entropy,
                        validated.digit_count,
                        validated.hyphen_count,
                        validated.answer_count,
                        validated.response_code,
                        validated.query_type,
                        validated.schema_version,
                        validated.parser_version,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise MonitoringContractError("DNS behavior feature persistence failed") from exc

    def get(self, event_id: str) -> DNSBehaviorFeatures | None:
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM dns_behavior_features WHERE event_id=?",
                (str(event_id),),
            ).fetchone()
        return None if row is None else self._from_row(row)
