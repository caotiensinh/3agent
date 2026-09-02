from __future__ import annotations

import json

from .contracts import MonitoringContractError
from .discovery_candidates import (
    DISCOVERY_CANDIDATE_SCHEMA,
    DiscoveryCandidate,
    deduplicate_discovery_candidates,
)
from .storage import MonitoringStore

DISCOVERY_CANDIDATE_STORAGE_VERSION = 1

_DISCOVERY_SCHEMA = """
CREATE TABLE IF NOT EXISTS discovery_candidates (
    candidate_id TEXT PRIMARY KEY,
    identity_ref TEXT NOT NULL UNIQUE,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    observation_count INTEGER NOT NULL,
    confidence_basis_points INTEGER NOT NULL,
    provenance_refs_json TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    candidate_fingerprint TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_discovery_candidates_last_seen
    ON discovery_candidates(last_seen, candidate_id);
"""


class DiscoveryCandidateStore:
    """Persist untrusted discovery candidates separately from approved inventory.

    This store deliberately has no enrollment or inventory mutation method. Exact
    replay is idempotent. A new observation for an existing identity may merge only
    when its evidence references are disjoint from the evidence already persisted;
    overlapping-but-different evidence fails closed to avoid double counting.
    """

    def __init__(self, store: MonitoringStore):
        self.store = store

    def initialize(self) -> None:
        self.store.initialize()
        with self.store.connect() as conn:
            conn.executescript(_DISCOVERY_SCHEMA)
            conn.execute(
                "INSERT INTO schema_meta(key,value) VALUES('discovery_candidate_storage_version',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(DISCOVERY_CANDIDATE_STORAGE_VERSION),),
            )

    def schema_version(self) -> int:
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT value FROM schema_meta WHERE key='discovery_candidate_storage_version'"
            ).fetchone()
        if row is None:
            raise RuntimeError("discovery candidate storage is not initialized")
        return int(row["value"])

    @staticmethod
    def _from_row(row) -> DiscoveryCandidate:
        if row["schema_version"] != DISCOVERY_CANDIDATE_SCHEMA:
            raise MonitoringContractError("stored discovery candidate schema is invalid")
        candidate = DiscoveryCandidate(
            candidate_id=row["candidate_id"],
            identity_ref=row["identity_ref"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            observation_count=int(row["observation_count"]),
            confidence_basis_points=int(row["confidence_basis_points"]),
            provenance_refs=tuple(json.loads(row["provenance_refs_json"])),
            evidence_refs=tuple(json.loads(row["evidence_refs_json"])),
        ).validate()
        if row["candidate_fingerprint"] != candidate.fingerprint:
            raise MonitoringContractError("stored discovery candidate fingerprint mismatch")
        return candidate

    def get(self, candidate_id: str) -> DiscoveryCandidate | None:
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM discovery_candidates WHERE candidate_id=?",
                (str(candidate_id),),
            ).fetchone()
        if row is None:
            return None
        return self._from_row(row)

    def _insert(self, candidate: DiscoveryCandidate) -> None:
        with self.store.connect() as conn:
            conn.execute(
                """
                INSERT INTO discovery_candidates(
                    candidate_id,identity_ref,first_seen,last_seen,observation_count,
                    confidence_basis_points,provenance_refs_json,evidence_refs_json,
                    candidate_fingerprint,schema_version
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    candidate.candidate_id,
                    candidate.identity_ref,
                    candidate.first_seen,
                    candidate.last_seen,
                    candidate.observation_count,
                    candidate.confidence_basis_points,
                    json.dumps(list(candidate.provenance_refs), separators=(",", ":")),
                    json.dumps(list(candidate.evidence_refs), separators=(",", ":")),
                    candidate.fingerprint,
                    candidate.schema_version,
                ),
            )

    def _replace(self, candidate: DiscoveryCandidate) -> None:
        with self.store.connect() as conn:
            changed = conn.execute(
                """
                UPDATE discovery_candidates SET
                    first_seen=?,last_seen=?,observation_count=?,confidence_basis_points=?,
                    provenance_refs_json=?,evidence_refs_json=?,candidate_fingerprint=?,
                    schema_version=?,updated_at=CURRENT_TIMESTAMP
                WHERE candidate_id=? AND identity_ref=?
                """,
                (
                    candidate.first_seen,
                    candidate.last_seen,
                    candidate.observation_count,
                    candidate.confidence_basis_points,
                    json.dumps(list(candidate.provenance_refs), separators=(",", ":")),
                    json.dumps(list(candidate.evidence_refs), separators=(",", ":")),
                    candidate.fingerprint,
                    candidate.schema_version,
                    candidate.candidate_id,
                    candidate.identity_ref,
                ),
            ).rowcount
        if changed != 1:
            raise MonitoringContractError("discovery candidate storage identity mutation is forbidden")

    def put(self, candidate: DiscoveryCandidate) -> DiscoveryCandidate:
        incoming = candidate.validate()
        existing = self.get(incoming.candidate_id)
        if existing is None:
            self._insert(incoming)
            return incoming
        if existing.identity_ref != incoming.identity_ref:
            raise MonitoringContractError("discovery candidate identity mutation is forbidden")
        if existing.fingerprint == incoming.fingerprint:
            return existing
        if set(existing.evidence_refs) & set(incoming.evidence_refs):
            raise MonitoringContractError("discovery candidate replay conflicts with persisted evidence")
        merged = deduplicate_discovery_candidates((existing, incoming), max_input_candidates=2, max_output_candidates=1)[0]
        self._replace(merged)
        return merged

    def list_candidates(self, *, limit: int = 1000) -> tuple[DiscoveryCandidate, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10000:
            raise MonitoringContractError("discovery candidate list limit must be within 1..10000")
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM discovery_candidates ORDER BY candidate_id LIMIT ?",
                (limit,),
            ).fetchall()
        return tuple(self._from_row(row) for row in rows)
