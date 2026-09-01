from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from .contracts import (
    AssetInventoryRecord,
    MonitoringContractError,
    _compact,
    canonical_json,
    sha256_fingerprint,
)
from .discovery_candidate_store import DiscoveryCandidateStore
from .discovery_candidates import DiscoveryCandidate, discovery_identity_ref
from .storage import MonitoringStore

DISCOVERY_ENROLLMENT_SCHEMA = "workspace-security-monitoring/discovery-enrollment-v1"
DISCOVERY_ENROLLMENT_STORAGE_VERSION = 1

_ENROLLMENT_SCHEMA = """
CREATE TABLE IF NOT EXISTS discovery_enrollment_receipts (
    enrollment_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL,
    candidate_fingerprint TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    asset_fingerprint TEXT NOT NULL,
    operator_approval_ref TEXT NOT NULL,
    enrolled_at TEXT NOT NULL,
    authority TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    UNIQUE(candidate_id, asset_id, operator_approval_ref)
);
CREATE INDEX IF NOT EXISTS idx_discovery_enrollment_asset
    ON discovery_enrollment_receipts(asset_id, enrolled_at);
"""


def _utc(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise MonitoringContractError(f"{field_name} must include timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _approval_ref(value: str) -> str:
    text = str(value or "").strip()
    if not text.startswith("approval-ref:"):
        raise MonitoringContractError("operator approval must use an approval-ref handle")
    suffix = text.removeprefix("approval-ref:")
    return "approval-ref:" + _compact(suffix, "operator_approval_ref", max_len=160)


@dataclass(frozen=True)
class DiscoveryEnrollmentRequest:
    candidate_id: str
    candidate_fingerprint: str
    asset: AssetInventoryRecord
    operator_approval_ref: str

    def validate(self) -> "DiscoveryEnrollmentRequest":
        object.__setattr__(self, "candidate_id", _compact(self.candidate_id, "candidate_id", max_len=128))
        fingerprint = str(self.candidate_fingerprint or "").strip().lower()
        if not fingerprint.startswith("sha256:") or len(fingerprint) != 71:
            raise MonitoringContractError("candidate_fingerprint must be a sha256 digest")
        object.__setattr__(self, "candidate_fingerprint", fingerprint)
        self.asset.validate()
        object.__setattr__(self, "operator_approval_ref", _approval_ref(self.operator_approval_ref))
        return self


@dataclass(frozen=True)
class DiscoveryEnrollmentReceipt:
    enrollment_id: str
    candidate_id: str
    candidate_fingerprint: str
    asset_id: str
    asset_fingerprint: str
    operator_approval_ref: str
    enrolled_at: str
    authority: str = "operator_approved"
    schema_version: str = DISCOVERY_ENROLLMENT_SCHEMA

    def validate(self) -> "DiscoveryEnrollmentReceipt":
        object.__setattr__(self, "enrollment_id", _compact(self.enrollment_id, "enrollment_id", max_len=128))
        object.__setattr__(self, "candidate_id", _compact(self.candidate_id, "candidate_id", max_len=128))
        object.__setattr__(self, "asset_id", _compact(self.asset_id, "asset_id", max_len=128))
        for field_name in ("candidate_fingerprint", "asset_fingerprint"):
            fingerprint = str(getattr(self, field_name) or "").strip().lower()
            if not fingerprint.startswith("sha256:") or len(fingerprint) != 71:
                raise MonitoringContractError(f"{field_name} must be a sha256 digest")
            object.__setattr__(self, field_name, fingerprint)
        object.__setattr__(self, "operator_approval_ref", _approval_ref(self.operator_approval_ref))
        object.__setattr__(self, "enrolled_at", _utc(self.enrolled_at, "enrolled_at"))
        if self.authority != "operator_approved":
            raise MonitoringContractError("discovery enrollment authority must be operator_approved")
        if self.schema_version != DISCOVERY_ENROLLMENT_SCHEMA:
            raise MonitoringContractError("unsupported discovery enrollment schema")
        expected = "enroll-" + sha256_fingerprint(
            {
                "candidate_fingerprint": self.candidate_fingerprint,
                "asset_fingerprint": self.asset_fingerprint,
                "operator_approval_ref": self.operator_approval_ref,
            }
        ).split(":", 1)[1][:24]
        if self.enrollment_id != expected:
            raise MonitoringContractError("enrollment_id must derive from approved enrollment inputs")
        return self

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "asset_fingerprint": self.asset_fingerprint,
            "asset_id": self.asset_id,
            "authority": self.authority,
            "candidate_fingerprint": self.candidate_fingerprint,
            "candidate_id": self.candidate_id,
            "enrolled_at": self.enrolled_at,
            "enrollment_id": self.enrollment_id,
            "operator_approval_ref": self.operator_approval_ref,
            "schema_version": self.schema_version,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


class DiscoveryEnrollmentService:
    """Explicit operator-controlled bridge from untrusted candidate to inventory.

    Discovery evidence never self-promotes. The caller must present an external
    operator approval reference and a complete AssetInventoryRecord. For v1, only
    IP/DNS candidates can be bound automatically because their typed hash can be
    recomputed from the operator-supplied management_host. MAC/device enrollment
    requires a future explicit cross-identity binding contract.
    """

    def __init__(
        self,
        *,
        store: MonitoringStore,
        candidate_store: DiscoveryCandidateStore,
    ) -> None:
        self.store = store
        self.candidate_store = candidate_store

    def initialize(self) -> None:
        self.candidate_store.initialize()
        with self.store.connect() as conn:
            conn.executescript(_ENROLLMENT_SCHEMA)
            conn.execute(
                "INSERT INTO schema_meta(key,value) VALUES('discovery_enrollment_storage_version',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(DISCOVERY_ENROLLMENT_STORAGE_VERSION),),
            )

    @staticmethod
    def _receipt_from_row(row) -> DiscoveryEnrollmentReceipt:
        return DiscoveryEnrollmentReceipt(
            enrollment_id=row["enrollment_id"],
            candidate_id=row["candidate_id"],
            candidate_fingerprint=row["candidate_fingerprint"],
            asset_id=row["asset_id"],
            asset_fingerprint=row["asset_fingerprint"],
            operator_approval_ref=row["operator_approval_ref"],
            enrolled_at=row["enrolled_at"],
            authority=row["authority"],
            schema_version=row["schema_version"],
        ).validate()

    @staticmethod
    def _verify_candidate_binding(candidate: DiscoveryCandidate, asset: AssetInventoryRecord) -> None:
        kind = candidate.identity_kind
        if kind not in {"ip", "dns"}:
            raise MonitoringContractError(
                "MAC/device discovery enrollment requires explicit cross-identity binding"
            )
        if discovery_identity_ref(kind, asset.management_host) != candidate.identity_ref:
            raise MonitoringContractError("approved asset management_host does not match discovery candidate")

    @staticmethod
    def _write_asset_row(conn, asset: AssetInventoryRecord) -> None:
        conn.execute(
            """
            INSERT INTO approved_assets(
                asset_id,role,management_host,collector_capabilities_json,
                allowed_tcp_ports_json,data_class,enabled,credential_ref,asset_fingerprint
            ) VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(asset_id) DO UPDATE SET
                role=excluded.role,
                management_host=excluded.management_host,
                collector_capabilities_json=excluded.collector_capabilities_json,
                allowed_tcp_ports_json=excluded.allowed_tcp_ports_json,
                data_class=excluded.data_class,
                enabled=excluded.enabled,
                credential_ref=excluded.credential_ref,
                asset_fingerprint=excluded.asset_fingerprint,
                updated_at=CURRENT_TIMESTAMP
            """,
            (
                asset.asset_id,
                asset.role,
                asset.management_host,
                json.dumps(list(asset.collector_capabilities), separators=(",", ":")),
                json.dumps(list(asset.allowed_tcp_ports), separators=(",", ":")),
                asset.data_class,
                1 if asset.enabled else 0,
                asset.credential_ref.handle if asset.credential_ref else None,
                asset.fingerprint,
            ),
        )

    def enroll(
        self,
        request: DiscoveryEnrollmentRequest,
        *,
        enrolled_at: str,
    ) -> DiscoveryEnrollmentReceipt:
        approved = request.validate()
        timestamp = _utc(enrolled_at, "enrolled_at")
        candidate = self.candidate_store.get(approved.candidate_id)
        if candidate is None:
            raise MonitoringContractError("discovery enrollment requires an existing candidate")
        if candidate.fingerprint != approved.candidate_fingerprint:
            raise MonitoringContractError("discovery candidate fingerprint changed before enrollment")
        self._verify_candidate_binding(candidate, approved.asset)

        enrollment_id = "enroll-" + sha256_fingerprint(
            {
                "candidate_fingerprint": candidate.fingerprint,
                "asset_fingerprint": approved.asset.fingerprint,
                "operator_approval_ref": approved.operator_approval_ref,
            }
        ).split(":", 1)[1][:24]

        try:
            with self.store.connect() as conn:
                persisted_candidate = conn.execute(
                    "SELECT candidate_fingerprint FROM discovery_candidates WHERE candidate_id=?",
                    (candidate.candidate_id,),
                ).fetchone()
                if persisted_candidate is None:
                    raise MonitoringContractError("discovery candidate disappeared before enrollment")
                if persisted_candidate["candidate_fingerprint"] != approved.candidate_fingerprint:
                    raise MonitoringContractError("discovery candidate changed during enrollment")

                prior_row = conn.execute(
                    "SELECT * FROM discovery_enrollment_receipts WHERE enrollment_id=?",
                    (enrollment_id,),
                ).fetchone()
                if prior_row is not None:
                    prior = self._receipt_from_row(prior_row)
                    asset_row = conn.execute(
                        "SELECT asset_fingerprint FROM approved_assets WHERE asset_id=?",
                        (approved.asset.asset_id,),
                    ).fetchone()
                    if asset_row is None or asset_row["asset_fingerprint"] != approved.asset.fingerprint:
                        raise MonitoringContractError(
                            "enrollment receipt exists but approved inventory state diverged"
                        )
                    return prior

                existing_asset = conn.execute(
                    "SELECT asset_fingerprint FROM approved_assets WHERE asset_id=?",
                    (approved.asset.asset_id,),
                ).fetchone()
                if existing_asset is not None and existing_asset["asset_fingerprint"] != approved.asset.fingerprint:
                    raise MonitoringContractError(
                        "discovery enrollment cannot mutate an existing asset definition"
                    )
                host_owner = conn.execute(
                    "SELECT asset_id FROM approved_assets WHERE management_host=?",
                    (approved.asset.management_host,),
                ).fetchone()
                if host_owner is not None and host_owner["asset_id"] != approved.asset.asset_id:
                    raise MonitoringContractError(
                        "management_host is already owned by another approved asset"
                    )

                receipt = DiscoveryEnrollmentReceipt(
                    enrollment_id=enrollment_id,
                    candidate_id=candidate.candidate_id,
                    candidate_fingerprint=candidate.fingerprint,
                    asset_id=approved.asset.asset_id,
                    asset_fingerprint=approved.asset.fingerprint,
                    operator_approval_ref=approved.operator_approval_ref,
                    enrolled_at=timestamp,
                ).validate()

                self._write_asset_row(conn, approved.asset)
                conn.execute(
                    """
                    INSERT INTO discovery_enrollment_receipts(
                        enrollment_id,candidate_id,candidate_fingerprint,asset_id,asset_fingerprint,
                        operator_approval_ref,enrolled_at,authority,schema_version
                    ) VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        receipt.enrollment_id,
                        receipt.candidate_id,
                        receipt.candidate_fingerprint,
                        receipt.asset_id,
                        receipt.asset_fingerprint,
                        receipt.operator_approval_ref,
                        receipt.enrolled_at,
                        receipt.authority,
                        receipt.schema_version,
                    ),
                )
                return receipt
        except sqlite3.IntegrityError as exc:
            raise MonitoringContractError("discovery enrollment transaction failed") from exc
