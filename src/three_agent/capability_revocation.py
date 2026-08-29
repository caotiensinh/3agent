from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from .config import load_config
from .store import TaskStore

TZ = ZoneInfo("Asia/Tokyo")
REVOCATION_SCHEMA = "workspace-capability-revocation/v1"
REVOCATION_LIST_SCHEMA = "workspace-capability-revocations/v1"
_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-=]{0,127}$")
_REASON_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")


@dataclass(frozen=True)
class CapabilityRevocation:
    task_id: str
    capability: str
    reason_code: str
    revoked_at: str

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": REVOCATION_SCHEMA,
            "task_id": self.task_id,
            "capability": self.capability,
            "reason_code": self.reason_code,
            "revoked_at": self.revoked_at,
        }


class TaskCapabilityRevocationStore:
    """Persistent monotonic operator revocation for TaskContract capabilities.

    Revocation may only narrow an already-bound TaskContract. There is
    intentionally no restore/unrevoke mutation in this baseline.
    """

    def __init__(self, store: TaskStore):
        self.store = store

    def _ensure_schema(self) -> None:
        with self.store.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS task_capability_revocations (
                    task_id TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    revoked_at TEXT NOT NULL,
                    PRIMARY KEY(task_id, capability),
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                )
                """
            )

    @staticmethod
    def _capability(value: object) -> str:
        text = str(value or "").strip()
        if not text or not _COMPACT_RE.fullmatch(text):
            raise ValueError("capability must be a compact identifier")
        return text

    @staticmethod
    def _reason(value: object) -> str:
        text = str(value or "").strip().upper()
        if not _REASON_RE.fullmatch(text):
            raise ValueError("reason_code must be a compact uppercase identifier")
        return text

    def revoke(
        self,
        task_id: str,
        capability: str,
        *,
        reason_code: str = "OPERATOR_REVOKED",
    ) -> CapabilityRevocation:
        task = self.store.get_task(str(task_id).strip())
        contract = self.store.task_contract_for_task(task.task_id)
        if contract is None:
            raise ValueError("TASK_CONTRACT_NOT_BOUND")
        logical = self._capability(capability)
        reason = self._reason(reason_code)
        allowed = contract.get("allowed_tools")
        if not isinstance(allowed, list) or logical not in {str(item) for item in allowed}:
            raise ValueError("CAPABILITY_NOT_IN_BOUND_TASK_CONTRACT")

        self._ensure_schema()
        now = datetime.now(TZ).isoformat()
        created = False
        with self.store.connect() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO task_capability_revocations(
                    task_id, capability, reason_code, revoked_at
                ) VALUES(?,?,?,?)
                """,
                (task.task_id, logical, reason, now),
            )
            created = int(cursor.rowcount or 0) > 0
            row = conn.execute(
                """
                SELECT task_id, capability, reason_code, revoked_at
                FROM task_capability_revocations
                WHERE task_id = ? AND capability = ?
                """,
                (task.task_id, logical),
            ).fetchone()
        if row is None:
            raise RuntimeError("CAPABILITY_REVOCATION_PERSIST_FAILED")
        if created:
            self.store.record_activity(
                task.task_id,
                "capability_broker",
                "capability_revoked",
                "ok",
                f"capability={logical} reason={reason}",
            )
        return CapabilityRevocation(
            task_id=str(row["task_id"]),
            capability=str(row["capability"]),
            reason_code=str(row["reason_code"]),
            revoked_at=str(row["revoked_at"]),
        )

    def is_revoked(self, task_id: str, capability: str) -> bool:
        logical = self._capability(capability)
        self._ensure_schema()
        with self.store.connect() as conn:
            row = conn.execute(
                """
                SELECT 1 FROM task_capability_revocations
                WHERE task_id = ? AND capability = ?
                """,
                (str(task_id).strip(), logical),
            ).fetchone()
        return row is not None

    def list_for_task(self, task_id: str) -> tuple[CapabilityRevocation, ...]:
        task = self.store.get_task(str(task_id).strip())
        self._ensure_schema()
        with self.store.connect() as conn:
            rows = conn.execute(
                """
                SELECT task_id, capability, reason_code, revoked_at
                FROM task_capability_revocations
                WHERE task_id = ?
                ORDER BY capability
                """,
                (task.task_id,),
            ).fetchall()
        return tuple(
            CapabilityRevocation(
                task_id=str(row["task_id"]),
                capability=str(row["capability"]),
                reason_code=str(row["reason_code"]),
                revoked_at=str(row["revoked_at"]),
            )
            for row in rows
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-capability",
        description="Persistent monotonic WorkSpace task capability revocation",
    )
    parser.add_argument("--config", help="Optional WorkSpace config path")
    sub = parser.add_subparsers(dest="command", required=True)
    revoke = sub.add_parser("revoke", help="Permanently narrow one bound task capability")
    revoke.add_argument("task_id")
    revoke.add_argument("capability")
    revoke.add_argument("--reason", default="OPERATOR_REVOKED")
    listing = sub.add_parser("list", help="List persistent revocations for one task")
    listing.add_argument("task_id")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = load_config(args.config)
    store = TaskStore(config.database_path)
    store.initialize()
    revocations = TaskCapabilityRevocationStore(store)
    try:
        if args.command == "revoke":
            payload: dict[str, Any] = revocations.revoke(
                args.task_id,
                args.capability,
                reason_code=args.reason,
            ).to_dict()
        else:
            rows = revocations.list_for_task(args.task_id)
            payload = {
                "schema_version": REVOCATION_LIST_SCHEMA,
                "task_id": args.task_id,
                "revocations": [row.to_dict() for row in rows],
                "monotonic": True,
                "restore_supported": False,
            }
    except (KeyError, ValueError, RuntimeError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": REVOCATION_SCHEMA,
                    "ok": False,
                    "error_type": type(exc).__name__,
                    "reason_code": str(exc) if _REASON_RE.fullmatch(str(exc)) else "CAPABILITY_REVOCATION_FAILED",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 3
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
