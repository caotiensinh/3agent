from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4
from zoneinfo import ZoneInfo

from .collectors import CollectorResult
from .contracts import AssetInventoryRecord, HourlyRunReceipt, sha256_fingerprint
from .locking import HourlyRunLockManager
from .plan import CollectorWorkItem, compile_collection_plan
from .policy import MonitoringPolicy
from .storage import MonitoringStore

TOKYO = ZoneInfo("Asia/Tokyo")
CollectorExecutor = Callable[[CollectorWorkItem, AssetInventoryRecord, str, str], CollectorResult]


def hourly_slot_key(profile_id: str, scheduled_at: str) -> str:
    parsed = datetime.fromisoformat(str(scheduled_at).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("scheduled_at must include timezone")
    local = parsed.astimezone(TOKYO)
    return f"hourly:{profile_id}:{local.strftime('%Y-%m-%dT%H')}"


class HourlyMonitoringRunner:
    """Execute one bounded hourly slot using only typed work from approved inventory."""

    def __init__(
        self,
        *,
        store: MonitoringStore,
        policy: MonitoringPolicy,
        execute_work_item: CollectorExecutor,
    ):
        self.store = store
        self.policy = policy.validate()
        self.execute_work_item = execute_work_item
        self.locks = HourlyRunLockManager(store)

    def _next_attempt(self, slot_key: str) -> int:
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(attempt),0) AS n FROM hourly_runs WHERE slot_key=?",
                (slot_key,),
            ).fetchone()
            return int(row["n"]) + 1

    @staticmethod
    def _inventory_fingerprint(assets: tuple[AssetInventoryRecord, ...]) -> str:
        return sha256_fingerprint([asset.fingerprint for asset in assets])

    def _execute_with_retry(
        self,
        item: CollectorWorkItem,
        asset: AssetInventoryRecord,
        run_id: str,
        observed_at: str,
    ) -> tuple[CollectorResult, int]:
        last = CollectorResult((), "COLLECTOR_NOT_RUN")
        for attempt in range(1, self.policy.max_retries + 2):
            try:
                last = self.execute_work_item(item, asset, run_id, observed_at)
            except PermissionError:
                return CollectorResult((), "POLICY_DENIED"), attempt
            except Exception as exc:  # fail closed; exact exception text is not audit data
                last = CollectorResult((), f"COLLECTOR_EXCEPTION_{type(exc).__name__.upper()}")
            if last.failure_code is None:
                return last, attempt
        return last, self.policy.max_retries + 1

    def run(self, *, scheduled_at: str) -> HourlyRunReceipt:
        self.store.initialize()
        assets = self.store.list_enabled_assets()
        slot_key = hourly_slot_key(self.policy.profile_id, scheduled_at)
        owner_id = "owner-" + uuid4().hex
        started_at = datetime.now(timezone.utc).isoformat()
        lock = self.locks.acquire(slot_key=slot_key, owner_id=owner_id, acquired_at=started_at)
        try:
            attempt = self._next_attempt(slot_key)
            run_id = "run-" + sha256_fingerprint([slot_key, attempt, owner_id]).split(":", 1)[1][:24]
            inventory_fingerprint = self._inventory_fingerprint(assets)
            receipt = HourlyRunReceipt(
                run_id=run_id,
                slot_key=slot_key,
                attempt=attempt,
                scheduled_at=scheduled_at,
                started_at=started_at,
                completed_at=None,
                status="collecting",
                inventory_fingerprint=inventory_fingerprint,
                policy_fingerprint=self.policy.fingerprint,
                expected_assets=len(assets),
                observed_assets=0,
                coverage_pct=0.0,
            ).validate()
            self.store.put_hourly_receipt(receipt)

            if not assets:
                final = replace(
                    receipt,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    status="partial",
                    failure_codes=("NO_APPROVED_ASSETS",),
                ).validate()
                self.store.put_hourly_receipt(final)
                return final

            assets_by_id = {asset.asset_id: asset for asset in assets}
            plan = compile_collection_plan(assets)
            results: list[tuple[CollectorWorkItem, CollectorResult, int]] = []
            observed_at = datetime.now(timezone.utc).isoformat()

            with ThreadPoolExecutor(max_workers=self.policy.max_workers, thread_name_prefix="ws-monitor") as pool:
                futures = {
                    pool.submit(
                        self._execute_with_retry,
                        item,
                        assets_by_id[item.asset_id],
                        run_id,
                        observed_at,
                    ): item
                    for item in plan
                }
                for future in as_completed(futures):
                    item = futures[future]
                    result, attempts_used = future.result()
                    results.append((item, result, attempts_used))

            covered_assets: set[str] = set()
            failure_codes: set[str] = set()
            for item, result, attempts_used in results:
                if result.observations:
                    covered_assets.add(item.asset_id)
                    for observation in result.observations:
                        self.store.add_observation(observation)
                if result.failure_code:
                    failure_codes.add(result.failure_code)
                if attempts_used > 1:
                    failure_codes.add("COLLECTOR_RETRIED")

            for asset in assets:
                if asset.asset_id not in covered_assets:
                    failure_codes.add("DATA_GAP_" + asset.asset_id.upper().replace("-", "_"))

            observed_assets = len(covered_assets)
            coverage_pct = (observed_assets / len(assets)) * 100.0
            status = "completed" if observed_assets == len(assets) else "partial"
            final = replace(
                receipt,
                completed_at=datetime.now(timezone.utc).isoformat(),
                status=status,
                observed_assets=observed_assets,
                coverage_pct=coverage_pct,
                failure_codes=tuple(sorted(failure_codes)),
            ).validate()
            self.store.put_hourly_receipt(final)
            return final
        finally:
            self.locks.release(lock)
