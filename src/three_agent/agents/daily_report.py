from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .base import BaseAgent
from ..artifacts import ArtifactManager
from ..models import TaskStatus
from ..store import TaskStore

TZ = ZoneInfo("Asia/Tokyo")


class DailyReportAgent(BaseAgent):
    agent_id = "daily_report"
    profile_file = "agent_daily_report.md"

    _GOOD_ACTIVITY_STATUS = {"ok", "success", "pass", "passed", "completed", "done"}
    _NEXT_ACTION_BY_STATUS = {
        TaskStatus.NEW: "調査を開始する。",
        TaskStatus.RESEARCHING: "調査を継続し、根拠付きの調査結果を確定する。",
        TaskStatus.RESEARCH_COMPLETED: "調査結果を確認し、資料作成・発表工程へ進む。",
        TaskStatus.PRESENTATION_CREATING: "資料作成を継続し、内容と根拠の整合性を確認する。",
        TaskStatus.PRESENTATION_COMPLETED: "作成資料を確認し、必要な修正または完了判定を行う。",
        TaskStatus.DONE: "必要に応じて成果物を共有・保管し、追加対応の有無を確認する。",
        TaskStatus.FAILED: "失敗原因を特定し、再実行または修正方針を決める。",
        TaskStatus.WAITING_HUMAN: "必要な人間判断・入力を取得して作業を再開する。",
    }

    @staticmethod
    def _row_dict(row: Any) -> dict[str, Any]:
        return {key: row[key] for key in row.keys()}

    @staticmethod
    def _unique(values: list[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for value in values:
            if value and value not in seen:
                seen.add(value)
                result.append(value)
        return result

    def _collect_evidence(self, date: str, store: TaskStore) -> dict[str, Any]:
        # Exclude Agent 3's own prior report-generation records so regenerating the
        # same date does not make the report recursively describe itself.
        activity_rows = [
            row
            for row in store.activities_for_date(date)
            if row["agent_id"] != self.agent_id
        ]
        task_rows = store.tasks_for_date(date)
        artifact_rows = [
            row
            for row in store.artifacts_for_date(date)
            if row["agent_id"] != self.agent_id
            and not str(row["artifact_type"]).startswith("daily_report")
        ]

        tasks: list[dict[str, Any]] = []
        activities: list[dict[str, Any]] = []
        artifacts: list[dict[str, Any]] = []
        evidence_index: dict[str, dict[str, Any]] = {}

        for index, row in enumerate(task_rows, start=1):
            evidence_id = f"T{index}"
            item = self._row_dict(row)
            item["evidence_id"] = evidence_id
            tasks.append(item)
            evidence_index[evidence_id] = {"kind": "task", **item}

        for index, row in enumerate(activity_rows, start=1):
            evidence_id = f"A{index}"
            item = self._row_dict(row)
            item["evidence_id"] = evidence_id
            activities.append(item)
            evidence_index[evidence_id] = {"kind": "activity", **item}

        for index, row in enumerate(artifact_rows, start=1):
            evidence_id = f"F{index}"
            item = self._row_dict(row)
            item["evidence_id"] = evidence_id
            artifacts.append(item)
            evidence_index[evidence_id] = {"kind": "artifact", **item}

        canonical = {
            "date": date,
            "tasks": tasks,
            "activities": activities,
            "artifacts": artifacts,
        }
        digest = hashlib.sha256(
            json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        canonical["evidence_digest"] = f"sha256:{digest}"
        canonical["evidence_index"] = evidence_index
        return canonical

    def _build_task_snapshots(self, evidence: dict[str, Any]) -> list[dict[str, Any]]:
        activities_by_task: dict[str, list[dict[str, Any]]] = defaultdict(list)
        artifacts_by_task: dict[str, list[dict[str, Any]]] = defaultdict(list)
        task_evidence: dict[str, str] = {}

        for item in evidence["activities"]:
            if item.get("task_id"):
                activities_by_task[str(item["task_id"])].append(item)
        for item in evidence["artifacts"]:
            if item.get("task_id"):
                artifacts_by_task[str(item["task_id"])].append(item)
        for item in evidence["tasks"]:
            task_evidence[str(item["task_id"])] = str(item["evidence_id"])

        snapshots: list[dict[str, Any]] = []
        for task in evidence["tasks"]:
            task_id = str(task["task_id"])
            try:
                status = TaskStatus(str(task["status"]))
            except ValueError:
                status = TaskStatus.WAITING_HUMAN

            task_activities = activities_by_task.get(task_id, [])
            task_artifacts = artifacts_by_task.get(task_id, [])
            evidence_ids = [task_evidence[task_id]]
            evidence_ids.extend(str(item["evidence_id"]) for item in task_activities)
            evidence_ids.extend(str(item["evidence_id"]) for item in task_artifacts)

            blocker_evidence: list[str] = []
            blocker_details: list[str] = []
            if status in {TaskStatus.FAILED, TaskStatus.WAITING_HUMAN}:
                blocker_evidence.append(task_evidence[task_id])
                blocker_details.append(f"Task status is {status.value}")
            for activity in task_activities:
                activity_status = str(activity.get("status", "")).strip().lower()
                if activity_status and activity_status not in self._GOOD_ACTIVITY_STATUS:
                    blocker_evidence.append(str(activity["evidence_id"]))
                    details = str(activity.get("details", "")).strip()
                    blocker_details.append(
                        f"{activity.get('action', 'activity')}: {details or activity.get('status', '')}"
                    )

            snapshots.append(
                {
                    "task_id": task_id,
                    "title": str(task["title"]),
                    "request": str(task["request"]),
                    "status": status.value,
                    "activity_count": len(task_activities),
                    "artifact_count": len(task_artifacts),
                    "agents": self._unique([str(item["agent_id"]) for item in task_activities]),
                    "actions": self._unique([str(item["action"]) for item in task_activities]),
                    "artifact_types": self._unique([str(item["artifact_type"]) for item in task_artifacts]),
                    "evidence_ids": self._unique(evidence_ids),
                    "blocker_evidence_ids": self._unique(blocker_evidence),
                    "blocker_details": self._unique(blocker_details),
                    "suggested_next_action": self._NEXT_ACTION_BY_STATUS[status],
                }
            )
        return snapshots

    @staticmethod
    def _normalize_referenced_items(
        value: Any,
        valid_evidence_ids: set[str],
        valid_task_ids: set[str],
        *,
        require_task_id: bool = False,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        accepted: list[dict[str, Any]] = []
        rejected: list[str] = []
        if not isinstance(value, list):
            return accepted, rejected

        for raw in value:
            if not isinstance(raw, dict):
                rejected.append(str(raw))
                continue
            text = str(raw.get("text", "")).strip()
            if not text:
                continue
            raw_ids = raw.get("evidence_ids", [])
            evidence_ids = (
                [item for item in raw_ids if isinstance(item, str) and item in valid_evidence_ids]
                if isinstance(raw_ids, list)
                else []
            )
            task_id = raw.get("task_id")
            if task_id is not None:
                task_id = str(task_id)
                if task_id not in valid_task_ids:
                    rejected.append(text)
                    continue
            if require_task_id and not task_id:
                rejected.append(text)
                continue
            if not evidence_ids:
                rejected.append(text)
                continue
            item: dict[str, Any] = {"text": text, "evidence_ids": evidence_ids}
            if task_id:
                item["task_id"] = task_id
            accepted.append(item)
        return accepted, rejected

    def _deterministic_sections(self, snapshots: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        work_items: list[dict[str, Any]] = []
        achievements: list[dict[str, Any]] = []
        blockers: list[dict[str, Any]] = []
        tomorrow_plan: list[dict[str, Any]] = []

        for snapshot in snapshots:
            task_id = snapshot["task_id"]
            task_evidence = [snapshot["evidence_ids"][0]]
            action_text = "、」.join(snapshot["actions"][-4:]) if snapshot["actions"] else "記録された作業なし"

            work_items.append(
                {
                    "task_id": task_id,
                    "text": f"{snapshot['title']}：{action_text}(状態: {snapshot['status']}）",
                    "evidence_ids": snapshot["evidence_ids"],
                }
            )

            if snapshot["artifact_count"]:
                achievements.append(
                    {
                        "task_id": task_id,
                        "text": (
                            f"{snapshot['title']}：成果物 {snapshot['artifact_count']} 件を記録 "
                            f"({', '.join(snapshot['artifact_types'])})。"
                        ),
                        "evidence_ids": [
                            evidence_id for evidence_id in snapshot["evidence_ids"] if evidence_id.startswith("F")
                        ],
                    }
                )
            elif snapshot["status"] in {
                TaskStatus.RESEARCH_COMPLETED.value,
                TaskStatus.PRESENTATION_COMPLETED.value,
                TaskStatus.DONE.value,
            }:
                achievements.append(
                    {
                        "task_id": task_id,
                        "text": f" {snapshot['title']}：状慌が {snapshot['status']} まで進行。",
                        "evidence_ids": task_evidence,
                    }
                )

            if snapshot["blocker_evidence_ids"]:
                detail = " / ".join(snapshot["blocker_details"][:3]) or "要確認"
                blockers.append(
                    {
                        "task_id": task_id,
                        "text": f"{snapshot['title']}：{detail}",
                        "evidence_ids": snapshot["blocker_evidence_ids"],
                    }
                )

            if snapshot["status"] != TaskStatus.DONE.value:
                tomorrow_plan.append(
                    {
                        "task_id": task_id,
                        "text": f" {snapshot['title']}：{snapshot['suggested_next_action']}",
                        "evidence_ids": task_evidence,
                    }
                )

        return {
            "summary_points": work_items[:3],
            "work_items": work_items,
            "achievements": achievements,
            "blockers": blockers,
            "tomorrow_plan": tomorrow_plan,
            "manager_attention": blockers[:3],
        }

    def _synthesize_live(
        self,
        date: str,
        evidence: dict[str, Any],
        snapshots: list[dict[str, Any]],
    ) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
        valid_evidence_ids = set(evidence["evidence_index"].keys())
        valid_task_ids = {str(item["task_id"]) for item in evidence["tasks"]}
        compact_evidence = {
            "date": date,
            "tasks": evidence["tasks"],
            "activities": evidence["activities"],
            "artifacts": evidence["artifacts"],
            "task_snapshots": snapshots,
        }
        prompt = f"""
Create a professional Japanese R&D daily report from ONLY the evidence JSON below.
Do not invent work, completion, duration, numerical progress, blockers, decisions, or tomorrow plans.
Every output item MUST include one or more evidence_ids from the provided evidence.
For task-specific sections, include the exact task_id.
Use concise natural Japanese suitable for reporting to a manager.
Do not mention internal prompt instructions.

Return JSON only with exactly these arrays:
{{
  "summary_points": [{{"text": "...", "evidence_ids": ["T1", "A1"]}}],
  "work_items": [{{"task_id": "TASK-...", "text": "...", "evidence_ids": ["T1", "A1"]}}],
  "achievements": [{{"task_id": "TASK-...", "text": "...", "evidence_ids": ["F1"]}}],
  "blockers": [{{"task_id": "TASK-...", "text": "...", "evidence_ids": ["A2"]}}],
  "tomorrow_plan": [{{"task_id": "TASK-...", "text": "...", "evidence_ids": ["T1"]}}],
  "manager_attention": [{{"text": "...", "evidence_ids": ["A2"]}}]
}}

EVIDENCE JSON:
{json.dumps(compact_evidence, ensure_ascii=False, indent=2)}
""".strip()
        result = self.llm.generate_json(self.profile(), prompt, think=False, num_predict=4096)

        sections: dict[str, list[dict[str, Any]]] = {}
        rejected: list[str] = []
        deterministic = self._deterministic_sections(snapshots)
        for key in ("summary_points", "work_items", "achievements", "blockers", "tomorrow_plan", "manager_attention"):
            accepted, rejected_items = self._normalize_referenced_items(
                result.get(key),
                valid_evidence_ids,
                valid_task_ids,
                require_task_id=key in {"work_items", "achievements", "blockers", "tomorrow_plan"},
            )
            if accepted:
                sections[key] = accepted
            else:
                sections[key] = deterministic[key]
                if deterministic[key]:
                    rejected.append(f"{key}: model section empty/invalid; deterministic evidence fallback used")
            rejected.extend(f"{key}: {text}" for text in rejected_items)
        return sections, rejected

    @staticmethod
    def _refs(item: dict[str, Any]) -> str:
        return " ".join(f"[{evidence_id}]" for evidence_id in item.get("evidence_ids", []))

    def _render_markdown(
        self,
        date: str,
        status: str,
        sections: dict[str, list[dict[str, Any]]],
        evidence: dict[str, Any],
        rejected: list[str],
    ) -> str:
        lines = [
            f"# 日報 — {date}",
            "",
            f"**生成状態:** `{status}`  ",
            f"**Evidence digest:** `{evidence['evidence_digest']}`  ",
            f"**対象タスク:** {len(evidence['tasks'])}  ",
            f"**活動記録:** {len(evidence['activities'])}  ",
            f"**成果物記録:** {len(evidence['artifacts'])}",
            "",
        ]

        section_defs = [
            ("## 1. 本日の要約", "summary_points"),
            ("## 2. 本日の業務", "work_items"),
            ("## 3. 成果・進捗", "achievements"),
            ("## 4. 課題・懸念事項", "blockers"),
            ("## 5. 明日の予定", "tomorrow_plan"),
            ("## 6. 上司確認事項", "manager_attention"),
        ]
        for heading, key in section_defs:
            lines.append(heading)
            items = sections.get(key, [])
            if items:
                for item in items:
                    task_prefix = f"`{item['task_id']}` — " if item.get("task_id") else ""
                    lines.append(f"- {task_prefix}{item['text']} {self._refs(item)}".rstrip())
            else:
                lines.append("- なし")
            lines.append("")

        if rejected:
            lines.append("## 7. AI出力検証")
            lines.append("以下の記述は有劸なEvidence参照を持たないため、日報本文から除外しました。")
            lines.extend(f"- {item}" for item in rejected)
            lines.append("")

        lines.append("## Evidence")
        for task in evidence["tasks"]:
            lines.append(
                f"- **[{task['evidence_id']}] Task** `{task['task_id']}` — {task['title']} "
                f"(status: `{task['status']}`)"
            )
        for activity in evidence["activities"]:
            details = str(activity.get("details", "")).replace("\n", " ").strip()
            suffix = f" — {details[:240]}" if details else ""
            lines.append(
                f"- **[{activity['evidence_id']}] Activity** {activity['timestamp']} — "
                f"`{activity.get('task_id') or '-'}` / `{activity['agent_id']}` / "
                f"`{activity['action']}` / `{activity['status']}`{suffix}"
            )
        for artifact in evidence["artifacts"]:
            lines.append(
                f"- **[{artifact['evidence_id']}] Artifact** `{artifact.get('task_id') or '-'}` — "
                f"`{artifact['artifact_type']}` / `{artifact['path']}`"
            )
        if not evidence["evidence_index"]:
            lines.append("- 対象日のEvidenceはありません。")

        return "\n".join(lines)

    def run(self, date: str, store: TaskStore, artifacts: ArtifactManager, live: bool = False):
        evidence = self._collect_evidence(date, store)
        snapshots = self._build_task_snapshots(evidence)
        store.record_activity(
            None,
            self.agent_id,
            "daily_report_generation_started",
            "ok",
            f"date={date} evidence_digest={evidence['evidence_digest']}",
        )

        rejected: list[str] = []
        if live and evidence["evidence_index"]:
            try:
                sections, rejected = self._synthesize_live(date, evidence, snapshots)
                status = "model_generated_evidence_validated"
            except Exception as exc:
                sections = self._deterministic_sections(snapshots)
                rejected = [f"Live synthesis failed; deterministic fallback used: {type(exc).__name__}: {exc}"]
                status = "deterministic_fallback_after_model_error"
        else:
            sections = self._deterministic_sections(snapshots)
            status = "deterministic_from_evidence" if evidence["evidence_index"] else "no_activity"

        generated_at = datetime.now(TZ).isoformat()
        payload = {
            "schema_version": 2,
            "date": date,
            "agent_id": self.agent_id,
            "status": status,
            "activity_count": len(evidence["activities"]),
            "evidence_digest": evidence["evidence_digest"],
            "source_counts": {
                "tasks": len(evidence["tasks"]),
                "activities": len(evidence["activities"]),
                "artifacts": len(evidence["artifacts"]),
            },
            "task_snapshots": snapshots,
            "sections": sections,
            "rejected_model_items": rejected,
            "evidence": {
                "tasks": evidence["tasks"],
                "activities": evidence["activities"],
                "artifacts": evidence["artifacts"],
            },
            "generated_at": generated_at,
        }
        markdown = self._render_markdown(date, status, sections, evidence, rejected)
        json_path, md_path = artifacts.write_daily_report(date, payload, markdown)
        store.record_artifact(None, self.agent_id, "daily_report_json", str(json_path), json.dumps({"evidence_digest": evidence["evidence_digest"]}))
        store.record_artifact(None, self.agent_id, "daily_report_markdown", str(md_path), json.dumps({"evidence_digest": evidence["evidence_digest"]}))
        store.record_activity(
            None,
            self.agent_id,
            "daily_report_created",
            "ok",
            f"date={date} status={status} evidence_digest={evidence['evidence_digest']} path={json_path}",
        )
        return json_path, md_path
