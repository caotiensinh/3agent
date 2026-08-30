from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as xml_escape
from zoneinfo import ZoneInfo

from .privacy import redact_sensitive_text

TZ = ZoneInfo("Asia/Tokyo")

WORKFLOW_SPEC_SCHEMA = "workspace-dispatch-spec/v1"
WORKFLOW_DRAFT_SCHEMA = "workspace-dispatch-draft/v1"
MAX_DESCRIPTION_CHARS = 12000
MAX_NODES = 12
MAX_PARALLEL_DISPATCH = 2
MAX_LABEL_CHARS = 80
MAX_OBJECTIVE_CHARS = 600
_NODE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_WORKFLOW_ID_RE = re.compile(r"^wf_[0-9a-f]{24}$")
_ALLOWED_KINDS = {
    "analysis",
    "research",
    "presentation",
    "verify",
    "daily_report",
    "human_approval",
}
_STANDARD_KINDS = ("research", "presentation", "verify", "daily_report")

_WORKFLOW_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "title": {"type": "string", "minLength": 1, "maxLength": 120},
        "summary": {"type": "string", "minLength": 1, "maxLength": 600},
        "nodes": {
            "type": "array",
            "minItems": 2,
            "maxItems": MAX_NODES,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "id": {
                        "type": "string",
                        "pattern": r"^[a-z][a-z0-9_]{0,31}$",
                    },
                    "label": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_LABEL_CHARS,
                    },
                    "kind": {
                        "type": "string",
                        "enum": sorted(_ALLOWED_KINDS),
                    },
                    "objective": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_OBJECTIVE_CHARS,
                    },
                    "depends_on": {
                        "type": "array",
                        "maxItems": MAX_NODES,
                        "uniqueItems": True,
                        "items": {
                            "type": "string",
                            "pattern": r"^[a-z][a-z0-9_]{0,31}$",
                        },
                    },
                    "requires_approval": {"type": "boolean"},
                },
                "required": [
                    "id",
                    "label",
                    "kind",
                    "objective",
                    "depends_on",
                    "requires_approval",
                ],
            },
        },
    },
    "required": ["title", "summary", "nodes"],
}


class WorkflowDispatchError(ValueError):
    pass


@dataclass(frozen=True)
class DispatchPlan:
    schema_version: str
    title: str
    summary: str
    nodes: tuple[dict[str, Any], ...]
    waves: tuple[tuple[str, ...], ...]
    dispatch_batches: tuple[tuple[str, ...], ...]
    mermaid: str
    diagram_svg: str
    spec_sha256: str
    execution_ready: bool
    execution_template: str | None
    execution_reason: str
    approval_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["nodes"] = list(self.nodes)
        payload["waves"] = [list(wave) for wave in self.waves]
        payload["dispatch_batches"] = [list(batch) for batch in self.dispatch_batches]
        return payload


def _canonical_sha256(payload: Any) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _clean_text(value: Any, *, field: str, limit: int) -> str:
    if not isinstance(value, str):
        raise WorkflowDispatchError(f"{field} must be a string")
    text = " ".join(value.replace("\x00", " ").split()).strip()
    if not text:
        raise WorkflowDispatchError(f"{field} must not be empty")
    if len(text) > limit:
        raise WorkflowDispatchError(f"{field} exceeds {limit} characters")
    return text


def _normalize_spec(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {"title", "summary", "nodes"}:
        raise WorkflowDispatchError("workflow output has an invalid top-level shape")
    title = _clean_text(payload["title"], field="title", limit=120)
    summary = _clean_text(payload["summary"], field="summary", limit=600)
    raw_nodes = payload["nodes"]
    if not isinstance(raw_nodes, list) or not 2 <= len(raw_nodes) <= MAX_NODES:
        raise WorkflowDispatchError(
            f"workflow must contain between 2 and {MAX_NODES} nodes"
        )

    nodes: list[dict[str, Any]] = []
    ids: set[str] = set()
    expected_keys = {
        "id",
        "label",
        "kind",
        "objective",
        "depends_on",
        "requires_approval",
    }
    for index, raw in enumerate(raw_nodes):
        if not isinstance(raw, dict) or set(raw) != expected_keys:
            raise WorkflowDispatchError(f"node[{index}] has an invalid shape")
        node_id = str(raw["id"]).strip().lower()
        if not _NODE_ID_RE.fullmatch(node_id):
            raise WorkflowDispatchError(f"invalid node id: {node_id!r}")
        if node_id in ids:
            raise WorkflowDispatchError(f"duplicate node id: {node_id}")
        ids.add(node_id)
        kind = str(raw["kind"]).strip().lower()
        if kind not in _ALLOWED_KINDS:
            raise WorkflowDispatchError(f"unsupported node kind: {kind}")
        dependencies = raw["depends_on"]
        if not isinstance(dependencies, list):
            raise WorkflowDispatchError(f"node {node_id} depends_on must be an array")
        normalized_deps: list[str] = []
        for dependency in dependencies:
            dep = str(dependency).strip().lower()
            if not _NODE_ID_RE.fullmatch(dep):
                raise WorkflowDispatchError(
                    f"node {node_id} has invalid dependency {dep!r}"
                )
            if dep == node_id:
                raise WorkflowDispatchError(f"node {node_id} cannot depend on itself")
            if dep not in normalized_deps:
                normalized_deps.append(dep)
        approval = raw["requires_approval"]
        if not isinstance(approval, bool):
            raise WorkflowDispatchError(
                f"node {node_id} requires_approval must be boolean"
            )
        nodes.append(
            {
                "id": node_id,
                "label": _clean_text(
                    raw["label"],
                    field=f"node {node_id} label",
                    limit=MAX_LABEL_CHARS,
                ),
                "kind": kind,
                "objective": _clean_text(
                    raw["objective"],
                    field=f"node {node_id} objective",
                    limit=MAX_OBJECTIVE_CHARS,
                ),
                "depends_on": normalized_deps,
                "requires_approval": approval,
            }
        )

    for node in nodes:
        missing = [dep for dep in node["depends_on"] if dep not in ids]
        if missing:
            raise WorkflowDispatchError(
                f"node {node['id']} depends on missing nodes: {', '.join(missing)}"
            )
    return {"title": title, "summary": summary, "nodes": nodes}


def _topological_waves(nodes: list[dict[str, Any]]) -> tuple[tuple[str, ...], ...]:
    order = {node["id"]: index for index, node in enumerate(nodes)}
    dependencies = {node["id"]: set(node["depends_on"]) for node in nodes}
    dependents = {node["id"]: set() for node in nodes}
    for node_id, deps in dependencies.items():
        for dep in deps:
            dependents[dep].add(node_id)

    ready = sorted(
        [node_id for node_id, deps in dependencies.items() if not deps],
        key=order.get,
    )
    waves: list[tuple[str, ...]] = []
    processed: set[str] = set()
    while ready:
        wave = tuple(ready)
        waves.append(wave)
        next_ready: list[str] = []
        for node_id in wave:
            processed.add(node_id)
            for child in dependents[node_id]:
                dependencies[child].discard(node_id)
                if not dependencies[child] and child not in processed:
                    next_ready.append(child)
        ready = sorted(set(next_ready), key=order.get)

    if len(processed) != len(nodes):
        remaining = [node["id"] for node in nodes if node["id"] not in processed]
        raise WorkflowDispatchError(
            "workflow must be a DAG; cycle detected around: "
            + ", ".join(remaining[:6])
        )
    return tuple(waves)


def _dispatch_batches(
    waves: tuple[tuple[str, ...], ...],
) -> tuple[tuple[str, ...], ...]:
    batches: list[tuple[str, ...]] = []
    for wave in waves:
        for start in range(0, len(wave), MAX_PARALLEL_DISPATCH):
            batches.append(wave[start : start + MAX_PARALLEL_DISPATCH])
    return tuple(batches)


def _mermaid(spec: dict[str, Any]) -> str:
    nodes = spec["nodes"]
    lines = ["flowchart TD"]
    for node in nodes:
        label = (
            node["label"]
            .replace("\\", "\\\\")
            .replace('"', "'")
            .replace("[", "(")
            .replace("]", ")")
            .replace("<", "(")
            .replace(">", ")")
            .replace("\n", " ")
        )
        lines.append(
            f'  {node["id"]}["{label}<br/><small>{node["kind"]}</small>"]'
        )
    for node in nodes:
        for dependency in node["depends_on"]:
            lines.append(f"  {dependency} --> {node['id']}")
    return "\n".join(lines)


def _svg(
    spec: dict[str, Any],
    waves: tuple[tuple[str, ...], ...],
) -> str:
    node_width = 230
    node_height = 72
    gap_x = 42
    gap_y = 72
    margin = 36
    max_width = max((len(wave) for wave in waves), default=1)
    width = max(
        360,
        margin * 2 + max_width * node_width + (max_width - 1) * gap_x,
    )
    height = max(
        180,
        margin * 2 + len(waves) * node_height + (len(waves) - 1) * gap_y,
    )
    positions: dict[str, tuple[float, float]] = {}
    for row, wave in enumerate(waves):
        row_width = len(wave) * node_width + max(0, len(wave) - 1) * gap_x
        start_x = (width - row_width) / 2
        y = margin + row * (node_height + gap_y)
        for col, node_id in enumerate(wave):
            x = start_x + col * (node_width + gap_x)
            positions[node_id] = (x, y)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        'role="img" aria-label="WorkSpace workflow diagram">',
        "<defs>",
        '<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="7" markerHeight="7" orient="auto-start-reverse">',
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#737780"/>',
        "</marker>",
        "</defs>",
        '<rect width="100%" height="100%" rx="16" fill="#111216"/>',
    ]
    for node in spec["nodes"]:
        child_x, child_y = positions[node["id"]]
        for dep in node["depends_on"]:
            parent_x, parent_y = positions[dep]
            x1 = parent_x + node_width / 2
            y1 = parent_y + node_height
            x2 = child_x + node_width / 2
            y2 = child_y
            middle = (y1 + y2) / 2
            parts.append(
                f'<path d="M{x1:.1f},{y1:.1f} C{x1:.1f},{middle:.1f} '
                f'{x2:.1f},{middle:.1f} {x2:.1f},{y2:.1f}" '
                'fill="none" stroke="#737780" stroke-width="2" '
                'marker-end="url(#arrow)"/>'
            )

    kind_color = {
        "analysis": "#283444",
        "research": "#173c34",
        "presentation": "#352b4e",
        "verify": "#493521",
        "daily_report": "#25354b",
        "human_approval": "#4a2c31",
    }
    for node in spec["nodes"]:
        x, y = positions[node["id"]]
        fill = kind_color[node["kind"]]
        label = xml_escape(node["label"])
        kind = xml_escape(node["kind"].replace("_", " ").title())
        approval = " · approval" if node["requires_approval"] else ""
        parts.extend(
            [
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{node_width}" '
                f'height="{node_height}" rx="12" fill="{fill}" '
                'stroke="#51545c" stroke-width="1.2"/>',
                f'<text x="{x + 14:.1f}" y="{y + 29:.1f}" '
                'font-family="system-ui,sans-serif" font-size="14" '
                f'font-weight="650" fill="#f2f3f5">{label}</text>',
                f'<text x="{x + 14:.1f}" y="{y + 52:.1f}" '
                'font-family="system-ui,sans-serif" font-size="11" '
                f'fill="#b9bcc4">{kind}{xml_escape(approval)}</text>',
            ]
        )
    parts.append("</svg>")
    return "".join(parts)


def _execution_adapter(
    spec: dict[str, Any],
) -> tuple[bool, str | None, str]:
    nodes = spec["nodes"]
    if len(nodes) != 4:
        return (
            False,
            None,
            "Custom DAG is preview-only until an approved execution adapter exists.",
        )
    by_kind = {node["kind"]: node for node in nodes}
    if set(by_kind) != set(_STANDARD_KINDS):
        return (
            False,
            None,
            "Only the verified Research → Presentation → Verify → Daily Report "
            "adapter is executable in Dispatch v1.",
        )
    research = by_kind["research"]
    presentation = by_kind["presentation"]
    verify = by_kind["verify"]
    report = by_kind["daily_report"]
    if (
        research["depends_on"] != []
        or presentation["depends_on"] != [research["id"]]
        or verify["depends_on"] != [presentation["id"]]
        or report["depends_on"] != [verify["id"]]
    ):
        return (
            False,
            None,
            "The v1 execution adapter requires a strict Research → Presentation "
            "→ Verify → Daily Report dependency chain.",
        )
    if any(node["requires_approval"] for node in nodes):
        return (
            False,
            None,
            "Mid-workflow approval nodes/flags are preview-only in v1; "
            "dispatch itself already requires explicit approval.",
        )
    return (
        True,
        "workspace-standard-deliverable-v1",
        "Mapped to the existing validated WorkSpace WorkflowRunner.",
    )


class WorkflowCompiler:
    """One model call proposes a graph; deterministic code owns validity/authority."""

    def __init__(self, llm: Any):
        self.llm = llm

    def compile(self, description: str) -> DispatchPlan:
        description = _clean_text(
            description,
            field="description",
            limit=MAX_DESCRIPTION_CHARS,
        )
        system = (
            "You are WorkSpace Workflow Compiler. Convert the user's goal into the "
            "smallest useful DAG. Output only the requested JSON schema. "
            "Allowed kinds: analysis, research, presentation, verify, daily_report, "
            "human_approval. A node describes work; it never grants filesystem, "
            "network, shell, secret, deployment, or approval authority. "
            "Use 2-12 nodes, no loops. Prefer independent nodes only when they can "
            "really run independently. The runtime globally requires explicit user "
            "approval before dispatch, so do not add human_approval unless the user "
            "explicitly asks for a checkpoint during the workflow. When the requested "
            "deliverable naturally matches WorkSpace's existing standard pipeline, "
            "use exactly research -> presentation -> verify -> daily_report with no "
            "extra node so the plan can use the verified execution adapter."
        )
        raw = self.llm.generate_json(
            system,
            description,
            schema=_WORKFLOW_SCHEMA,
            schema_id=WORKFLOW_SPEC_SCHEMA,
            think=False,
            num_predict=1800,
            trust_domain="workspace-dispatch-design",
            template_version="workspace.dispatch.compiler.v1",
        )
        spec = _normalize_spec(raw)
        waves = _topological_waves(spec["nodes"])
        batches = _dispatch_batches(waves)
        execution_ready, execution_template, execution_reason = _execution_adapter(
            spec
        )
        fingerprint_payload = {
            "schema_version": WORKFLOW_SPEC_SCHEMA,
            **spec,
        }
        return DispatchPlan(
            schema_version=WORKFLOW_SPEC_SCHEMA,
            title=spec["title"],
            summary=spec["summary"],
            nodes=tuple(spec["nodes"]),
            waves=waves,
            dispatch_batches=batches,
            mermaid=_mermaid(spec),
            diagram_svg=_svg(spec, waves),
            spec_sha256=_canonical_sha256(fingerprint_payload),
            execution_ready=execution_ready,
            execution_template=execution_template,
            execution_reason=execution_reason,
            approval_required=True,
        )


class WorkflowDraftStore:
    """Owner-scoped local JSON drafts; no database migration or new service."""

    def __init__(self, root: Path):
        self.root = Path(root) / "workflow_dispatch"
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @staticmethod
    def _owner_digest(owner_key: str) -> str:
        value = str(owner_key or "").encode("utf-8")
        return hashlib.sha256(value).hexdigest()

    def _path(self, workflow_id: str) -> Path:
        if not _WORKFLOW_ID_RE.fullmatch(workflow_id):
            raise WorkflowDispatchError("invalid workflow id")
        return self.root / f"{workflow_id}.json"

    def create(
        self,
        owner_key: str,
        description: str,
        plan: DispatchPlan,
    ) -> dict[str, Any]:
        workflow_id = "wf_" + secrets.token_hex(12)
        now = datetime.now(TZ).isoformat()
        payload = {
            "schema_version": WORKFLOW_DRAFT_SCHEMA,
            "workflow_id": workflow_id,
            "owner_sha256": self._owner_digest(owner_key),
            "description": description,
            "plan": plan.to_dict(),
            "status": "draft",
            "result": None,
            "error": None,
            "created_at": now,
            "updated_at": now,
        }
        self._write(payload)
        return payload

    def _write(self, payload: dict[str, Any]) -> None:
        path = self._path(payload["workflow_id"])
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)

    def get(self, owner_key: str, workflow_id: str) -> dict[str, Any]:
        path = self._path(workflow_id)
        if not path.is_file():
            raise KeyError(workflow_id)
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("owner_sha256") != self._owner_digest(owner_key):
            raise KeyError(workflow_id)
        return payload

    def update(
        self,
        owner_key: str,
        workflow_id: str,
        **changes: Any,
    ) -> dict[str, Any]:
        with self._lock:
            payload = self.get(owner_key, workflow_id)
            payload.update(changes)
            payload["updated_at"] = datetime.now(TZ).isoformat()
            self._write(payload)
            return payload


class WorkflowDispatchService:
    """Compile, persist and dispatch only explicitly approved executable drafts."""

    def __init__(self, orchestrator: Any, artifact_root: Path):
        self.orchestrator = orchestrator
        self.compiler = WorkflowCompiler(orchestrator.research_llm)
        self.store = WorkflowDraftStore(artifact_root)
        self._dispatch_slot = threading.Semaphore(1)

    @staticmethod
    def public(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in payload.items()
            if key not in {"owner_sha256", "description"}
        }

    def compile(self, owner_key: str, description: str) -> dict[str, Any]:
        description = _clean_text(
            description,
            field="description",
            limit=MAX_DESCRIPTION_CHARS,
        )
        plan = self.compiler.compile(description)
        draft = self.store.create(owner_key, description, plan)
        return self.public(draft)

    def status(self, owner_key: str, workflow_id: str) -> dict[str, Any]:
        return self.public(self.store.get(owner_key, workflow_id))

    def dispatch(
        self,
        owner_key: str,
        workflow_id: str,
        *,
        approved: bool,
        language: str = "ja",
        output_format: str = "pptx",
    ) -> dict[str, Any]:
        if approved is not True:
            raise WorkflowDispatchError("explicit approval is required")
        if language not in {"ja", "vi", "en"}:
            raise WorkflowDispatchError("unsupported language")
        if output_format not in {"source", "pptx", "pdf", "all"}:
            raise WorkflowDispatchError("unsupported output format")
        draft = self.store.get(owner_key, workflow_id)
        if draft["status"] not in {"draft", "failed"}:
            raise WorkflowDispatchError(
                f"workflow cannot be dispatched from status={draft['status']}"
            )
        plan = draft["plan"]
        if plan.get("execution_ready") is not True:
            raise WorkflowDispatchError(
                str(plan.get("execution_reason") or "workflow is preview-only")
            )
        if plan.get("execution_template") != "workspace-standard-deliverable-v1":
            raise WorkflowDispatchError("unsupported execution adapter")

        self.store.update(
            owner_key,
            workflow_id,
            status="queued",
            result=None,
            error=None,
        )

        def run() -> None:
            with self._dispatch_slot:
                self.store.update(
                    owner_key,
                    workflow_id,
                    status="running",
                )
                try:
                    result = self.orchestrator.run_workflow(
                        plan["title"],
                        draft["description"],
                        live=True,
                        audience="R&D internal",
                        purpose="inform",
                        language=language,
                        slide_count=6,
                        output_format=output_format,
                    )
                    result_payload = (
                        result.__dict__.copy()
                        if hasattr(result, "__dict__")
                        else {"result": str(result)}
                    )
                    self.store.update(
                        owner_key,
                        workflow_id,
                        status="completed",
                        result=result_payload,
                        error=None,
                    )
                except Exception as exc:
                    safe = redact_sensitive_text(
                        f"{type(exc).__name__}: {exc}"
                    )[:1000]
                    self.store.update(
                        owner_key,
                        workflow_id,
                        status="failed",
                        result=None,
                        error=safe,
                    )

        threading.Thread(
            target=run,
            name=f"workspace-dispatch-{workflow_id}",
            daemon=True,
        ).start()
        return self.status(owner_key, workflow_id)
