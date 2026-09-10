from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint

PROCESS_TREE_SCHEMA = "workspace-security-forensics/process-tree-v1"
PROCESS_OBSERVATION_SCHEMA = "workspace-security-forensics/process-observation-v1"
MAX_PROCESS_TREE_INPUTS = 4096
MAX_PROCESS_TREE_NODES = 512
MAX_PROCESS_TREE_DEPTH = 32

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$")


def _identifier(value: str, field_name: str, *, max_len: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or not _ID_RE.fullmatch(text):
        raise MonitoringContractError(f"{field_name} must be a compact identifier")
    if "://" in text or "\\" in text:
        raise MonitoringContractError(f"{field_name} must not contain a URL or filesystem path")
    return text


def _timestamp(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MonitoringContractError(f"{field_name} must include timezone")
    return text


def _positive_int(value: int, field_name: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise MonitoringContractError(f"{field_name} must be within 1..{maximum}")
    return value


@dataclass(frozen=True)
class ProcessObservation:
    event_id: str
    asset_ref: str
    process_ref: str
    observed_at: str
    evidence_ref: str
    parent_process_ref: str | None = None
    user_ref: str | None = None
    schema_version: str = PROCESS_OBSERVATION_SCHEMA

    def validate(self) -> "ProcessObservation":
        object.__setattr__(self, "event_id", _identifier(self.event_id, "event_id", max_len=128))
        object.__setattr__(self, "asset_ref", _identifier(self.asset_ref, "asset_ref", max_len=128))
        object.__setattr__(self, "process_ref", _identifier(self.process_ref, "process_ref", max_len=128))
        object.__setattr__(self, "observed_at", _timestamp(self.observed_at, "observed_at"))
        object.__setattr__(self, "evidence_ref", _identifier(self.evidence_ref, "evidence_ref", max_len=128))
        if self.parent_process_ref is not None:
            parent = _identifier(self.parent_process_ref, "parent_process_ref", max_len=128)
            if parent == self.process_ref:
                raise MonitoringContractError("process cannot declare itself as parent")
            object.__setattr__(self, "parent_process_ref", parent)
        if self.user_ref is not None:
            object.__setattr__(self, "user_ref", _identifier(self.user_ref, "user_ref", max_len=128))
        if self.schema_version != PROCESS_OBSERVATION_SCHEMA:
            raise MonitoringContractError("unsupported process observation schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class ProcessTreeNode:
    process_ref: str
    parent_process_ref: str | None
    depth: int
    observed_at: str
    evidence_ref: str
    user_ref: str | None


@dataclass(frozen=True)
class ProcessTreeAssessment:
    asset_ref: str
    root_process_ref: str
    nodes: tuple[ProcessTreeNode, ...]
    orphan_process_refs: tuple[str, ...]
    cycle_process_refs: tuple[str, ...]
    truncated: bool
    authority: str = "advisory"
    schema_version: str = PROCESS_TREE_SCHEMA

    def validate(self) -> "ProcessTreeAssessment":
        object.__setattr__(self, "asset_ref", _identifier(self.asset_ref, "asset_ref", max_len=128))
        object.__setattr__(self, "root_process_ref", _identifier(self.root_process_ref, "root_process_ref", max_len=128))
        if not self.nodes:
            raise MonitoringContractError("process tree requires at least one node")
        if len(self.nodes) > MAX_PROCESS_TREE_NODES:
            raise MonitoringContractError("process tree node bound exceeded")
        refs = [node.process_ref for node in self.nodes]
        if len(refs) != len(set(refs)):
            raise MonitoringContractError("process tree nodes must be unique")
        if self.root_process_ref not in refs:
            raise MonitoringContractError("root process is missing from process tree")
        for node in self.nodes:
            _identifier(node.process_ref, "process_ref", max_len=128)
            if node.parent_process_ref is not None:
                _identifier(node.parent_process_ref, "parent_process_ref", max_len=128)
            if isinstance(node.depth, bool) or not isinstance(node.depth, int) or not 0 <= node.depth <= MAX_PROCESS_TREE_DEPTH:
                raise MonitoringContractError("process tree depth is invalid")
            _timestamp(node.observed_at, "observed_at")
            _identifier(node.evidence_ref, "evidence_ref", max_len=128)
            if node.user_ref is not None:
                _identifier(node.user_ref, "user_ref", max_len=128)
        object.__setattr__(self, "orphan_process_refs", tuple(sorted({_identifier(v, "orphan_process_ref", max_len=128) for v in self.orphan_process_refs})))
        object.__setattr__(self, "cycle_process_refs", tuple(sorted({_identifier(v, "cycle_process_ref", max_len=128) for v in self.cycle_process_refs})))
        if not isinstance(self.truncated, bool):
            raise MonitoringContractError("truncated must be boolean")
        if self.authority != "advisory":
            raise MonitoringContractError("process tree assessment must remain advisory")
        if self.schema_version != PROCESS_TREE_SCHEMA:
            raise MonitoringContractError("unsupported process tree schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "asset_ref": self.asset_ref,
            "root_process_ref": self.root_process_ref,
            "nodes": [asdict(node) for node in self.nodes],
            "orphan_process_refs": list(self.orphan_process_refs),
            "cycle_process_refs": list(self.cycle_process_refs),
            "truncated": self.truncated,
            "authority": self.authority,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


def _cycle_members(parent_by_process: dict[str, str | None]) -> set[str]:
    cycle_members: set[str] = set()
    done: set[str] = set()
    for start in sorted(parent_by_process):
        if start in done:
            continue
        path: list[str] = []
        index: dict[str, int] = {}
        current: str | None = start
        while current is not None and current in parent_by_process and current not in done:
            if current in index:
                cycle_members.update(path[index[current] :])
                break
            index[current] = len(path)
            path.append(current)
            current = parent_by_process[current]
        done.update(path)
    return cycle_members


def reconstruct_process_tree(
    observations: Iterable[ProcessObservation],
    *,
    asset_ref: str,
    root_process_ref: str,
    max_nodes: int = MAX_PROCESS_TREE_NODES,
    max_depth: int = MAX_PROCESS_TREE_DEPTH,
) -> ProcessTreeAssessment:
    """Reconstruct a bounded, evidence-backed process descendant tree.

    The function is read-only and deterministic. It never executes commands,
    resolves paths, acquires host data, or guesses parentage when evidence is
    missing or contradictory.
    """

    asset_ref = _identifier(asset_ref, "asset_ref", max_len=128)
    root_process_ref = _identifier(root_process_ref, "root_process_ref", max_len=128)
    max_nodes = _positive_int(max_nodes, "max_nodes", maximum=MAX_PROCESS_TREE_NODES)
    max_depth = _positive_int(max_depth, "max_depth", maximum=MAX_PROCESS_TREE_DEPTH)

    rows = tuple(observation.validate() for observation in observations)
    if not rows or len(rows) > MAX_PROCESS_TREE_INPUTS:
        raise MonitoringContractError("process observation input bound exceeded or empty")
    scoped = tuple(row for row in rows if row.asset_ref == asset_ref)
    if not scoped:
        raise MonitoringContractError("no process observations exist for requested asset")

    by_process: dict[str, ProcessObservation] = {}
    for row in scoped:
        previous = by_process.get(row.process_ref)
        if previous is not None and previous.public_dict() != row.public_dict():
            raise MonitoringContractError("conflicting observations for one process_ref")
        by_process[row.process_ref] = row
    if root_process_ref not in by_process:
        raise MonitoringContractError("root process is not present in supplied evidence")

    parent_by_process = {ref: row.parent_process_ref for ref, row in by_process.items()}
    cycles = _cycle_members(parent_by_process)
    orphans = {
        ref
        for ref, parent in parent_by_process.items()
        if parent is not None and parent not in by_process
    }

    children: dict[str, list[str]] = {}
    for process_ref, parent in parent_by_process.items():
        if parent is not None and process_ref not in cycles and parent not in cycles:
            children.setdefault(parent, []).append(process_ref)
    for values in children.values():
        values.sort()

    queue: list[tuple[str, int]] = [(root_process_ref, 0)]
    visited: set[str] = set()
    nodes: list[ProcessTreeNode] = []
    truncated = False
    while queue:
        process_ref, depth = queue.pop(0)
        if process_ref in visited:
            continue
        if depth > max_depth or len(nodes) >= max_nodes:
            truncated = True
            continue
        visited.add(process_ref)
        row = by_process[process_ref]
        nodes.append(
            ProcessTreeNode(
                process_ref=process_ref,
                parent_process_ref=row.parent_process_ref,
                depth=depth,
                observed_at=row.observed_at,
                evidence_ref=row.evidence_ref,
                user_ref=row.user_ref,
            )
        )
        for child in children.get(process_ref, []):
            queue.append((child, depth + 1))

    if any(ref not in visited for ref in children.get(root_process_ref, [])):
        truncated = True
    nodes.sort(key=lambda node: (node.depth, node.observed_at, node.process_ref))
    return ProcessTreeAssessment(
        asset_ref=asset_ref,
        root_process_ref=root_process_ref,
        nodes=tuple(nodes),
        orphan_process_refs=tuple(sorted(orphans)),
        cycle_process_refs=tuple(sorted(cycles)),
        truncated=truncated,
    ).validate()
