from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterable

LANE_MANIFEST_SCHEMA = "workspace-security-lane-write-set/v1"
MAX_LANES = 32
MAX_PATHS_PER_LANE = 32


class LaneWriteSetError(ValueError):
    """Lane ownership is malformed or would create a competing writer."""


def _text(value: str, field: str, max_len: int = 160) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or any(ch.isspace() for ch in text):
        raise LaneWriteSetError(f"{field} must be a bounded identifier")
    return text


def _path(value: str) -> str:
    text = _text(value, "path", 240)
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or text.startswith(".git/"):
        raise LaneWriteSetError("path must be repository-relative and non-traversing")
    if text.endswith("/"):
        raise LaneWriteSetError("write-set entries must identify files, not directories")
    return text


@dataclass(frozen=True)
class LaneWriteSet:
    lane_id: str
    branch: str
    weight_percent: int
    owned_paths: tuple[str, ...]
    verifier: str
    schema_version: str = LANE_MANIFEST_SCHEMA

    def validate(self) -> "LaneWriteSet":
        if self.schema_version != LANE_MANIFEST_SCHEMA:
            raise LaneWriteSetError("unsupported lane manifest schema")
        _text(self.lane_id, "lane_id", 64)
        _text(self.branch, "branch", 180)
        _text(self.verifier, "verifier", 180)
        if isinstance(self.weight_percent, bool) or self.weight_percent != 10:
            raise LaneWriteSetError("every lane must carry exactly 10 percent weight")
        paths = tuple(_path(item) for item in self.owned_paths)
        if not paths or len(paths) > MAX_PATHS_PER_LANE:
            raise LaneWriteSetError("lane write-set is empty or exceeds its bound")
        if len(set(paths)) != len(paths):
            raise LaneWriteSetError("lane write-set contains duplicate paths")
        object.__setattr__(self, "owned_paths", tuple(sorted(paths)))
        return self


@dataclass(frozen=True)
class ParallelLaneManifest:
    lanes: tuple[LaneWriteSet, ...]

    @classmethod
    def build(cls, rows: Iterable[LaneWriteSet]) -> "ParallelLaneManifest":
        return cls(tuple(rows)).validate()

    def validate(self) -> "ParallelLaneManifest":
        if len(self.lanes) != 10:
            raise LaneWriteSetError("parallel execution requires exactly 10 lanes")
        if len(self.lanes) > MAX_LANES:
            raise LaneWriteSetError("lane bound exceeded")
        lane_ids: set[str] = set()
        branches: set[str] = set()
        owners: dict[str, str] = {}
        for lane in self.lanes:
            lane.validate()
            if lane.lane_id in lane_ids:
                raise LaneWriteSetError("duplicate lane_id")
            if lane.branch in branches:
                raise LaneWriteSetError("duplicate lane branch")
            lane_ids.add(lane.lane_id)
            branches.add(lane.branch)
            for path in lane.owned_paths:
                previous = owners.get(path)
                if previous is not None:
                    raise LaneWriteSetError(
                        f"write-set collision: {path} owned by {previous} and {lane.lane_id}"
                    )
                owners[path] = lane.lane_id
        if sum(lane.weight_percent for lane in self.lanes) != 100:
            raise LaneWriteSetError("lane weights must total 100 percent")
        return self

    def owner_of(self, path: str) -> str | None:
        wanted = _path(path)
        for lane in self.lanes:
            lane.validate()
            if wanted in lane.owned_paths:
                return lane.lane_id
        return None
