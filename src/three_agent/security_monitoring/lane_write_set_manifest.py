from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterable

LANE_MANIFEST_SCHEMA = "workspace-security-lane-write-set/v1"
MAX_LANES = 32
MAX_PATHS_PER_LANE = 32
_EXPECTED_LANE_IDS = frozenset(f"L{index:02d}" for index in range(1, 11))


class LaneWriteSetError(ValueError):
    """Lane ownership is malformed or would create a competing writer."""


def _text(value: str, field: str, max_len: int = 160) -> str:
    if not isinstance(value, str):
        raise LaneWriteSetError(f"{field} must be a string identifier")
    text = value.strip()
    if not text or len(text) > max_len or any(ch.isspace() for ch in text):
        raise LaneWriteSetError(f"{field} must be a bounded identifier")
    return text


def _path(value: str) -> str:
    text = _text(value, "path", 240)
    path = PurePosixPath(text)
    canonical = path.as_posix()
    if path.is_absolute() or ".." in path.parts or canonical in {"", "."}:
        raise LaneWriteSetError("path must be repository-relative and non-traversing")
    if text.startswith(".git/") or canonical.startswith(".git/"):
        raise LaneWriteSetError(".git paths are forbidden")
    if text.endswith("/"):
        raise LaneWriteSetError("write-set entries must identify files, not directories")
    if canonical != text:
        raise LaneWriteSetError("path must use canonical repository-relative spelling")
    return canonical


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
        lane_id = _text(self.lane_id, "lane_id", 64)
        branch = _text(self.branch, "branch", 180)
        verifier = _path(self.verifier)
        if isinstance(self.weight_percent, bool) or not isinstance(self.weight_percent, int) or self.weight_percent != 10:
            raise LaneWriteSetError("every lane must carry exactly 10 percent weight")
        paths = tuple(_path(item) for item in self.owned_paths)
        if not paths or len(paths) > MAX_PATHS_PER_LANE:
            raise LaneWriteSetError("lane write-set is empty or exceeds its bound")
        if len(set(paths)) != len(paths):
            raise LaneWriteSetError("lane write-set contains duplicate paths")
        if verifier not in paths:
            raise LaneWriteSetError("lane verifier must be included in its owned write-set")
        object.__setattr__(self, "lane_id", lane_id)
        object.__setattr__(self, "branch", branch)
        object.__setattr__(self, "verifier", verifier)
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
        normalized: list[LaneWriteSet] = []
        for lane in self.lanes:
            lane.validate()
            if lane.lane_id in lane_ids:
                raise LaneWriteSetError("duplicate lane_id")
            if lane.branch in branches:
                raise LaneWriteSetError("duplicate lane branch")
            lane_ids.add(lane.lane_id)
            branches.add(lane.branch)
            normalized.append(lane)
            for path in lane.owned_paths:
                previous = owners.get(path)
                if previous is not None:
                    raise LaneWriteSetError(
                        f"write-set collision: {path} owned by {previous} and {lane.lane_id}"
                    )
                owners[path] = lane.lane_id
        if lane_ids != _EXPECTED_LANE_IDS:
            raise LaneWriteSetError("lane IDs must be exactly L01 through L10")
        if sum(lane.weight_percent for lane in normalized) != 100:
            raise LaneWriteSetError("lane weights must total 100 percent")
        object.__setattr__(self, "lanes", tuple(sorted(normalized, key=lambda lane: lane.lane_id)))
        return self

    def owner_of(self, path: str) -> str | None:
        wanted = _path(path)
        self.validate()
        for lane in self.lanes:
            if wanted in lane.owned_paths:
                return lane.lane_id
        return None
