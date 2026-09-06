#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import socket
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from three_agent.local_embedding import (
    LocalEmbeddingAdapter,
    LocalSentenceTransformerBackend,
)
from three_agent.model_artifacts import apply_runtime_offline_environment
from three_agent.model_residency import ModelResidencyConfig, ModelResidencyManager


EVIDENCE_SCHEMA = "workspace.model-candidate-evidence/v1"
ACCEPTANCE_SCHEMA = "workspace.model-candidate-acceptance/v1"
_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REPO_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:/")
EmbeddingLoader = Callable[[Path], Any]


class CandidateAcceptanceError(RuntimeError):
    """Candidate runtime acceptance failed without granting model approval."""


@dataclass(frozen=True)
class CandidateArtifact:
    path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class CandidateEvidence:
    repo_id: str
    revision: str
    artifacts: tuple[CandidateArtifact, ...]
    evidence_sha256: str


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256_file(path: Path, *, chunk_size: int = 4 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative_path(value: str) -> str:
    raw = str(value).strip().replace("\\", "/")
    path = Path(raw)
    if (
        not raw
        or "\x00" in raw
        or raw.startswith(("/", "~"))
        or _WINDOWS_DRIVE_RE.match(raw)
        or ":" in raw
        or path.is_absolute()
    ):
        raise CandidateAcceptanceError(f"unsafe candidate artifact path: {raw or '<empty>'}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise CandidateAcceptanceError(f"unsafe candidate artifact path: {raw}")
    normalized = Path(*path.parts).as_posix()
    if normalized != raw:
        raise CandidateAcceptanceError(f"candidate artifact path must be normalized: {raw}")
    return normalized


def parse_candidate_evidence(raw: Mapping[str, Any]) -> CandidateEvidence:
    if raw.get("schema") != EVIDENCE_SCHEMA:
        raise CandidateAcceptanceError(f"candidate evidence schema must be {EVIDENCE_SCHEMA}")
    if raw.get("status") != "candidate_only":
        raise CandidateAcceptanceError("candidate evidence must remain candidate_only")
    if raw.get("runtime_download") is not False:
        raise CandidateAcceptanceError("candidate evidence must forbid runtime download")
    approval = raw.get("approval")
    if not isinstance(approval, Mapping) or approval.get("approved") is not False:
        raise CandidateAcceptanceError("candidate evidence must not already grant approval")

    repo_id = str(raw.get("repo_id", "")).strip()
    revision = str(raw.get("revision", "")).strip().lower()
    if not _REPO_ID_RE.fullmatch(repo_id):
        raise CandidateAcceptanceError("candidate repo_id must be a canonical owner/name identifier")
    if not _HEX40_RE.fullmatch(revision):
        raise CandidateAcceptanceError("candidate revision must be an exact 40-character commit hash")

    artifacts_raw = raw.get("artifacts")
    if not isinstance(artifacts_raw, list) or not artifacts_raw:
        raise CandidateAcceptanceError("candidate evidence requires a non-empty artifact set")

    artifacts: list[CandidateArtifact] = []
    for item in artifacts_raw:
        if not isinstance(item, Mapping):
            raise CandidateAcceptanceError("candidate evidence contains an invalid artifact entry")
        path = _safe_relative_path(str(item.get("path", "")))
        digest = str(item.get("sha256", "")).strip().lower()
        if not _SHA256_RE.fullmatch(digest):
            raise CandidateAcceptanceError(f"candidate artifact {path} requires an exact SHA-256")
        try:
            size = int(item.get("size_bytes"))
        except (TypeError, ValueError) as exc:
            raise CandidateAcceptanceError(
                f"candidate artifact {path} size_bytes must be an integer"
            ) from exc
        if size <= 0:
            raise CandidateAcceptanceError(f"candidate artifact {path} size_bytes must be > 0")
        artifacts.append(CandidateArtifact(path=path, sha256=digest, size_bytes=size))

    paths = [item.path for item in artifacts]
    if len(paths) != len(set(paths)):
        raise CandidateAcceptanceError("candidate evidence contains duplicate artifact paths")

    return CandidateEvidence(
        repo_id=repo_id,
        revision=revision,
        artifacts=tuple(sorted(artifacts, key=lambda item: item.path)),
        evidence_sha256=_canonical_sha256(raw),
    )


def load_candidate_evidence(path: str | Path) -> tuple[CandidateEvidence, dict[str, Any]]:
    source = Path(path)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CandidateAcceptanceError(f"cannot read candidate evidence: {source}: {exc}") from exc
    if not isinstance(raw, dict):
        raise CandidateAcceptanceError("candidate evidence must be a JSON object")
    return parse_candidate_evidence(raw), raw


class CandidateEvidenceResolver:
    """Review-only resolver that proves a local snapshot matches candidate evidence.

    This resolver is intentionally outside the runtime package. It exists only to
    exercise the local embedding adapter before the candidate is admitted to the
    approved runtime manifest.
    """

    def __init__(self, model_id: str, evidence: CandidateEvidence, snapshot_root: str | Path):
        self.model_id = str(model_id).strip()
        if not self.model_id:
            raise CandidateAcceptanceError("candidate model id must not be empty")
        self.evidence = evidence
        self.snapshot_root = Path(snapshot_root)
        self.resolve_calls = 0

    def _verify_snapshot(self) -> Path:
        root = self.snapshot_root
        if not root.is_dir():
            raise CandidateAcceptanceError(f"candidate snapshot directory does not exist: {root}")
        root_resolved = root.resolve()
        expected = {artifact.path for artifact in self.evidence.artifacts}
        actual: set[str] = set()

        for path in root.rglob("*"):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise CandidateAcceptanceError(
                    f"symlinked candidate content is forbidden: {relative}"
                )
            if not path.is_file():
                continue
            resolved = path.resolve()
            try:
                resolved.relative_to(root_resolved)
            except ValueError as exc:
                raise CandidateAcceptanceError(
                    f"candidate artifact escaped snapshot root: {relative}"
                ) from exc
            actual.add(relative)

        unexpected = sorted(actual - expected)
        missing = sorted(expected - actual)
        if unexpected:
            raise CandidateAcceptanceError(
                "candidate snapshot contains unapproved files: " + ", ".join(unexpected)
            )
        if missing:
            raise CandidateAcceptanceError(
                "candidate snapshot is missing evidence files: " + ", ".join(missing)
            )

        for artifact in self.evidence.artifacts:
            path = root / artifact.path
            size = path.stat().st_size
            if size != artifact.size_bytes:
                raise CandidateAcceptanceError(
                    f"candidate artifact size mismatch for {artifact.path}: "
                    f"expected {artifact.size_bytes}, got {size}"
                )
            digest = _sha256_file(path)
            if digest != artifact.sha256:
                raise CandidateAcceptanceError(
                    f"candidate artifact SHA-256 mismatch for {artifact.path}: "
                    f"expected {artifact.sha256}, got {digest}"
                )
        return root_resolved

    def resolve(self, model_id: str) -> Path:
        requested = str(model_id).strip()
        if requested != self.model_id:
            raise CandidateAcceptanceError(
                f"acceptance resolver refuses unexpected candidate model id: {requested or '<empty>'}"
            )
        self.resolve_calls += 1
        return self._verify_snapshot()


@contextmanager
def block_python_network() -> Iterable[list[str]]:
    """Fail closed on Python socket connection attempts during runtime acceptance.

    This guard complements HF/Transformers offline flags. It proves that the
    Python runtime did not attempt a socket connection; it is not a substitute
    for a host/network-namespace packet-capture acceptance test.
    """

    attempts: list[str] = []
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_create_connection = socket.create_connection

    def blocked_connect(_sock: socket.socket, address: Any) -> None:
        attempts.append(repr(address))
        raise CandidateAcceptanceError(f"runtime network attempt blocked: {address!r}")

    def blocked_connect_ex(_sock: socket.socket, address: Any) -> int:
        attempts.append(repr(address))
        raise CandidateAcceptanceError(f"runtime network attempt blocked: {address!r}")

    def blocked_create_connection(address: Any, *args: Any, **kwargs: Any) -> socket.socket:
        attempts.append(repr(address))
        raise CandidateAcceptanceError(f"runtime network attempt blocked: {address!r}")

    socket.socket.connect = blocked_connect  # type: ignore[method-assign]
    socket.socket.connect_ex = blocked_connect_ex  # type: ignore[method-assign]
    socket.create_connection = blocked_create_connection  # type: ignore[assignment]
    try:
        yield attempts
    finally:
        socket.socket.connect = original_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = original_connect_ex  # type: ignore[method-assign]
        socket.create_connection = original_create_connection  # type: ignore[assignment]


def _rows(value: Any) -> list[list[float]]:
    if hasattr(value, "tolist"):
        value = value.tolist()
    try:
        rows = [list(row) for row in value]
    except TypeError as exc:
        raise CandidateAcceptanceError("embedding result must be a two-dimensional sequence") from exc
    try:
        return [[float(item) for item in row] for row in rows]
    except (TypeError, ValueError) as exc:
        raise CandidateAcceptanceError("embedding result contains a non-numeric value") from exc


def _validate_vectors(
    value: Any,
    *,
    expected_rows: int,
    expected_dimensions: int,
    label: str,
    norm_tolerance: float = 0.02,
) -> dict[str, Any]:
    rows = _rows(value)
    if len(rows) != expected_rows:
        raise CandidateAcceptanceError(
            f"{label} embedding row count mismatch: expected {expected_rows}, got {len(rows)}"
        )
    if any(len(row) != expected_dimensions for row in rows):
        observed = sorted({len(row) for row in rows})
        raise CandidateAcceptanceError(
            f"{label} embedding dimension mismatch: expected {expected_dimensions}, got {observed}"
        )
    if any(not math.isfinite(item) for row in rows for item in row):
        raise CandidateAcceptanceError(f"{label} embedding contains non-finite values")
    norms = [math.sqrt(sum(item * item for item in row)) for row in rows]
    if any(abs(norm - 1.0) > norm_tolerance for norm in norms):
        raise CandidateAcceptanceError(
            f"{label} embeddings are not normalized within tolerance {norm_tolerance}"
        )
    return {
        "rows": len(rows),
        "dimensions": expected_dimensions,
        "normalized": True,
        "min_l2_norm": min(norms),
        "max_l2_norm": max(norms),
    }


def _gpu_memory_snapshot() -> dict[str, Any]:
    try:
        import torch
    except ImportError:
        return {"cuda_available": False}
    try:
        if not torch.cuda.is_available():
            return {"cuda_available": False}
        return {
            "cuda_available": True,
            "device_count": int(torch.cuda.device_count()),
            "allocated_bytes": int(torch.cuda.memory_allocated()),
            "reserved_bytes": int(torch.cuda.memory_reserved()),
        }
    except RuntimeError as exc:
        return {"cuda_available": False, "probe_error": str(exc)}


def accept_candidate(
    *,
    evidence: CandidateEvidence,
    snapshot_root: str | Path,
    model_id: str,
    dimensions: int,
    batch_size: int,
    queries: Sequence[str],
    documents: Sequence[str],
    loader: EmbeddingLoader | None = None,
) -> dict[str, Any]:
    queries = tuple(str(item).strip() for item in queries)
    documents = tuple(str(item).strip() for item in documents)
    if not queries or any(not item for item in queries):
        raise CandidateAcceptanceError("acceptance requires non-empty query smoke inputs")
    if not documents or any(not item for item in documents):
        raise CandidateAcceptanceError("acceptance requires non-empty document smoke inputs")

    apply_runtime_offline_environment()
    resolver = CandidateEvidenceResolver(model_id, evidence, snapshot_root)
    backend = LocalSentenceTransformerBackend(resolver, loader=loader)

    with tempfile.TemporaryDirectory(prefix="workspace-model-acceptance-locks-") as lock_tmp:
        residency = ModelResidencyManager(
            backend,
            ModelResidencyConfig(idle_ttl_seconds=0.0),
            lock_root=Path(lock_tmp),
        )
        adapter = LocalEmbeddingAdapter(
            resolver,
            model_id=model_id,
            dimensions=dimensions,
            batch_size=batch_size,
            backend=backend,
            residency=residency,
        )

        gpu_before = _gpu_memory_snapshot()
        with block_python_network() as network_attempts:
            started = time.perf_counter()
            query_vectors = adapter.encode_queries(queries)
            query_ms = (time.perf_counter() - started) * 1000.0
            gpu_loaded = _gpu_memory_snapshot()

            started = time.perf_counter()
            document_vectors = adapter.encode_documents(documents)
            document_ms = (time.perf_counter() - started) * 1000.0

            query_check = _validate_vectors(
                query_vectors,
                expected_rows=len(queries),
                expected_dimensions=dimensions,
                label="query",
            )
            document_check = _validate_vectors(
                document_vectors,
                expected_rows=len(documents),
                expected_dimensions=dimensions,
                label="document",
            )

            evicted = adapter.evict_idle()
            if evicted != (model_id,):
                raise CandidateAcceptanceError(
                    f"candidate residency eviction failed: expected {(model_id,)}, got {evicted}"
                )
            if backend.resident_models():
                raise CandidateAcceptanceError("candidate model remained resident after explicit idle eviction")
            gpu_evicted = _gpu_memory_snapshot()

            started = time.perf_counter()
            reload_vectors = adapter.encode_queries([queries[0]])
            reload_ms = (time.perf_counter() - started) * 1000.0
            reload_check = _validate_vectors(
                reload_vectors,
                expected_rows=1,
                expected_dimensions=dimensions,
                label="reload-query",
            )

        if network_attempts:
            raise CandidateAcceptanceError(
                "candidate runtime attempted network access: " + ", ".join(network_attempts)
            )
        if resolver.resolve_calls < 2:
            raise CandidateAcceptanceError(
                "candidate residency reload did not re-resolve the integrity-verified local snapshot"
            )

        residency_snapshot = adapter.snapshot()

    return {
        "schema": ACCEPTANCE_SCHEMA,
        "status": "runtime_acceptance_pass",
        "candidate": {
            "model_id": model_id,
            "repo_id": evidence.repo_id,
            "revision": evidence.revision,
            "evidence_sha256": evidence.evidence_sha256,
            "artifact_count": len(evidence.artifacts),
        },
        "runtime": {
            "runtime_download": False,
            "HF_HUB_OFFLINE": os.environ.get("HF_HUB_OFFLINE"),
            "TRANSFORMERS_OFFLINE": os.environ.get("TRANSFORMERS_OFFLINE"),
            "HF_HUB_DISABLE_TELEMETRY": os.environ.get("HF_HUB_DISABLE_TELEMETRY"),
            "python_socket_attempts": 0,
            "local_files_only": True,
            "trust_remote_code": False,
        },
        "checks": {
            "query_embedding": query_check,
            "document_embedding": document_check,
            "residency_eviction": True,
            "residency_reload": reload_check,
            "integrity_resolve_calls": resolver.resolve_calls,
        },
        "metrics": {
            "query_ms": query_ms,
            "document_ms": document_ms,
            "reload_query_ms": reload_ms,
            "gpu_before": gpu_before,
            "gpu_loaded": gpu_loaded,
            "gpu_evicted": gpu_evicted,
            "residency": residency_snapshot,
        },
        "approval": {
            "approved": False,
            "reason": (
                "runtime acceptance evidence is not production admission; "
                "benchmark thresholds, license review and explicit human approval remain required"
            ),
        },
        "accepted_at": datetime.now(timezone.utc).isoformat(),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run local-only runtime acceptance for an immutable Hugging Face model candidate"
    )
    parser.add_argument("--evidence", required=True, help="Candidate evidence JSON")
    parser.add_argument("--snapshot", required=True, help="Local candidate snapshot directory")
    parser.add_argument("--model-id", default="qwen3-embedding-0.6b")
    parser.add_argument("--dimensions", type=int, default=1024)
    parser.add_argument("--batch-size", type=int, default=2)
    parser.add_argument("--query", action="append", default=[])
    parser.add_argument("--document", action="append", default=[])
    parser.add_argument("--output", help="Optional acceptance receipt JSON output")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _build_parser().parse_args(list(argv) if argv is not None else None)
    evidence, _ = load_candidate_evidence(args.evidence)
    queries = args.query or [
        "camera offline after PoE switch restart",
        "router uplink packet loss diagnosis",
    ]
    documents = args.document or [
        "A PoE camera can go offline when the switch power budget is exhausted.",
        "Packet loss on an uplink should be correlated with interface counters and path telemetry.",
    ]
    payload = accept_candidate(
        evidence=evidence,
        snapshot_root=args.snapshot,
        model_id=args.model_id,
        dimensions=args.dimensions,
        batch_size=args.batch_size,
        queries=queries,
        documents=documents,
    )
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(encoded, encoding="utf-8")
    else:
        sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CandidateAcceptanceError as exc:
        print(f"[workspace-model-candidate-acceptance][ERROR] {exc}", file=sys.stderr)
        raise SystemExit(2)
