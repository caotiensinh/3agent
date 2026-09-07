#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gc
import hashlib
import json
import math
import os
import re
import resource
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from accept_hf_model_candidate import CandidateEvidenceResolver, load_candidate_evidence
from three_agent.model_artifacts import apply_runtime_offline_environment

SCHEMA = "workspace.embedding-production-benchmark/v1"
FIXTURE_SCHEMA = "workspace.embedding-retrieval-benchmark/v1"
ALLOWED_ISOLATION_MODES = {
    "sudo-net",
    "userns-net",
    "firejail-net",
    "seccomp-no-network",
    "docker-none",
}


def canonical_sha256(payload: Mapping[str, Any]) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def percentile(values: Sequence[float], p: float) -> float:
    if not values:
        raise ValueError("percentile requires values")
    ordered = sorted(float(v) for v in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * p
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def tokenize(text: str) -> set[str]:
    return set(re.findall(r"[\w.-]+", text.lower(), flags=re.UNICODE))


def lexical_rank(query: str, documents: Sequence[Mapping[str, Any]]) -> list[str]:
    q = tokenize(query)
    scored: list[tuple[float, str]] = []
    for item in documents:
        doc_id = str(item["id"])
        d = tokenize(str(item["text"]))
        union = q | d
        score = (len(q & d) / len(union)) if union else 0.0
        scored.append((score, doc_id))
    return [doc_id for _, doc_id in sorted(scored, key=lambda row: (-row[0], row[1]))]


def cosine_rank(
    query_vector: Sequence[float],
    document_vectors: Mapping[str, Sequence[float]],
) -> list[str]:
    scored: list[tuple[float, str]] = []
    for doc_id, vector in document_vectors.items():
        score = sum(float(a) * float(b) for a, b in zip(query_vector, vector))
        scored.append((score, doc_id))
    return [doc_id for _, doc_id in sorted(scored, key=lambda row: (-row[0], row[1]))]


def reciprocal_rank(ranking: Sequence[str], relevant: set[str], k: int) -> float:
    for index, doc_id in enumerate(ranking[:k], start=1):
        if doc_id in relevant:
            return 1.0 / index
    return 0.0


def recall_at_k(ranking: Sequence[str], relevant: set[str], k: int) -> float:
    if not relevant:
        return 0.0
    return len(set(ranking[:k]) & relevant) / len(relevant)


def ndcg_at_k(ranking: Sequence[str], relevant: set[str], k: int) -> float:
    dcg = 0.0
    for index, doc_id in enumerate(ranking[:k], start=1):
        if doc_id in relevant:
            dcg += 1.0 / math.log2(index + 1)
    ideal_hits = min(len(relevant), k)
    idcg = sum(1.0 / math.log2(index + 1) for index in range(1, ideal_hits + 1))
    return dcg / idcg if idcg else 0.0


def aggregate_metrics(
    rankings: Mapping[str, Sequence[str]],
    queries: Sequence[Mapping[str, Any]],
) -> dict[str, float]:
    recall1: list[float] = []
    recall3: list[float] = []
    recall5: list[float] = []
    mrr10: list[float] = []
    ndcg10: list[float] = []
    for item in queries:
        query_id = str(item["id"])
        relevant = {str(value) for value in item["relevant"]}
        ranking = rankings[query_id]
        recall1.append(recall_at_k(ranking, relevant, 1))
        recall3.append(recall_at_k(ranking, relevant, 3))
        recall5.append(recall_at_k(ranking, relevant, 5))
        mrr10.append(reciprocal_rank(ranking, relevant, 10))
        ndcg10.append(ndcg_at_k(ranking, relevant, 10))
    return {
        "recall_at_1": statistics.fmean(recall1),
        "recall_at_3": statistics.fmean(recall3),
        "recall_at_5": statistics.fmean(recall5),
        "mrr_at_10": statistics.fmean(mrr10),
        "ndcg_at_10": statistics.fmean(ndcg10),
    }


def validate_fixture(raw: Mapping[str, Any]) -> None:
    if raw.get("schema") != FIXTURE_SCHEMA:
        raise SystemExit(f"benchmark fixture schema must be {FIXTURE_SCHEMA}")
    documents = raw.get("documents")
    queries = raw.get("queries")
    if not isinstance(documents, list) or not documents:
        raise SystemExit("benchmark fixture requires documents")
    if not isinstance(queries, list) or not queries:
        raise SystemExit("benchmark fixture requires queries")
    doc_ids = [str(item.get("id", "")) for item in documents]
    if any(not value for value in doc_ids) or len(doc_ids) != len(set(doc_ids)):
        raise SystemExit("benchmark document ids must be unique and non-empty")
    known = set(doc_ids)
    for item in queries:
        relevant = item.get("relevant")
        if not isinstance(relevant, list) or not relevant:
            raise SystemExit(f"query {item.get('id')} requires relevant document ids")
        missing = sorted(set(map(str, relevant)) - known)
        if missing:
            raise SystemExit(f"query {item.get('id')} references unknown documents: {missing}")


def torch_snapshot(device: int) -> dict[str, Any]:
    import torch

    return {
        "device": device,
        "name": torch.cuda.get_device_name(device),
        "allocated_bytes": int(torch.cuda.memory_allocated(device)),
        "reserved_bytes": int(torch.cuda.memory_reserved(device)),
        "max_allocated_bytes": int(torch.cuda.max_memory_allocated(device)),
        "max_reserved_bytes": int(torch.cuda.max_memory_reserved(device)),
    }


def encode_to_rows(
    model: Any,
    texts: Sequence[str],
    *,
    prompt_name: str | None,
    batch_size: int,
) -> list[list[float]]:
    kwargs: dict[str, Any] = {
        "batch_size": batch_size,
        "normalize_embeddings": True,
        "convert_to_numpy": True,
        "show_progress_bar": False,
    }
    if prompt_name:
        kwargs["prompt_name"] = prompt_name
    try:
        value = model.encode(list(texts), **kwargs)
    except (KeyError, ValueError):
        kwargs.pop("prompt_name", None)
        value = model.encode(list(texts), **kwargs)
    return [[float(cell) for cell in row] for row in value.tolist()]


def run_device(
    *,
    resolver: CandidateEvidenceResolver,
    device: int,
    documents: Sequence[Mapping[str, Any]],
    queries: Sequence[Mapping[str, Any]],
    batch_size: int,
    repeats: int,
) -> tuple[dict[str, Any], dict[str, list[str]]]:
    import torch
    from sentence_transformers import SentenceTransformer

    if not torch.cuda.is_available() or torch.cuda.device_count() <= device:
        raise SystemExit(f"CUDA device {device} is unavailable")
    torch.cuda.set_device(device)
    torch.cuda.empty_cache()
    torch.cuda.reset_peak_memory_stats(device)
    before = torch_snapshot(device)
    snapshot = resolver.resolve("qwen3-embedding-0.6b")

    load_start = time.perf_counter()
    model = SentenceTransformer(
        str(snapshot),
        device=f"cuda:{device}",
        local_files_only=True,
        trust_remote_code=False,
    )
    torch.cuda.synchronize(device)
    cold_load_ms = (time.perf_counter() - load_start) * 1000.0

    document_texts = [str(item["text"]) for item in documents]
    query_texts = [str(item["text"]) for item in queries]
    document_ids = [str(item["id"]) for item in documents]

    doc_start = time.perf_counter()
    document_rows = encode_to_rows(
        model,
        document_texts,
        prompt_name=None,
        batch_size=batch_size,
    )
    torch.cuda.synchronize(device)
    document_ms = (time.perf_counter() - doc_start) * 1000.0
    doc_vectors = dict(zip(document_ids, document_rows, strict=True))

    latencies: list[float] = []
    query_rows: list[list[float]] = []
    for _ in range(repeats):
        started = time.perf_counter()
        query_rows = encode_to_rows(
            model,
            query_texts,
            prompt_name="query",
            batch_size=batch_size,
        )
        torch.cuda.synchronize(device)
        latencies.append((time.perf_counter() - started) * 1000.0)

    rankings = {
        str(item["id"]): cosine_rank(vector, doc_vectors)
        for item, vector in zip(queries, query_rows, strict=True)
    }
    loaded = torch_snapshot(device)
    del model
    gc.collect()
    torch.cuda.empty_cache()
    torch.cuda.synchronize(device)
    unloaded = torch_snapshot(device)
    residual = max(0, unloaded["reserved_bytes"] - before["reserved_bytes"])

    return (
        {
            "device": device,
            "name": loaded["name"],
            "cold_load_ms": cold_load_ms,
            "document_batch_ms": document_ms,
            "query_batch_ms": {
                "samples": len(latencies),
                "p50": percentile(latencies, 0.50),
                "p95": percentile(latencies, 0.95),
                "p99": percentile(latencies, 0.99),
                "min": min(latencies),
                "max": max(latencies),
            },
            "documents_per_second": len(document_texts) / (document_ms / 1000.0),
            "queries_per_second_p50": len(query_texts) / (percentile(latencies, 0.50) / 1000.0),
            "memory": {
                "before": before,
                "loaded": loaded,
                "unloaded": unloaded,
                "residual_reserved_bytes_after_unload": residual,
            },
            "inference_proven": (
                len(query_rows) == len(query_texts)
                and len(document_rows) == len(document_texts)
            ),
        },
        rankings,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run non-authoritative Qwen3 production benchmark on two CUDA GPUs."
    )
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()

    if args.batch_size <= 0 or args.repeats < 3:
        raise SystemExit("batch-size must be > 0 and repeats must be >= 3")
    apply_runtime_offline_environment()
    if os.environ.get("HF_HUB_OFFLINE") != "1" or os.environ.get("TRANSFORMERS_OFFLINE") != "1":
        raise SystemExit("offline model environment is required")
    isolation_mode = os.environ.get("NETWORK_ISOLATION_MODE")
    if isolation_mode not in ALLOWED_ISOLATION_MODES:
        raise SystemExit(
            f"verified OS-level network isolation mode is required, got {isolation_mode!r}"
        )

    fixture_path = Path(args.benchmark)
    fixture_raw = json.loads(fixture_path.read_text(encoding="utf-8"))
    validate_fixture(fixture_raw)
    evidence = load_candidate_evidence(args.evidence)
    resolver = CandidateEvidenceResolver(
        "qwen3-embedding-0.6b",
        evidence,
        args.snapshot,
    )

    import torch

    if not torch.cuda.is_available():
        raise SystemExit("representative hardware gate requires CUDA")
    if torch.cuda.device_count() < 2:
        raise SystemExit(
            f"representative hardware gate requires >=2 CUDA GPUs; found {torch.cuda.device_count()}"
        )

    documents = fixture_raw["documents"]
    queries = fixture_raw["queries"]
    lexical_rankings = {
        str(item["id"]): lexical_rank(str(item["text"]), documents)
        for item in queries
    }
    lexical_metrics = aggregate_metrics(lexical_rankings, queries)

    devices: list[dict[str, Any]] = []
    semantic_rankings: dict[str, list[str]] | None = None
    for device in (0, 1):
        result, rankings = run_device(
            resolver=resolver,
            device=device,
            documents=documents,
            queries=queries,
            batch_size=args.batch_size,
            repeats=args.repeats,
        )
        devices.append(result)
        if semantic_rankings is None:
            semantic_rankings = rankings
    assert semantic_rankings is not None
    semantic_metrics = aggregate_metrics(semantic_rankings, queries)

    thresholds = fixture_raw["thresholds"]
    checks = {
        "dual_gpu_inference": (
            all(item["inference_proven"] for item in devices) and len(devices) == 2
        ),
        "recall_at_1": (
            semantic_metrics["recall_at_1"] >= float(thresholds["recall_at_1"])
        ),
        "recall_at_3": (
            semantic_metrics["recall_at_3"] >= float(thresholds["recall_at_3"])
        ),
        "recall_at_5": (
            semantic_metrics["recall_at_5"] >= float(thresholds["recall_at_5"])
        ),
        "mrr_at_10": semantic_metrics["mrr_at_10"] >= float(thresholds["mrr_at_10"]),
        "ndcg_at_10": (
            semantic_metrics["ndcg_at_10"] >= float(thresholds["ndcg_at_10"])
        ),
        "mrr_non_regression_vs_lexical": (
            semantic_metrics["mrr_at_10"] >= lexical_metrics["mrr_at_10"]
            if thresholds.get("require_mrr_non_regression_vs_lexical") is True
            else True
        ),
        "integrity_revalidated_per_gpu": resolver.resolve_calls >= 2,
        "gpu_memory_released": all(
            item["memory"]["residual_reserved_bytes_after_unload"] <= 256 * 1024 * 1024
            for item in devices
        ),
    }
    status = "production_benchmark_pass" if all(checks.values()) else "production_benchmark_fail"
    receipt: dict[str, Any] = {
        "schema": SCHEMA,
        "status": status,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "candidate": {
            "model_id": "qwen3-embedding-0.6b",
            "repo_id": evidence.repo_id,
            "revision": evidence.revision,
            "evidence_sha256": evidence.evidence_sha256,
        },
        "benchmark": {
            "benchmark_id": fixture_raw["benchmark_id"],
            "fixture_sha256": canonical_sha256(fixture_raw),
            "query_count": len(queries),
            "document_count": len(documents),
            "semantic": semantic_metrics,
            "lexical_baseline": lexical_metrics,
            "thresholds": thresholds,
        },
        "hardware": {
            "cuda_device_count": int(torch.cuda.device_count()),
            "devices": devices,
            "host_peak_rss_kib": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
        },
        "checks": checks,
        "security": {
            "runtime_download": False,
            "local_files_only": True,
            "trust_remote_code": False,
            "HF_HUB_OFFLINE": os.environ.get("HF_HUB_OFFLINE"),
            "TRANSFORMERS_OFFLINE": os.environ.get("TRANSFORMERS_OFFLINE"),
            "network_isolation_mode": isolation_mode,
        },
        "admission": {
            "production_approval": False,
            "runtime_authority": False,
            "reason": (
                "Benchmark evidence is non-authoritative until license review and "
                "explicit human production admission complete."
            ),
        },
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"status": status, "checks": checks}, ensure_ascii=False, indent=2))
    return 0 if status == "production_benchmark_pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
