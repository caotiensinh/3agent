#!/usr/bin/env python3
"""Daily Hugging Face model radar.

Keeps a compact watchlist from the most-downloaded models on Hugging Face and
marks models that are also currently trending. Uses only the Python standard
library so GitHub Actions does not need extra packages.
"""

from __future__ import annotations

import json
import math
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

BASE_URL = "https://huggingface.co/api/models"
DOWNLOAD_POOL = 300
TREND_POOL = 100
DISPLAY_LIMIT = 50

ROOT = Path(__file__).resolve().parent
TOP_MODELS_PATH = ROOT / "TOP_MODELS.md"
PROJECT_MATCH_PATH = ROOT / "PROJECT_MATCH.md"

JST = timezone(timedelta(hours=9))

TASK_USAGE = {
    "sentence-similarity": ("Embedding / semantic search", "RAG, log/event similarity, vector search."),
    "feature-extraction": ("Embedding / feature extraction", "Create vectors for retrieval, clustering and anomaly features."),
    "text-ranking": ("Reranker", "Rerank retrieved logs/documents after vector search."),
    "text-classification": ("Classifier", "Classify alerts, logs, documents or security events."),
    "zero-shot-classification": ("Zero-shot classifier", "Classify new event types without task-specific training."),
    "text-generation": ("LLM / agent", "Reasoning, summarization, code assistance and internal agents."),
    "image-text-to-text": ("Vision-language model", "Camera/image reasoning, visual QA and document understanding."),
    "image-to-text": ("Vision caption / OCR helper", "Image description, OCR post-processing and visual extraction."),
    "object-detection": ("Object detector", "Detect people, vehicles, animals and field objects."),
    "image-segmentation": ("Image segmentation", "Pixel-level object/region masks for camera analytics."),
    "image-classification": ("Image classifier", "Fast visual classification on edge devices."),
    "zero-shot-image-classification": ("CLIP-style vision search", "Natural-language image/event search and open-vocabulary matching."),
    "automatic-speech-recognition": ("Speech recognition", "Japanese/field audio transcription and voice input."),
    "text-to-speech": ("Text to speech", "Japanese/field voice feedback and operator assistant."),
    "translation": ("Translation", "Japanese/Vietnamese/English assistance."),
    "time-series-forecasting": ("Time-series forecasting", "Bandwidth, latency, load and capacity forecasting."),
    "document-question-answering": ("Document AI", "Extract and answer questions from EIR/forms/documents."),
}

PROJECT_TASKS = {
    "WorkSpace — Network / Security Analyst": {
        "sentence-similarity", "feature-extraction", "text-ranking", "text-classification",
        "zero-shot-classification", "text-generation", "time-series-forecasting",
    },
    "CameraOps AI / Bear Detection / VMS": {
        "object-detection", "image-segmentation", "image-classification",
        "zero-shot-image-classification", "image-text-to-text", "image-to-text",
    },
    "EIR / Container Document AI": {
        "document-question-answering", "image-text-to-text", "image-to-text",
        "sentence-similarity", "feature-extraction",
    },
    "SuperConnect / RTSP / Network QoS": {
        "time-series-forecasting", "feature-extraction", "text-generation",
    },
    "Japanese Field Assistant": {
        "automatic-speech-recognition", "text-to-speech", "translation",
        "sentence-similarity", "text-generation",
    },
    "Local LLM / Agent / Coding": {
        "text-generation", "image-text-to-text",
    },
}


def fetch_models(sort: str, limit: int) -> list[dict[str, Any]]:
    params = urllib.parse.urlencode(
        {
            "sort": sort,
            "direction": "-1",
            "limit": str(limit),
            "full": "true",
        }
    )
    request = urllib.request.Request(
        f"{BASE_URL}?{params}",
        headers={"User-Agent": "caotiensinh-hf-model-radar/0.1"},
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        data = json.load(response)
    if not isinstance(data, list):
        raise RuntimeError(f"Unexpected Hugging Face response for sort={sort}")
    return data


def safe_fetch(sort: str, limit: int) -> list[dict[str, Any]]:
    try:
        return fetch_models(sort, limit)
    except Exception as exc:
        print(f"WARN: unable to fetch sort={sort}: {exc}")
        return []


def model_id(model: dict[str, Any]) -> str:
    return str(model.get("id") or model.get("modelId") or "unknown")


def task_of(model: dict[str, Any]) -> str:
    return str(model.get("pipeline_tag") or model.get("pipelineTag") or "other")


def tags_of(model: dict[str, Any]) -> list[str]:
    tags = model.get("tags") or []
    return [str(tag) for tag in tags if isinstance(tag, str)]


def license_of(model: dict[str, Any]) -> str:
    for tag in tags_of(model):
        if tag.startswith("license:"):
            return tag.split(":", 1)[1]
    return "not-declared"


def compact_number(value: Any) -> str:
    try:
        n = float(value or 0)
    except (TypeError, ValueError):
        return "0"
    for unit, threshold in (("B", 1e9), ("M", 1e6), ("K", 1e3)):
        if n >= threshold:
            return f"{n / threshold:.1f}{unit}"
    return str(int(n))


def md(text: Any) -> str:
    return str(text).replace("|", r"\|").replace("\n", " ").strip()


def usage_for(model: dict[str, Any]) -> tuple[str, str]:
    task = task_of(model)
    if task in TASK_USAGE:
        return TASK_USAGE[task]
    tags = set(tags_of(model))
    if "gguf" in tags:
        return "Local quantized model", "Run locally with llama.cpp/Ollama-compatible tooling when architecture is supported."
    return "General ML model", "Inspect the model card before integrating; validate license, hardware and task fit."


def standout(model: dict[str, Any], trending_ids: set[str]) -> str:
    mid = model_id(model)
    downloads = compact_number(model.get("downloads"))
    likes = compact_number(model.get("likes"))
    task = task_of(model)
    flags = [f"{downloads} downloads", f"{likes} likes", task]
    if mid in trending_ids:
        flags.insert(0, "🔥 trending")
    lic = license_of(model)
    if lic != "not-declared":
        flags.append(f"license:{lic}")
    return " · ".join(flags)


def generate_top_models(downloaded: list[dict[str, Any]], trending: list[dict[str, Any]]) -> str:
    trending_ids = {model_id(m) for m in trending}
    now_jst = datetime.now(JST).strftime("%Y-%m-%d %H:%M JST")
    total_reference = "3M+"
    elite_estimate = math.ceil(3_000_000 * 0.015)

    lines = [
        "# Hugging Face — Elite Model Radar",
        "",
        f"_Auto-updated: **{now_jst}**_",
        "",
        f"Tracking pool: **Top {len(downloaded)} by downloads**. With {total_reference} Hub models, "
        f"the top 1.5% is roughly {elite_estimate:,}+ models, so this pool is intentionally a very small elite sample.",
        "",
        "Only the first 50 are shown to keep this file short.",
        "",
        "| # | Model | Nổi bật | Cách dùng ngắn gọn |",
        "|---:|---|---|---|",
    ]

    for idx, model in enumerate(downloaded[:DISPLAY_LIMIT], start=1):
        mid = model_id(model)
        label, usage = usage_for(model)
        how = f"**{label}:** {usage}"
        lines.append(
            f"| {idx} | [{md(mid)}](https://huggingface.co/{md(mid)}) | "
            f"{md(standout(model, trending_ids))} | {md(how)} |"
        )

    if trending_ids:
        overlap = [m for m in downloaded if model_id(m) in trending_ids][:20]
        lines.extend(["", "## 🔥 Trending inside the elite download pool", ""])
        if overlap:
            for m in overlap:
                lines.append(f"- [{md(model_id(m))}](https://huggingface.co/{md(model_id(m))}) — {md(standout(m, trending_ids))}")
        else:
            lines.append("- No overlap detected in this run.")
    else:
        lines.extend(["", "> Trending endpoint was unavailable in this run; download ranking was still updated."])

    lines.extend([
        "",
        "## Safety rule",
        "",
        "Before production use: check the model card, license, files, remote code requirement, hardware need and your own benchmark.",
        "",
    ])
    return "\n".join(lines)


def project_score(model: dict[str, Any], project: str) -> int:
    task = task_of(model)
    score = 0
    if task in PROJECT_TASKS[project]:
        score += 100
    tags = set(tags_of(model))
    mid = model_id(model).lower()

    if project == "Local LLM / Agent / Coding":
        if "gguf" in tags or "gguf" in mid:
            score += 30
        if any(x in mid for x in ("coder", "qwen", "granite", "deepseek", "glm")):
            score += 15
    if project == "Japanese Field Assistant":
        if "japanese" in mid or "ja" in tags:
            score += 35
        if "multilingual" in mid:
            score += 20
    if project == "WorkSpace — Network / Security Analyst":
        if any(x in mid for x in ("bge", "e5", "minilm", "reranker", "embed")):
            score += 25
    if project == "CameraOps AI / Bear Detection / VMS":
        if any(x in mid for x in ("clip", "yolo", "detr", "vit", "qwen")):
            score += 20
    if project == "EIR / Container Document AI":
        if any(x in mid for x in ("layout", "document", "qwen", "vision")):
            score += 20
    if project == "SuperConnect / RTSP / Network QoS":
        if any(x in mid for x in ("chronos", "timesfm", "time")):
            score += 30

    downloads = int(model.get("downloads") or 0)
    if downloads >= 10_000_000:
        score += 10
    elif downloads >= 1_000_000:
        score += 5
    return score


def generate_project_match(downloaded: list[dict[str, Any]], trending: list[dict[str, Any]]) -> str:
    trending_ids = {model_id(m) for m in trending}
    now_jst = datetime.now(JST).strftime("%Y-%m-%d %H:%M JST")

    lines = [
        "# AI modules phù hợp với các dự án hiện tại",
        "",
        f"_Auto-updated: **{now_jst}**_",
        "",
        "Danh sách này chỉ chọn model từ **elite download pool** của Radar; ưu tiên model có task phù hợp trực tiếp.",
        "",
    ]

    for project in PROJECT_TASKS:
        ranked = sorted(
            ((project_score(m, project), m) for m in downloaded),
            key=lambda pair: (pair[0], int(pair[1].get("downloads") or 0)),
            reverse=True,
        )
        selected = [m for score, m in ranked if score >= 100][:8]

        lines.extend([f"## {project}", ""])
        if not selected:
            lines.append("- Chưa có candidate đủ rõ trong elite pool hiện tại.")
            lines.append("")
            continue

        lines.extend(["| Model | Nổi bật | Dùng vào đâu |", "|---|---|---|"])
        for model in selected:
            mid = model_id(model)
            label, usage = usage_for(model)
            lines.append(
                f"| [{md(mid)}](https://huggingface.co/{md(mid)}) | "
                f"{md(standout(model, trending_ids))} | {md(label)} — {md(usage)} |"
            )
        lines.append("")

    lines.extend([
        "## Quy tắc chọn production",
        "",
        "Download/trending chỉ là tín hiệu sàng lọc. Production vẫn phải PASS: **license → security → hardware → benchmark → real-data test**.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    downloaded = safe_fetch("downloads", DOWNLOAD_POOL)
    if not downloaded:
        raise SystemExit("ERROR: cannot fetch Hugging Face download ranking")

    trending = safe_fetch("trendingScore", TREND_POOL)

    TOP_MODELS_PATH.write_text(generate_top_models(downloaded, trending), encoding="utf-8")
    PROJECT_MATCH_PATH.write_text(generate_project_match(downloaded, trending), encoding="utf-8")
    print(f"Updated {TOP_MODELS_PATH}")
    print(f"Updated {PROJECT_MATCH_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
