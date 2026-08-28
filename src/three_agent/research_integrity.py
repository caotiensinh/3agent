from __future__ import annotations

import re
from typing import Any


_NUM_RE = re.compile(r"(?<![A-Za-z])(?:[$¥€£]\s*)?\d[\d,]*(?:\.\d+)?%?")


def _clean(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _number_tokens(value: str) -> set[str]:
    tokens: set[str] = set()
    for match in _NUM_RE.findall(value or ""):
        normalized = re.sub(r"[$¥€£,%\s]", "", match)
        if normalized:
            tokens.add(normalized)
    return tokens


def detect_request_constraints(request: str) -> dict[str, bool]:
    text = _clean(request).casefold()
    return {
        "temporal": bool(re.search(r"\b(past|last|latest|recent|current|today|weekly|week)\b|過去|直近|最新|現在|今週|tuần|mới nhất|hiện tại", text)),
        "ranking": bool(re.search(r"\btop\s*\d+\b|best\s*seller|ranking|bán chạy|売れ筋|ランキング", text)),
        "quantity": bool(re.search(r"sales?\s*(volume|quantity)|units?\s*sold|number\s*of\s*sales|số lượng\s*bán|販売数|販売数量|売上数量", text)),
        "category_scope": bool(re.search(r"all\s+categor|across\s+categor|category|toàn\s+amazon|danh\s+mục|全.*カテゴリ|カテゴリ", text)),
    }


def clean_source_assessments(items: Any, valid_source_ids: set[str]) -> list[dict]:
    cleaned: list[dict] = []
    seen: set[str] = set()
    if not isinstance(items, list):
        return cleaned
    for item in items:
        if not isinstance(item, dict):
            continue
        source_id = _clean(item.get("source_id"))
        if source_id not in valid_source_ids or source_id in seen:
            continue
        relevance = _clean(item.get("relevance")).lower()
        if relevance not in {"high", "medium", "low"}:
            relevance = "low"
        authority = _clean(item.get("authority")).lower()
        if authority not in {"primary", "secondary", "unknown"}:
            authority = "unknown"
        time_match_raw = item.get("time_match")
        time_match = time_match_raw if isinstance(time_match_raw, bool) else None
        scope_match = item.get("scope_match") is True
        cleaned.append(
            {
                "source_id": source_id,
                "relevance": relevance,
                "scope_match": scope_match,
                "time_match": time_match,
                "authority": authority,
                "reason": _clean(item.get("reason"))[:320],
            }
        )
        seen.add(source_id)
    return cleaned


def vetted_source_ids(assessments: list[dict]) -> set[str]:
    return {
        item["source_id"]
        for item in assessments
        if item.get("relevance") in {"high", "medium"} and item.get("scope_match") is True
    }


def _quote_is_verbatim(quote: str, source_text: str) -> bool:
    needle = _clean(quote).casefold()
    haystack = _clean(source_text).casefold()
    return bool(needle) and needle in haystack


def enforce_numeric_evidence(
    claims: list[dict],
    source_texts: dict[str, str],
    *,
    temporal_required: bool = False,
    source_assessments: dict[str, dict] | None = None,
) -> tuple[list[dict], list[str]]:
    """Reject quantitative claims unless their numeric values are verbatim-evidenced.

    Non-numeric claims pass unchanged. Numeric claims must provide one or more
    evidence_quotes whose source_id is already cited by the claim. Every numeric
    token in the claim must occur in at least one verified quote. For temporal
    requests, at least one quoted source must also be assessed as time-matching.
    """
    accepted: list[dict] = []
    rejected: list[str] = []
    assessments = source_assessments or {}

    for claim in claims:
        text = _clean(claim.get("claim"))
        numbers = _number_tokens(text)
        if not numbers:
            accepted.append(claim)
            continue

        raw_quotes = claim.get("evidence_quotes")
        quotes = raw_quotes if isinstance(raw_quotes, list) else []
        valid_quotes: list[dict] = []
        quoted_numbers: set[str] = set()
        time_supported = not temporal_required
        cited = set(claim.get("source_ids") or [])

        for item in quotes:
            if not isinstance(item, dict):
                continue
            sid = _clean(item.get("source_id"))
            quote = _clean(item.get("quote"))
            if sid not in cited or sid not in source_texts or not _quote_is_verbatim(quote, source_texts[sid]):
                continue
            valid_quotes.append({"source_id": sid, "quote": quote[:500]})
            quoted_numbers.update(_number_tokens(quote))
            if assessments.get(sid, {}).get("time_match") is True:
                time_supported = True

        if not valid_quotes or not numbers.issubset(quoted_numbers) or not time_supported:
            reason = "numeric evidence missing"
            if valid_quotes and not numbers.issubset(quoted_numbers):
                reason = "numeric values not present in verified quotes"
            elif valid_quotes and not time_supported:
                reason = "numeric claim lacks time-matched evidence"
            rejected.append(f"{text} ({reason})")
            continue

        claim = dict(claim)
        claim["evidence_quotes"] = valid_quotes
        accepted.append(claim)

    return accepted, rejected


def core_constraint_gaps(
    request: str,
    verified_claims: list[dict],
    source_assessments: list[dict],
) -> list[str]:
    constraints = detect_request_constraints(request)
    gaps: list[str] = []

    if constraints["temporal"] and not any(item.get("time_match") is True for item in source_assessments):
        gaps.append("FRESHNESS_UNVERIFIED")

    if constraints["quantity"]:
        if not any(_number_tokens(_clean(item.get("claim"))) and item.get("evidence_quotes") for item in verified_claims):
            gaps.append("QUANTITATIVE_EVIDENCE_MISSING")

    if constraints["ranking"]:
        ranking_text = " ".join(_clean(item.get("claim")).casefold() for item in verified_claims)
        if not re.search(r"\b(top|rank|#\s*\d+)\b|第\s*\d|ランキング|bán chạy", ranking_text):
            gaps.append("RANKING_SCOPE_UNVERIFIED")

    if constraints["category_scope"] and source_assessments:
        if not any(item.get("scope_match") is True for item in source_assessments):
            gaps.append("CATEGORY_SCOPE_UNVERIFIED")

    return list(dict.fromkeys(gaps))
