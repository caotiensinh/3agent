from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "config" / "model-candidates" / "qwen3-embedding-0.6b.source.json"
REVIEW = ROOT / "config" / "model-candidates" / "qwen3-embedding-0.6b.license-review.json"


def test_qwen3_license_review_matches_immutable_candidate() -> None:
    source = json.loads(SOURCE.read_text(encoding="utf-8"))
    review = json.loads(REVIEW.read_text(encoding="utf-8"))

    assert review["schema"] == "workspace.model-license-review/v1"
    assert review["status"] == "license_review_pass"
    assert review["candidate_id"] == "qwen3-embedding-0.6b"
    assert review["repo_id"] == source["repo_id"]
    assert review["revision"] == source["revision"]
    assert review["license_id"] == source["license"] == "apache-2.0"


def test_qwen3_license_review_is_non_authoritative() -> None:
    review = json.loads(REVIEW.read_text(encoding="utf-8"))
    admission = review["admission"]
    scope = review["intended_deployment_scope"]

    assert admission["production_approval"] is False
    assert admission["runtime_authority"] is False
    assert scope["github_model_weights"] is False
    assert scope["workspace_release_bundle_model_weights"] is False
    assert scope["modified_model_weight_distribution"] is False
    assert review["review_conclusion"]["legal_opinion"] is False


def test_qwen3_license_review_requires_rereview_for_distribution_change() -> None:
    review = json.loads(REVIEW.read_text(encoding="utf-8"))
    conditions = "\n".join(review["review_conclusion"]["conditions"])
    assert "Apache-2.0" in conditions
    assert "NOTICE" in conditions
    assert "new license review" in conditions
    assert "GitHub" in conditions


def test_qwen3_license_review_evidence_is_exact_revision_scoped() -> None:
    review = json.loads(REVIEW.read_text(encoding="utf-8"))
    exact = [
        item
        for item in review["upstream_evidence"]
        if item["kind"] == "huggingface_model_card_metadata_at_exact_revision"
    ]
    assert len(exact) == 1
    assert exact[0]["observed_revision"] == review["revision"]
    assert review["revision"] in exact[0]["source"]
    assert exact[0]["observed_license_id"] == review["license_id"]
