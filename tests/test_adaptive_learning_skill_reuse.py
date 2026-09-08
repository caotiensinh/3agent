from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from three_agent.adaptive_learning_contract import (
    EvidenceReference,
    ExperienceRecord,
    KnowledgeCandidate,
)
from three_agent.adaptive_learning_retrieval import (
    LearningContext,
    LearningContextItem,
    LearningRetrievalGateway,
)
from three_agent.adaptive_learning_skill_reuse import (
    AdaptiveLearningSkillReuseError,
    prepare_learning_reuse,
)
from three_agent.agents import research_compiled
from three_agent.agents.research_compiled import ResearchAgent
from three_agent.agents.research_ranked import ResearchAgent as RankedResearchAgent
from three_agent.candidate_skill import CandidateSkill
from three_agent.skill_catalog import ApprovedSkillCatalog
from three_agent.skills import SkillSecurityError

NOW = "2026-09-08T06:30:00Z"


def _sha(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _candidate(candidate_id: str = "candidate:runtime-reuse") -> KnowledgeCandidate:
    task_id = "task:runtime-reuse-source"
    evidence = EvidenceReference(
        ref_id="evidence:runtime-reuse",
        sha256=_sha("runtime-reuse-evidence"),
        source_type="task_artifact",
        source_task_id=task_id,
        sensitivity="confidential",
        collection_mode="offline",
        created_at=NOW,
        vendor_family="fixture",
        version="1",
    )
    experience = ExperienceRecord(
        experience_id="experience:runtime-reuse",
        domain="analyst",
        task_id=task_id,
        outcome="verified_success",
        sensitivity="confidential",
        summary="Verified synthesis-only learned skill reuse fixture.",
        evidence=(evidence,),
        created_at=NOW,
    )
    return KnowledgeCandidate.from_experiences(
        candidate_id=candidate_id,
        domain="analyst",
        kind="skill",
        title="Verified gateway diagnosis reuse",
        content=(
            "Correlate verified gateway evidence before drawing a conclusion. "
            "Preserve uncertainty and do not mutate system state."
        ),
        scope="local analyst synthesis only",
        sensitivity="confidential",
        risk_level="medium",
        ownership="learner_managed",
        action="create",
        execution_mode="analysis_only",
        experiences=(experience,),
        created_at=NOW,
    )


class _StableAuthority:
    def __init__(self) -> None:
        self.checkpoint = SimpleNamespace(
            sequence=7,
            checkpoint_sha256=_sha("checkpoint"),
            state_sha256=_sha("state"),
        )

    def verify(self, store):
        return self.checkpoint


class _ActiveStore:
    def __init__(self, candidate: KnowledgeCandidate, knowledge_sha256: str) -> None:
        self.row = {
            "item_id": candidate.candidate_id,
            "candidate_id": candidate.candidate_id,
            "candidate_sha256": candidate.sha256,
            "knowledge_sha256": knowledge_sha256,
            "level": "approved",
            "disposition": "active_snapshot",
            "candidate": candidate.to_payload(),
        }

    def active(self, item_id: str):
        if item_id != self.row["item_id"]:
            return None
        return dict(self.row)


def _gateway(store: _ActiveStore) -> LearningRetrievalGateway:
    gateway = object.__new__(LearningRetrievalGateway)
    gateway._store = store
    gateway._authority = _StableAuthority()
    gateway._telemetry = None
    return gateway


def _context(candidate: KnowledgeCandidate, knowledge_sha256: str) -> LearningContext:
    return LearningContext(
        query_sha256=_sha("gateway diagnosis reuse"),
        domain=candidate.domain,
        task_sensitivity="confidential",
        items=(
            LearningContextItem(
                item_id=candidate.candidate_id,
                knowledge_sha256=knowledge_sha256,
                level="approved",
                domain=candidate.domain,
                kind=candidate.kind,
                title=candidate.title,
                content=candidate.content,
                scope=candidate.scope,
                sensitivity=candidate.sensitivity,
                risk_level=candidate.risk_level,
                execution_mode=candidate.execution_mode,
            ),
        ),
    ).validate()


def _catalog_fixture(
    root: Path,
    candidate: KnowledgeCandidate,
    *,
    duplicate: bool = False,
) -> tuple[ApprovedSkillCatalog, Path]:
    project = root / "project"
    skills_root = project / "skills"
    docs = project / "docs"
    skills_root.mkdir(parents=True)
    docs.mkdir(parents=True)
    (docs / "review.md").write_text("# Reviewed\n", encoding="utf-8")

    view = CandidateSkill.from_candidate(candidate)
    document = CandidateSkill.render_proposed_document(candidate)
    skill_dir = skills_root / view.proposed_skill_name
    skill_dir.mkdir()
    skill_path = skill_dir / "SKILL.md"
    skill_path.write_text(document, encoding="utf-8")
    token = f"candidate:{candidate.candidate_id}:{candidate.sha256}"

    def entry(name: str, content: str) -> dict:
        return {
            "enabled": True,
            "agent_ids": ["research"],
            "instruction_only": True,
            "network_access": False,
            "credential_access": False,
            "persistent_self_modify": False,
            "external_code_vendored": False,
            "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "review": "docs/review.md",
            "provenance": [token],
            "enterprise_tier": "E2",
            "risk_class": "medium",
        }

    skills = {view.proposed_skill_name: entry(view.proposed_skill_name, document)}
    if duplicate:
        duplicate_name = "duplicate-runtime-reuse"
        duplicate_document = document.replace(
            f"name: {view.proposed_skill_name}",
            f"name: {duplicate_name}",
            1,
        )
        duplicate_dir = skills_root / duplicate_name
        duplicate_dir.mkdir()
        (duplicate_dir / "SKILL.md").write_text(duplicate_document, encoding="utf-8")
        skills[duplicate_name] = entry(duplicate_name, duplicate_document)

    (skills_root / "registry.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "policy": "approved-local-instruction-only",
                "skills": skills,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return ApprovedSkillCatalog(skills_root), skill_path


class AdaptiveLearningSkillReuseTests(unittest.TestCase):
    def test_exact_selected_version_loads_canonical_production_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = _candidate()
            knowledge_sha256 = _sha("knowledge-version-1")
            catalog, _ = _catalog_fixture(Path(tmp), candidate)
            prepared = prepare_learning_reuse(
                _gateway(_ActiveStore(candidate, knowledge_sha256)),
                catalog,
                agent_id="research",
                context=_context(candidate, knowledge_sha256),
            )

            self.assertEqual(len(prepared.reuse_context.items), 1)
            self.assertEqual(prepared.reference_context.items, ())
            self.assertEqual(len(prepared.materialized_skill_blocks), 1)
            self.assertIn("## Approved local skill:", prepared.materialized_skill_blocks[0])
            self.assertIn("Correlate verified gateway evidence", prepared.materialized_skill_blocks[0])

    def test_unmaterialized_skill_is_withheld_instead_of_using_raw_candidate_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = _candidate("candidate:unmaterialized-runtime-reuse")
            knowledge_sha256 = _sha("knowledge-unmaterialized")
            project = Path(tmp) / "project"
            skills_root = project / "skills"
            skills_root.mkdir(parents=True)
            (skills_root / "registry.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "policy": "approved-local-instruction-only",
                        "skills": {},
                    }
                ),
                encoding="utf-8",
            )

            prepared = prepare_learning_reuse(
                _gateway(_ActiveStore(candidate, knowledge_sha256)),
                ApprovedSkillCatalog(skills_root),
                agent_id="research",
                context=_context(candidate, knowledge_sha256),
            )
            self.assertEqual(prepared.reuse_context.items, ())
            self.assertEqual(prepared.reference_context.items, ())
            self.assertEqual(prepared.materialized_skill_blocks, ())

    def test_changed_active_version_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = _candidate()
            selected_sha = _sha("selected-version")
            active_sha = _sha("newer-active-version")
            catalog, _ = _catalog_fixture(Path(tmp), candidate)
            with self.assertRaisesRegex(
                AdaptiveLearningSkillReuseError,
                "LEARNING_REUSE_VERSION_CHANGED",
            ):
                prepare_learning_reuse(
                    _gateway(_ActiveStore(candidate, active_sha)),
                    catalog,
                    agent_id="research",
                    context=_context(candidate, selected_sha),
                )

    def test_duplicate_candidate_materialization_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = _candidate()
            knowledge_sha256 = _sha("knowledge-duplicate")
            catalog, _ = _catalog_fixture(Path(tmp), candidate, duplicate=True)
            with self.assertRaisesRegex(
                AdaptiveLearningSkillReuseError,
                "LEARNING_REUSE_MATERIALIZATION_AMBIGUOUS",
            ):
                prepare_learning_reuse(
                    _gateway(_ActiveStore(candidate, knowledge_sha256)),
                    catalog,
                    agent_id="research",
                    context=_context(candidate, knowledge_sha256),
                )

    def test_tampered_production_skill_is_rejected_by_canonical_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = _candidate()
            knowledge_sha256 = _sha("knowledge-tamper")
            catalog, skill_path = _catalog_fixture(Path(tmp), candidate)
            skill_path.write_text(
                skill_path.read_text(encoding="utf-8") + "\nUNREVIEWED CHANGE\n",
                encoding="utf-8",
            )
            with self.assertRaises(SkillSecurityError):
                prepare_learning_reuse(
                    _gateway(_ActiveStore(candidate, knowledge_sha256)),
                    catalog,
                    agent_id="research",
                    context=_context(candidate, knowledge_sha256),
                )

    def test_research_synthesis_receives_production_block_not_raw_skill_reference_packet(self):
        candidate = _candidate()
        knowledge_sha256 = _sha("knowledge-synthesis")
        context = _context(candidate, knowledge_sha256)
        production_block = (
            "## Approved local skill: verified-runtime-reuse\n\n"
            "PRODUCTION-ONLY-REVIEWED-PROCEDURE"
        )
        captured: dict[str, str] = {}

        def parent_synthesize(
            self,
            title,
            request,
            objective,
            focus,
            sources,
            source_assessments,
        ):
            captured["objective"] = objective
            return {"ok": True}

        agent = object.__new__(ResearchAgent)
        reference_context = LearningContext(
            query_sha256=context.query_sha256,
            domain=context.domain,
            task_sensitivity=context.task_sensitivity,
            items=(),
        ).validate()
        context_token = research_compiled._ACTIVE_LEARNING_CONTEXT.set(reference_context)
        skill_token = research_compiled._ACTIVE_MATERIALIZED_LEARNING_SKILLS.set(
            (production_block,)
        )
        try:
            with patch.object(RankedResearchAgent, "_synthesize", parent_synthesize):
                result = ResearchAgent._synthesize(
                    agent,
                    "title",
                    "authoritative request",
                    "base objective",
                    [],
                    [],
                    [],
                )
        finally:
            research_compiled._ACTIVE_MATERIALIZED_LEARNING_SKILLS.reset(skill_token)
            research_compiled._ACTIVE_LEARNING_CONTEXT.reset(context_token)

        self.assertEqual(result, {"ok": True})
        objective = captured["objective"]
        self.assertIn("WORKSPACE_APPROVED_MATERIALIZED_LEARNING_SKILLS_SYNTHESIS_ONLY", objective)
        self.assertIn("PRODUCTION-ONLY-REVIEWED-PROCEDURE", objective)
        self.assertNotIn("WORKSPACE_LEARNING_REFERENCE_DATA=", objective)


if __name__ == "__main__":
    unittest.main()
