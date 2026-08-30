from __future__ import annotations

import unittest
from pathlib import Path

from three_agent.network_dataset_policy import (
    CacheEntry,
    NetworkDatasetDenied,
    NetworkDatasetManager,
)


ROOT = Path(__file__).resolve().parents[1]


def manager() -> NetworkDatasetManager:
    return NetworkDatasetManager.load(
        policy_path=ROOT / "config/network-data-policy.json",
        registry_path=ROOT / "config/network-datasets.registry.json",
    )


class NetworkDatasetPolicyTests(unittest.TestCase):
    def test_enterprise_dataset_allowed_for_experience_extraction(self):
        plan = manager().plan(
            "cse-cic-ids2018",
            purpose="experience_extraction",
            variant="processed-ml",
            estimated_bytes=1024 * 1024,
            object_count=1,
        )
        self.assertEqual(plan.destination_class, "experience_staging")
        self.assertEqual(plan.variant, "processed-ml")
        self.assertTrue(plan.allowlisted_hosts)

    def test_training_is_secondary_staging_not_durable_log_promotion(self):
        mgr = manager()
        plan = mgr.plan(
            "cse-cic-ids2018",
            purpose="training",
            variant="processed-ml",
            estimated_bytes=1024,
        )
        self.assertEqual(plan.destination_class, "training_staging")
        self.assertFalse(mgr.policy.raw_logs_durable)
        self.assertFalse(mgr.policy.normalized_events_durable)
        self.assertTrue(
            str(mgr.policy.experience_root).endswith("workspace-network-experience/approved")
        )
        self.assertTrue(str(mgr.policy.normalized_staging_root).startswith("/var/cache/"))

    def test_research_only_dataset_denied_for_enterprise_experience_extraction(self):
        with self.assertRaises(NetworkDatasetDenied) as caught:
            manager().plan(
                "mawi",
                purpose="experience_extraction",
                estimated_bytes=1024,
            )
        self.assertEqual(caught.exception.reason_code, "ENTERPRISE_USE_NOT_ALLOWED")

    def test_research_only_dataset_stays_in_research_store(self):
        plan = manager().plan(
            "mawi",
            purpose="research",
            variant="sampled",
            estimated_bytes=1024,
        )
        self.assertEqual(plan.destination_class, "research")

    def test_review_required_fails_closed(self):
        with self.assertRaises(NetworkDatasetDenied) as caught:
            manager().plan(
                "ugr16",
                purpose="research",
                estimated_bytes=1024,
            )
        self.assertEqual(caught.exception.reason_code, "DATASET_STATUS_DENIED")

    def test_full_sync_is_denied(self):
        with self.assertRaises(NetworkDatasetDenied) as caught:
            manager().plan(
                "cse-cic-ids2018",
                purpose="experience_extraction",
                estimated_bytes=1024,
                full_sync=True,
            )
        self.assertEqual(caught.exception.reason_code, "FULL_SYNC_DENIED")

    def test_per_job_byte_budget_is_enforced(self):
        mgr = manager()
        with self.assertRaises(NetworkDatasetDenied) as caught:
            mgr.plan(
                "cse-cic-ids2018",
                purpose="experience_extraction",
                estimated_bytes=mgr.policy.max_job_bytes + 1,
            )
        self.assertEqual(caught.exception.reason_code, "JOB_BYTE_BUDGET_EXCEEDED")

    def test_object_budget_is_enforced(self):
        mgr = manager()
        with self.assertRaises(NetworkDatasetDenied) as caught:
            mgr.plan(
                "splunk-bots-v2",
                purpose="experience_extraction",
                estimated_bytes=1024,
                object_count=mgr.policy.max_objects_per_job + 1,
            )
        self.assertEqual(caught.exception.reason_code, "OBJECT_BUDGET_EXCEEDED")

    def test_lru_eviction_never_selects_pinned_or_active(self):
        mgr = manager()
        one_third = mgr.policy.max_cache_bytes // 3
        entries = [
            CacheEntry("old", one_third, 1.0),
            CacheEntry("pinned", one_third, 0.0, pinned=True),
            CacheEntry("active", one_third, 0.5, active=True),
        ]
        selected = mgr.plan_evictions(entries, incoming_bytes=one_third)
        self.assertEqual(selected, ("old",))

    def test_eviction_fails_when_only_protected_data_can_make_room(self):
        mgr = manager()
        entries = [
            CacheEntry(
                "pinned",
                mgr.policy.max_cache_bytes,
                0.0,
                pinned=True,
            )
        ]
        with self.assertRaises(NetworkDatasetDenied) as caught:
            mgr.plan_evictions(entries, incoming_bytes=1)
        self.assertEqual(caught.exception.reason_code, "CACHE_EVICTION_INSUFFICIENT")

    def test_plan_contains_stable_registry_and_policy_fingerprints(self):
        plan = manager().plan(
            "splunk-bots-v2",
            purpose="experience_extraction",
            variant="attack-only",
            estimated_bytes=4096,
        )
        self.assertTrue(plan.registry_fingerprint.startswith("sha256:"))
        self.assertTrue(plan.policy_fingerprint.startswith("sha256:"))

    def test_policy_forbids_auto_approval_of_dataset_derived_skills(self):
        mgr = manager()
        self.assertFalse(mgr.policy.candidate_skills_auto_approve)
        self.assertGreaterEqual(mgr.policy.minimum_independent_cases_for_pattern, 2)

    def test_provenance_template_marks_raw_and_normalized_as_temporary(self):
        mgr = manager()
        plan = mgr.plan(
            "lanl-comprehensive",
            purpose="experience_extraction",
            estimated_bytes=1024,
        )
        provenance = mgr.provenance_template(
            plan,
            source_object="flows.txt.gz",
            source_sha256="sha256:" + ("a" * 64),
            source_size_bytes=1024,
            fetched_at="2026-08-30T00:00:00Z",
            parser_version="network-normalizer/0.1",
            schema_version="workspace-network-event/v1",
        )
        self.assertEqual(provenance["dataset_id"], "lanl-comprehensive")
        self.assertTrue(provenance["license_source"].startswith("https://"))
        self.assertEqual(provenance["registry_fingerprint"], mgr.registry_fingerprint)
        self.assertEqual(provenance["raw_retention"], "ephemeral")
        self.assertEqual(
            provenance["normalized_retention"], "until_experience_extracted"
        )


if __name__ == "__main__":
    unittest.main()
