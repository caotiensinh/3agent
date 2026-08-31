from __future__ import annotations

import json
import unittest
from pathlib import Path

from three_agent.network_cic_adapter import CIC_ADAPTER_ID, CIC_ADAPTER_VERSION
from three_agent.network_lanl_adapter import LANL_AUTH_ADAPTER_ID, LANL_AUTH_ADAPTER_VERSION
from three_agent.network_lanl_dns_adapter import LANL_DNS_ADAPTER_ID, LANL_DNS_ADAPTER_VERSION
from three_agent.network_lanl_flow_adapter import LANL_FLOW_ADAPTER_ID, LANL_FLOW_ADAPTER_VERSION
from three_agent.network_lanl_process_adapter import (
    LANL_PROCESS_ADAPTER_ID,
    LANL_PROCESS_ADAPTER_VERSION,
)
from three_agent.network_lanl_redteam_matcher import (
    LANL_REDTEAM_MATCHER_ID,
    LANL_REDTEAM_MATCHER_VERSION,
)
from three_agent.network_real_source_acceptance_contract import (
    FAIL_INTEGRITY,
    FAIL_PROVENANCE,
    FAIL_SECURITY,
    MANIFEST_SCHEMA,
    NOT_ENOUGH_REAL_SOURCE_EVIDENCE,
    PASS,
    RECEIPT_SCHEMA,
    LaneObservation,
    RealSourceAcceptanceError,
    canonical_sha256,
    evaluate_coverage,
    validate_manifest,
    validate_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "evaluation" / "network_real_source_acceptance_v1.json"
POLICY_FINGERPRINT = "sha256:" + "a" * 64
VALID_SHA = "sha256:" + "b" * 64
ALT_SHA = "sha256:" + "c" * 64
RECEIPT_SHA = "sha256:" + "d" * 64


def load_profile() -> dict:
    return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))


def cic_registry() -> dict:
    return {
        "schema_version": "workspace-network-dataset-registry/v1",
        "datasets": [
            {
                "id": "cse-cic-ids2018",
                "status": "enterprise_approved",
                "license": {
                    "commercial_use": True,
                    "source": "https://www.unb.ca/cic/datasets/ids-2018.html",
                },
                "acquisition": {
                    "mode": "bounded-manual-fixture",
                    "allowlisted_hosts": ["www.unb.ca"],
                },
                "variants": {"processed-ml": {}},
            }
        ],
    }


def cic_source() -> dict:
    return {
        "source_id": "cic-real-001",
        "dataset_id": "cse-cic-ids2018",
        "variant": "processed-ml",
        "source_family": None,
        "real_source": True,
        "publisher_reference": "https://www.unb.ca/cic/datasets/ids-2018.html",
        "acquisition_mode": "bounded-manual-fixture",
        "acquisition_receipt_fingerprint": RECEIPT_SHA,
        "parent_source_object_ref": "staged/cic/parent.csv",
        "parent_source_sha256": VALID_SHA,
        "parent_source_size_bytes": 4096,
        "bounded_source_object_ref": "staged/cic/slice.csv",
        "bounded_source_sha256": ALT_SHA,
        "bounded_source_size_bytes": 2048,
        "derivation": {
            "method": "record_aligned_slice",
            "selection_rule": "first 1000 reviewed records",
            "record_boundary_rule": "complete CSV records only",
        },
        "adapter_id": CIC_ADAPTER_ID,
        "adapter_version": CIC_ADAPTER_VERSION,
        "provenance_ref": "provenance/cic-real-001.json",
    }


def cic_manifest(*, source: dict | None = None, registry: dict | None = None) -> tuple[dict, dict]:
    registry_value = registry or cic_registry()
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "acceptance_id": "v3-02e-cic-contract-fixture",
        "spec_version": "WORKSPACE_NETWORK_V3_02E_REAL_SOURCE_ACCEPTANCE_SPEC_V1",
        "created_by_role": "HARNESS_TEST",
        "registry_fingerprint": canonical_sha256(registry_value),
        "policy_fingerprint": POLICY_FINGERPRINT,
        "sources": [source or cic_source()],
        "expected_lanes": ["cic_processed_ml"],
        "bots_direct_adapter_authorized": False,
    }
    return manifest, registry_value


def validated_cic_manifest():
    profile = load_profile()
    manifest, registry = cic_manifest()
    return profile, validate_manifest(
        manifest,
        profile=profile,
        registry=registry,
        policy_fingerprint=POLICY_FINGERPRINT,
    )


def pass_receipt() -> dict:
    return {
        "schema_version": RECEIPT_SCHEMA,
        "acceptance_id": "v3-02e-cic-contract-fixture",
        "exact_head_sha": "1" * 40,
        "spec_fingerprint": VALID_SHA,
        "manifest_fingerprint": ALT_SHA,
        "dataset_id": "cse-cic-ids2018",
        "variant": "processed-ml",
        "source_family": None,
        "real_source_verified": True,
        "publisher_reference_fingerprint": VALID_SHA,
        "acquisition_receipt_fingerprint": RECEIPT_SHA,
        "parent_source_sha256": VALID_SHA,
        "bounded_source_sha256": ALT_SHA,
        "adapter_id": CIC_ADAPTER_ID,
        "adapter_version": CIC_ADAPTER_VERSION,
        "records_seen": 1000,
        "records_emitted": 1000,
        "records_rejected": 0,
        "truth_records_emitted": 1000,
        "evidence_fingerprint": VALID_SHA,
        "truth_fingerprint": ALT_SHA,
        "deterministic_replay_pass": True,
        "visible_schema_pass": True,
        "truth_separation_pass": True,
        "provenance_pass": True,
        "resource_pass": True,
        "cleanup_pass": True,
        "network_calls": 0,
        "model_calls": 0,
        "subprocess_calls": 0,
        "peak_rss_delta_bytes": 1024,
        "verdict": PASS,
        "failed_gate_ids": [],
    }


class RealSourceAcceptanceContractTests(unittest.TestCase):
    def test_profile_adapter_bindings_match_production_constants(self) -> None:
        profile = load_profile()
        actual = {
            lane["lane_id"]: (lane["adapter_id"], lane["adapter_version"])
            for lane in profile["authorized_lanes"]
        }
        expected = {
            "cic_processed_ml": (CIC_ADAPTER_ID, CIC_ADAPTER_VERSION),
            "lanl_authentication": (LANL_AUTH_ADAPTER_ID, LANL_AUTH_ADAPTER_VERSION),
            "lanl_process": (LANL_PROCESS_ADAPTER_ID, LANL_PROCESS_ADAPTER_VERSION),
            "lanl_dns": (LANL_DNS_ADAPTER_ID, LANL_DNS_ADAPTER_VERSION),
            "lanl_flow": (LANL_FLOW_ADAPTER_ID, LANL_FLOW_ADAPTER_VERSION),
            "lanl_redteam_truth": (LANL_REDTEAM_MATCHER_ID, LANL_REDTEAM_MATCHER_VERSION),
        }
        self.assertEqual(actual, expected)

    def test_valid_cic_manifest_contract_passes(self) -> None:
        _, manifest = validated_cic_manifest()
        self.assertEqual(manifest.expected_lanes, ("cic_processed_ml",))
        self.assertTrue(manifest.fingerprint.startswith("sha256:"))

    def test_missing_acquisition_receipt_is_provenance_failure(self) -> None:
        source = cic_source()
        source["acquisition_receipt_fingerprint"] = None
        manifest, registry = cic_manifest(source=source)
        with self.assertRaises(RealSourceAcceptanceError) as caught:
            validate_manifest(
                manifest,
                profile=load_profile(),
                registry=registry,
                policy_fingerprint=POLICY_FINGERPRINT,
            )
        self.assertEqual(caught.exception.verdict, FAIL_PROVENANCE)
        self.assertEqual(caught.exception.gate_id, "DIGEST_FORMAT")

    def test_missing_parent_digest_is_provenance_failure(self) -> None:
        source = cic_source()
        source["parent_source_sha256"] = None
        manifest, registry = cic_manifest(source=source)
        with self.assertRaises(RealSourceAcceptanceError) as caught:
            validate_manifest(
                manifest,
                profile=load_profile(),
                registry=registry,
                policy_fingerprint=POLICY_FINGERPRINT,
            )
        self.assertEqual(caught.exception.verdict, FAIL_PROVENANCE)
        self.assertEqual(caught.exception.gate_id, "DIGEST_FORMAT")

    def test_non_string_digest_is_provenance_failure(self) -> None:
        source = cic_source()
        source["bounded_source_sha256"] = 123
        manifest, registry = cic_manifest(source=source)
        with self.assertRaises(RealSourceAcceptanceError) as caught:
            validate_manifest(
                manifest,
                profile=load_profile(),
                registry=registry,
                policy_fingerprint=POLICY_FINGERPRINT,
            )
        self.assertEqual(caught.exception.verdict, FAIL_PROVENANCE)
        self.assertEqual(caught.exception.gate_id, "DIGEST_FORMAT")

    def test_unreviewed_mirror_fails_provenance(self) -> None:
        source = cic_source()
        source["publisher_reference"] = "https://mirror.invalid/cic.csv"
        manifest, registry = cic_manifest(source=source)
        with self.assertRaises(RealSourceAcceptanceError) as caught:
            validate_manifest(
                manifest,
                profile=load_profile(),
                registry=registry,
                policy_fingerprint=POLICY_FINGERPRINT,
            )
        self.assertEqual(caught.exception.verdict, FAIL_PROVENANCE)
        self.assertEqual(caught.exception.gate_id, "UNREVIEWED_PUBLISHER_OR_MIRROR")

    def test_nondeterministic_slice_fails_provenance(self) -> None:
        source = cic_source()
        source["derivation"]["selection_rule"] = "random 1000 records"
        manifest, registry = cic_manifest(source=source)
        with self.assertRaises(RealSourceAcceptanceError) as caught:
            validate_manifest(
                manifest,
                profile=load_profile(),
                registry=registry,
                policy_fingerprint=POLICY_FINGERPRINT,
            )
        self.assertEqual(caught.exception.verdict, FAIL_PROVENANCE)
        self.assertEqual(caught.exception.gate_id, "NONDETERMINISTIC_SLICE_DERIVATION")

    def test_path_escape_is_security_failure(self) -> None:
        source = cic_source()
        source["bounded_source_object_ref"] = "../outside/cic.csv"
        manifest, registry = cic_manifest(source=source)
        with self.assertRaises(RealSourceAcceptanceError) as caught:
            validate_manifest(
                manifest,
                profile=load_profile(),
                registry=registry,
                policy_fingerprint=POLICY_FINGERPRINT,
            )
        self.assertEqual(caught.exception.verdict, FAIL_SECURITY)
        self.assertEqual(caught.exception.gate_id, "PATH_OR_SYMLINK_ESCAPE")

    def test_cic_coverage_pass_requires_benign_and_attack_truth(self) -> None:
        profile, manifest = validated_cic_manifest()
        decision = evaluate_coverage(
            manifest,
            profile=profile,
            observations=[
                LaneObservation(
                    lane_id="cic_processed_ml",
                    valid_records=1000,
                    truth_classes=("Benign", "Bot"),
                )
            ],
        )
        self.assertEqual(decision.verdict, PASS)
        self.assertEqual(decision.failed_gate_ids, ())

    def test_cic_missing_attack_truth_is_not_enough_evidence(self) -> None:
        profile, manifest = validated_cic_manifest()
        decision = evaluate_coverage(
            manifest,
            profile=profile,
            observations=[
                LaneObservation(
                    lane_id="cic_processed_ml",
                    valid_records=1000,
                    truth_classes=("Benign",),
                )
            ],
        )
        self.assertEqual(decision.verdict, NOT_ENOUGH_REAL_SOURCE_EVIDENCE)
        self.assertIn("CIC_MISSING_NON_BENIGN_TRUTH", decision.failed_gate_ids)

    def test_network_call_is_zero_tolerance_security_failure(self) -> None:
        profile, manifest = validated_cic_manifest()
        decision = evaluate_coverage(
            manifest,
            profile=profile,
            observations=[
                LaneObservation(
                    lane_id="cic_processed_ml",
                    valid_records=1000,
                    truth_classes=("Benign", "Bot"),
                    network_calls=1,
                )
            ],
        )
        self.assertEqual(decision.verdict, FAIL_SECURITY)
        self.assertIn("INTERNET_CALL_OBSERVED", decision.failed_gate_ids)

    def test_replay_mismatch_is_integrity_failure(self) -> None:
        profile, manifest = validated_cic_manifest()
        decision = evaluate_coverage(
            manifest,
            profile=profile,
            observations=[
                LaneObservation(
                    lane_id="cic_processed_ml",
                    valid_records=1000,
                    truth_classes=("Benign", "Bot"),
                    deterministic_replay_pass=False,
                )
            ],
        )
        self.assertEqual(decision.verdict, FAIL_INTEGRITY)
        self.assertIn("DETERMINISTIC_REPLAY_MISMATCH", decision.failed_gate_ids)

    def test_valid_pass_receipt_has_stable_fingerprint(self) -> None:
        receipt = pass_receipt()
        self.assertEqual(validate_receipt(receipt), validate_receipt(receipt))

    def test_missing_receipt_digest_is_provenance_failure(self) -> None:
        receipt = pass_receipt()
        receipt["parent_source_sha256"] = None
        with self.assertRaises(RealSourceAcceptanceError) as caught:
            validate_receipt(receipt)
        self.assertEqual(caught.exception.verdict, FAIL_PROVENANCE)
        self.assertEqual(caught.exception.gate_id, "DIGEST_FORMAT")

    def test_pass_receipt_cannot_claim_external_authority(self) -> None:
        receipt = pass_receipt()
        receipt["network_calls"] = 1
        with self.assertRaises(RealSourceAcceptanceError) as caught:
            validate_receipt(receipt)
        self.assertEqual(caught.exception.verdict, FAIL_SECURITY)
        self.assertEqual(caught.exception.gate_id, "PASS_AUTHORITY_NONZERO")


if __name__ == "__main__":
    unittest.main()
