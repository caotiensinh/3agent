import importlib.util
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
AUDIT_SCRIPT = REPO_ROOT / "scripts" / "audit_hf_model_candidate.py"
REVISION = "a" * 40


def _load_auditor_module():
    spec = importlib.util.spec_from_file_location(
        "workspace_model_candidate_auditor",
        AUDIT_SCRIPT,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load candidate auditor")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AUDITOR = _load_auditor_module()


class ModelCandidateAuditTests(unittest.TestCase):
    def test_exact_commit_revision_is_required(self):
        with self.assertRaisesRegex(AUDITOR.CandidateAuditError, "exact 40-character"):
            AUDITOR.audit_candidate(
                repo_id="Example/Model",
                revision="main",
                artifacts=["config.json"],
                downloader=lambda **_: "",
            )

    def test_repo_url_and_unsafe_artifact_paths_are_rejected(self):
        with self.assertRaisesRegex(AUDITOR.CandidateAuditError, "owner/name"):
            AUDITOR.audit_candidate(
                repo_id="https://huggingface.co/Example/Model",
                revision=REVISION,
                artifacts=["config.json"],
                downloader=lambda **_: "",
            )
        for unsafe in ("../model.bin", "/tmp/model.bin", "C:/models/model.bin"):
            with self.subTest(unsafe=unsafe):
                with self.assertRaises(AUDITOR.CandidateAuditError):
                    AUDITOR.audit_candidate(
                        repo_id="Example/Model",
                        revision=REVISION,
                        artifacts=[unsafe],
                        downloader=lambda **_: "",
                    )

    def test_hashes_only_explicit_candidate_set_and_never_approves(self):
        calls = []

        def downloader(**kwargs):
            calls.append(kwargs)
            target = Path(kwargs["local_dir"])
            (target / "config.json").write_bytes(b"config")
            nested = target / "1_Pooling"
            nested.mkdir()
            (nested / "config.json").write_bytes(b"pool")
            return str(target)

        payload = AUDITOR.audit_candidate(
            repo_id="Example/Model",
            revision=REVISION,
            artifacts=["config.json", "1_Pooling/config.json"],
            token="review-token",
            downloader=downloader,
        )
        self.assertEqual(calls[0]["repo_id"], "Example/Model")
        self.assertEqual(calls[0]["revision"], REVISION)
        self.assertEqual(
            calls[0]["allow_patterns"],
            ["config.json", "1_Pooling/config.json"],
        )
        self.assertEqual(calls[0]["token"], "review-token")
        self.assertEqual(payload["status"], "candidate_only")
        self.assertFalse(payload["approval"]["approved"])
        self.assertFalse(payload["runtime_download"])
        self.assertEqual(
            [item["path"] for item in payload["artifacts"]],
            ["1_Pooling/config.json", "config.json"],
        )
        self.assertTrue(all(len(item["sha256"]) == 64 for item in payload["artifacts"]))
        self.assertEqual(
            {item["path"]: item["size_bytes"] for item in payload["artifacts"]},
            {"1_Pooling/config.json": 4, "config.json": 6},
        )

    def test_unrequested_file_is_rejected(self):
        def downloader(**kwargs):
            target = Path(kwargs["local_dir"])
            (target / "config.json").write_text("{}", encoding="utf-8")
            (target / "remote_code.py").write_text("raise SystemExit", encoding="utf-8")
            return str(target)

        with self.assertRaisesRegex(AUDITOR.CandidateAuditError, "unrequested files"):
            AUDITOR.audit_candidate(
                repo_id="Example/Model",
                revision=REVISION,
                artifacts=["config.json"],
                downloader=downloader,
            )

    def test_hub_metadata_is_removed_before_exact_set_check(self):
        def downloader(**kwargs):
            target = Path(kwargs["local_dir"])
            (target / "config.json").write_text("{}", encoding="utf-8")
            metadata = target / ".cache" / "huggingface"
            metadata.mkdir(parents=True)
            (metadata / "download.json").write_text("{}", encoding="utf-8")
            return str(target)

        payload = AUDITOR.audit_candidate(
            repo_id="Example/Model",
            revision=REVISION,
            artifacts=["config.json"],
            downloader=downloader,
        )
        self.assertEqual([item["path"] for item in payload["artifacts"]], ["config.json"])

    def test_downloader_cannot_redirect_outside_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "outside"
            outside.mkdir()

            def downloader(**kwargs):
                target = Path(kwargs["local_dir"])
                (target / "config.json").write_text("{}", encoding="utf-8")
                return str(outside)

            with self.assertRaisesRegex(AUDITOR.CandidateAuditError, "outside controlled staging"):
                AUDITOR.audit_candidate(
                    repo_id="Example/Model",
                    revision=REVISION,
                    artifacts=["config.json"],
                    downloader=downloader,
                )

    @unittest.skipIf(__import__("os").name == "nt", "symlink creation is privilege-dependent on Windows")
    def test_symlinked_candidate_content_is_rejected(self):
        def downloader(**kwargs):
            target = Path(kwargs["local_dir"])
            real = target / "real.bin"
            real.write_bytes(b"weights")
            (target / "model.bin").symlink_to(real.name)
            return str(target)

        with self.assertRaisesRegex(AUDITOR.CandidateAuditError, "symlinked"):
            AUDITOR.audit_candidate(
                repo_id="Example/Model",
                revision=REVISION,
                artifacts=["model.bin", "real.bin"],
                downloader=downloader,
            )

    def test_duplicate_artifact_allowlist_is_rejected(self):
        with self.assertRaisesRegex(AUDITOR.CandidateAuditError, "duplicates"):
            AUDITOR.audit_candidate(
                repo_id="Example/Model",
                revision=REVISION,
                artifacts=["config.json", "config.json"],
                downloader=lambda **_: "",
            )

    def test_script_does_not_contain_approved_manifest_mutation(self):
        source = AUDIT_SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("models.approved.json", source)
        self.assertNotIn("ApprovedModelManifest", source)
        self.assertIn('"approved": False', source)


if __name__ == "__main__":
    unittest.main()
