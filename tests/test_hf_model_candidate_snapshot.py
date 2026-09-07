import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
AUDIT_SCRIPT = REPO_ROOT / "scripts" / "audit_hf_model_candidate.py"
REVISION = "a" * 40
ARTIFACTS = (
    "config.json",
    "nested/tokenizer.json",
    "model.safetensors",
)


def _load_audit_module():
    spec = importlib.util.spec_from_file_location(
        "workspace_hf_model_candidate_audit_snapshot",
        AUDIT_SCRIPT,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load candidate audit script")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


AUDIT = _load_audit_module()


def _bytes_for(relative: str) -> bytes:
    return f"fixture:{relative}".encode("utf-8")


def _downloader(**kwargs):
    root = Path(kwargs["local_dir"])
    for relative in kwargs["allow_patterns"]:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_bytes_for(relative))
    cache = root / ".cache" / "huggingface"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "metadata.json").write_text("{}", encoding="utf-8")
    return str(root)


class CandidateSnapshotRetentionTests(unittest.TestCase):
    def test_default_audit_still_cleans_temporary_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            payload = AUDIT.audit_candidate(
                repo_id="Example/EmbeddingModel",
                revision=REVISION,
                artifacts=ARTIFACTS,
                downloader=_downloader,
                staging_parent=parent,
            )

            self.assertEqual(payload["status"], "candidate_only")
            self.assertFalse(payload["approval"]["approved"])
            self.assertEqual(list(parent.iterdir()), [])

    def test_explicit_snapshot_output_retains_only_verified_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = root / "verified-snapshot"
            payload = AUDIT.audit_candidate(
                repo_id="Example/EmbeddingModel",
                revision=REVISION,
                artifacts=ARTIFACTS,
                downloader=_downloader,
                staging_parent=root / "staging",
                snapshot_output=snapshot,
            )

            actual = sorted(
                path.relative_to(snapshot).as_posix()
                for path in snapshot.rglob("*")
                if path.is_file()
            )
            self.assertEqual(actual, sorted(ARTIFACTS))
            self.assertFalse((snapshot / ".cache").exists())

            by_path = {item["path"]: item for item in payload["artifacts"]}
            for relative in ARTIFACTS:
                data = _bytes_for(relative)
                self.assertEqual(by_path[relative]["size_bytes"], len(data))
                self.assertEqual(
                    by_path[relative]["sha256"],
                    hashlib.sha256(data).hexdigest(),
                )
                self.assertEqual((snapshot / relative).read_bytes(), data)

    def test_snapshot_output_must_not_preexist(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = root / "existing"
            snapshot.mkdir()
            (snapshot / "stale.bin").write_bytes(b"stale")

            with self.assertRaisesRegex(
                AUDIT.CandidateAuditError,
                "must not already exist",
            ):
                AUDIT.audit_candidate(
                    repo_id="Example/EmbeddingModel",
                    revision=REVISION,
                    artifacts=ARTIFACTS,
                    downloader=_downloader,
                    staging_parent=root / "staging",
                    snapshot_output=snapshot,
                )
            self.assertEqual((snapshot / "stale.bin").read_bytes(), b"stale")

    def test_unrequested_download_content_never_reaches_snapshot_output(self):
        def downloader_with_extra(**kwargs):
            result = _downloader(**kwargs)
            (Path(kwargs["local_dir"]) / "remote_code.py").write_text(
                "raise SystemExit",
                encoding="utf-8",
            )
            return result

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = root / "verified-snapshot"
            with self.assertRaisesRegex(
                AUDIT.CandidateAuditError,
                "unrequested files",
            ):
                AUDIT.audit_candidate(
                    repo_id="Example/EmbeddingModel",
                    revision=REVISION,
                    artifacts=ARTIFACTS,
                    downloader=downloader_with_extra,
                    staging_parent=root / "staging",
                    snapshot_output=snapshot,
                )
            self.assertFalse(snapshot.exists())

    def test_symlinked_download_content_never_reaches_snapshot_output(self):
        def downloader_with_symlink(**kwargs):
            result = _downloader(**kwargs)
            target = Path(kwargs["local_dir"]) / "config.json"
            link = Path(kwargs["local_dir"]) / "linked-config.json"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable on this platform")
            return result

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = root / "verified-snapshot"
            with self.assertRaisesRegex(
                AUDIT.CandidateAuditError,
                "symlinked candidate content is forbidden",
            ):
                AUDIT.audit_candidate(
                    repo_id="Example/EmbeddingModel",
                    revision=REVISION,
                    artifacts=ARTIFACTS,
                    downloader=downloader_with_symlink,
                    staging_parent=root / "staging",
                    snapshot_output=snapshot,
                )
            self.assertFalse(snapshot.exists())


if __name__ == "__main__":
    unittest.main()
