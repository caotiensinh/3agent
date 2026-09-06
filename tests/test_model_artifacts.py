import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.model_artifacts import (
    ApprovedModelManifest,
    HuggingFaceModelProvisioner,
    ModelManifestError,
    ModelProvisioningError,
    ModelResolutionError,
    RuntimeModelResolver,
    apply_runtime_offline_environment,
)


REVISION = "a" * 40


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def manifest_payload(*, model_id="embedding", revision=REVISION, local_subdir="embedding", data=b"weights"):
    return {
        "schema": "workspace.model-manifest/v1",
        "runtime_download": False,
        "models": [
            {
                "id": model_id,
                "provider": "huggingface",
                "repo_id": "Example/EmbeddingModel",
                "revision": revision,
                "local_subdir": local_subdir,
                "capabilities": ["retrieval.embedding"],
                "license": "apache-2.0",
                "artifacts": [
                    {
                        "path": "model.safetensors",
                        "sha256": digest(data),
                        "size_bytes": len(data),
                    }
                ],
            }
        ],
    }


class ApprovedModelManifestTests(unittest.TestCase):
    def write_manifest(self, root: Path, payload):
        path = root / "models.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_exact_commit_revision_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = manifest_payload(revision="main")
            with self.assertRaisesRegex(ModelManifestError, "exact 40-character commit hash"):
                ApprovedModelManifest.load(self.write_manifest(root, payload))

    def test_runtime_download_must_be_explicitly_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = manifest_payload()
            payload["runtime_download"] = True
            with self.assertRaisesRegex(ModelManifestError, "runtime_download"):
                ApprovedModelManifest.load(self.write_manifest(root, payload))

    def test_repo_id_must_not_be_a_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = manifest_payload()
            payload["models"][0]["repo_id"] = "https://huggingface.co/Example/EmbeddingModel"
            with self.assertRaisesRegex(ModelManifestError, "canonical owner/name"):
                ApprovedModelManifest.load(self.write_manifest(root, payload))

    def test_local_subdir_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = manifest_payload(local_subdir="../outside")
            with self.assertRaisesRegex(ModelManifestError, "unsafe path segment"):
                ApprovedModelManifest.load(self.write_manifest(root, payload))

    def test_manifest_requires_artifact_sha256(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = manifest_payload()
            payload["models"][0]["artifacts"][0]["sha256"] = "latest"
            with self.assertRaisesRegex(ModelManifestError, "exact SHA-256"):
                ApprovedModelManifest.load(self.write_manifest(root, payload))

    def test_capability_lookup_is_manifest_derived(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = ApprovedModelManifest.load(self.write_manifest(root, manifest_payload()))
            self.assertEqual(
                [model.model_id for model in manifest.for_capability("retrieval.embedding")],
                ["embedding"],
            )
            self.assertEqual(manifest.for_capability("unapproved.capability"), ())


class ProvisioningTests(unittest.TestCase):
    def prepare(self, root: Path, *, data=b"weights"):
        manifest_path = root / "models.json"
        manifest_path.write_text(json.dumps(manifest_payload(data=data)), encoding="utf-8")
        return ApprovedModelManifest.load(manifest_path), root / "store"

    def test_provision_uses_exact_revision_and_controlled_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, store = self.prepare(root)
            calls = []

            def downloader(**kwargs):
                calls.append(kwargs)
                target = Path(kwargs["local_dir"])
                (target / "model.safetensors").write_bytes(b"weights")
                return str(target)

            provisioner = HuggingFaceModelProvisioner(
                manifest,
                store,
                snapshot_downloader=downloader,
            )
            installed = provisioner.provision("embedding", token="deployment-token")
            self.assertEqual(installed, store / "embedding")
            self.assertEqual(calls[0]["repo_id"], "Example/EmbeddingModel")
            self.assertEqual(calls[0]["revision"], REVISION)
            self.assertEqual(calls[0]["allow_patterns"], ["model.safetensors"])
            self.assertEqual(calls[0]["token"], "deployment-token")
            self.assertTrue((installed / ".workspace-model-receipt.json").is_file())

    def test_hash_mismatch_never_promotes_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, store = self.prepare(root)

            def downloader(**kwargs):
                target = Path(kwargs["local_dir"])
                (target / "model.safetensors").write_bytes(b"tampered")
                return str(target)

            provisioner = HuggingFaceModelProvisioner(manifest, store, snapshot_downloader=downloader)
            with self.assertRaisesRegex(ModelProvisioningError, "SHA-256 mismatch|size mismatch"):
                provisioner.provision("embedding")
            self.assertFalse((store / "embedding").exists())

    def test_downloader_cannot_redirect_outside_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, store = self.prepare(root)
            outside = root / "outside"
            outside.mkdir()

            def downloader(**kwargs):
                target = Path(kwargs["local_dir"])
                (target / "model.safetensors").write_bytes(b"weights")
                return str(outside)

            provisioner = HuggingFaceModelProvisioner(manifest, store, snapshot_downloader=downloader)
            with self.assertRaisesRegex(ModelProvisioningError, "outside the controlled staging"):
                provisioner.provision("embedding")

    def test_existing_install_survives_failed_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, store = self.prepare(root)
            existing = store / "embedding"
            existing.mkdir(parents=True)
            (existing / "sentinel.txt").write_text("keep", encoding="utf-8")

            def downloader(**kwargs):
                target = Path(kwargs["local_dir"])
                (target / "model.safetensors").write_bytes(b"bad")
                return str(target)

            provisioner = HuggingFaceModelProvisioner(manifest, store, snapshot_downloader=downloader)
            with self.assertRaises(ModelProvisioningError):
                provisioner.provision("embedding")
            self.assertEqual((existing / "sentinel.txt").read_text(encoding="utf-8"), "keep")


class RuntimeResolverTests(unittest.TestCase):
    def prepare_installed(self, root: Path):
        manifest_path = root / "models.json"
        manifest_path.write_text(json.dumps(manifest_payload()), encoding="utf-8")
        manifest = ApprovedModelManifest.load(manifest_path)
        store = root / "store"

        def downloader(**kwargs):
            target = Path(kwargs["local_dir"])
            (target / "model.safetensors").write_bytes(b"weights")
            return str(target)

        HuggingFaceModelProvisioner(
            manifest,
            store,
            snapshot_downloader=downloader,
        ).provision("embedding")
        return manifest, store

    def test_missing_local_model_fails_closed_without_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "models.json"
            manifest_path.write_text(json.dumps(manifest_payload()), encoding="utf-8")
            manifest = ApprovedModelManifest.load(manifest_path)
            resolver = RuntimeModelResolver(manifest, root / "store")
            with self.assertRaisesRegex(ModelResolutionError, "runtime download is forbidden"):
                resolver.resolve("embedding")

    def test_runtime_forces_offline_environment(self):
        env = {}
        apply_runtime_offline_environment(env)
        self.assertEqual(env["HF_HUB_OFFLINE"], "1")
        self.assertEqual(env["TRANSFORMERS_OFFLINE"], "1")
        self.assertEqual(env["HF_HUB_DISABLE_TELEMETRY"], "1")

    def test_runtime_resolves_verified_local_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, store = self.prepare_installed(root)
            with patch.dict(os.environ, {}, clear=False):
                resolver = RuntimeModelResolver(manifest, store)
                resolved = resolver.resolve("embedding")
                self.assertEqual(resolved, (store / "embedding").resolve())
                self.assertEqual(os.environ["HF_HUB_OFFLINE"], "1")

    def test_runtime_detects_artifact_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, store = self.prepare_installed(root)
            (store / "embedding" / "model.safetensors").write_bytes(b"tampered")
            resolver = RuntimeModelResolver(manifest, store)
            with self.assertRaisesRegex(ModelResolutionError, "mismatch"):
                resolver.resolve("embedding")

    def test_runtime_detects_manifest_receipt_identity_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, store = self.prepare_installed(root)
            receipt_path = store / "embedding" / ".workspace-model-receipt.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["revision"] = "b" * 40
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            resolver = RuntimeModelResolver(manifest, store)
            with self.assertRaisesRegex(ModelResolutionError, "revision is not approved"):
                resolver.resolve("embedding")

    def test_unapproved_model_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "models.json"
            manifest_path.write_text(json.dumps(manifest_payload()), encoding="utf-8")
            manifest = ApprovedModelManifest.load(manifest_path)
            resolver = RuntimeModelResolver(manifest, root / "store")
            with self.assertRaisesRegex(ModelManifestError, "not approved"):
                resolver.resolve("user-controlled-model")


if __name__ == "__main__":
    unittest.main()
