import json
import tempfile
import unittest
from pathlib import Path

from three_agent.runtime_dispatch import (
    RUNTIME_V3_DISPATCH_DESCRIPTOR_SCHEMA,
    DurableRuntimeV3DispatchExecutor,
    RuntimeV3DispatchDescriptor,
    RuntimeV3DispatchError,
    validate_runtime_v3_executor,
)


GOOD = "sha256:" + "1" * 64
GOOD2 = "sha256:" + "2" * 64
GOOD3 = "sha256:" + "3" * 64
GOOD4 = "sha256:" + "4" * 64
GOOD5 = "sha256:" + "5" * 64
APPROVAL = "sha256:" + "a" * 64
APPROVER = "sha256:" + "b" * 64


class FakeExecutor:
    def describe(self, runtime_ref):
        return runtime_ref

    def execute(self, runtime_ref, **kwargs):
        return runtime_ref, kwargs


class DurableFakeProvider:
    durable = True

    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.describe_calls = []
        self.execute_calls = []

    def describe_package(self, package_ref):
        self.describe_calls.append(package_ref)
        return self.descriptor

    def execute_package(self, package_ref, **kwargs):
        self.execute_calls.append((package_ref, kwargs))
        return {
            "status": "completed",
            "task_status": "done",
            "stage": "runtime_provider_completed",
        }


class RuntimeV3DispatchContractTests(unittest.TestCase):
    @staticmethod
    def descriptor(**overrides):
        values = {
            "task_id": "task-123",
            "runtime_ref": "runtime:codefix-001",
            "compiled_plan_fingerprint": GOOD,
            "invocation_bundle_fingerprint": GOOD2,
            "authority_fingerprint": GOOD3,
            "source_binding_bundle_fingerprint": GOOD4,
            "query_bundle_fingerprint": None,
        }
        values.update(overrides)
        return RuntimeV3DispatchDescriptor(**values)

    def test_descriptor_is_content_free_and_fingerprint_stable(self):
        descriptor = self.descriptor().validate()
        metadata = descriptor.metadata()
        self.assertEqual(metadata["schema_version"], RUNTIME_V3_DISPATCH_DESCRIPTOR_SCHEMA)
        self.assertEqual(descriptor.fingerprint, self.descriptor().fingerprint)
        restored = RuntimeV3DispatchDescriptor.from_metadata(metadata)
        self.assertEqual(restored, descriptor)
        encoded = repr(metadata)
        for forbidden in (
            "SELECT ",
            "diff --git",
            "/srv/workspace",
            "https://",
            "secret-value",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_descriptor_fingerprint_changes_on_any_runtime_semantic_binding(self):
        baseline = self.descriptor().fingerprint
        mutations = (
            {"compiled_plan_fingerprint": GOOD5},
            {"invocation_bundle_fingerprint": GOOD5},
            {"authority_fingerprint": GOOD5},
            {"source_binding_bundle_fingerprint": GOOD5},
            {"query_bundle_fingerprint": GOOD5},
            {"runtime_ref": "runtime:codefix-002"},
        )
        for change in mutations:
            with self.subTest(change=change):
                self.assertNotEqual(baseline, self.descriptor(**change).fingerprint)

    def test_runtime_ref_cannot_be_url_or_empty(self):
        for value in ("", "https://example.com/runtime", "../runtime"):
            with self.subTest(value=value):
                with self.assertRaises(RuntimeV3DispatchError):
                    self.descriptor(runtime_ref=value).validate()

    def test_all_required_fingerprints_are_strict_sha256(self):
        fields = (
            "compiled_plan_fingerprint",
            "invocation_bundle_fingerprint",
            "authority_fingerprint",
        )
        for field in fields:
            with self.subTest(field=field):
                with self.assertRaises(RuntimeV3DispatchError):
                    self.descriptor(**{field: "sha256:abcd"}).validate()

    def test_optional_bundle_fingerprints_are_validated_when_present(self):
        with self.assertRaises(RuntimeV3DispatchError):
            self.descriptor(source_binding_bundle_fingerprint="not-a-digest").validate()
        with self.assertRaises(RuntimeV3DispatchError):
            self.descriptor(query_bundle_fingerprint="not-a-digest").validate()

    def test_executor_protocol_fails_closed(self):
        self.assertIs(validate_runtime_v3_executor(FakeExecutor()).__class__, FakeExecutor)
        for executor in (
            None,
            object(),
            type("DescribeOnly", (), {"describe": lambda self, ref: ref})(),
        ):
            with self.subTest(executor=type(executor).__name__):
                with self.assertRaises(RuntimeV3DispatchError):
                    validate_runtime_v3_executor(executor)

    def test_durable_executor_survives_restart_and_executes_exact_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            descriptor = self.descriptor().validate()
            provider1 = DurableFakeProvider(descriptor)
            executor1 = DurableRuntimeV3DispatchExecutor(Path(tmp))
            executor1.register_provider("codefix", provider1)
            registered = executor1.register_package(
                provider_id="codefix",
                package_ref="package:reviewed-001",
            )
            self.assertEqual(registered, descriptor)

            # New executor + new provider object models a process restart. The
            # registration source of truth is the durable manifest on disk.
            provider2 = DurableFakeProvider(descriptor)
            executor2 = DurableRuntimeV3DispatchExecutor(
                Path(tmp), providers={"codefix": provider2}
            )
            self.assertEqual(executor2.describe(descriptor.runtime_ref), descriptor)
            result = executor2.execute(
                descriptor.runtime_ref,
                expected_descriptor_fingerprint=descriptor.fingerprint,
                approval_fingerprint=APPROVAL,
                approver_ref=APPROVER,
            )
            self.assertEqual(result["status"], "completed")
            self.assertEqual(len(provider2.execute_calls), 1)
            package_ref, kwargs = provider2.execute_calls[0]
            self.assertEqual(package_ref, "package:reviewed-001")
            self.assertEqual(
                kwargs["expected_descriptor_fingerprint"], descriptor.fingerprint
            )
            self.assertEqual(kwargs["approval_fingerprint"], APPROVAL)
            self.assertEqual(kwargs["approver_ref"], APPROVER)

    def test_manifest_contains_only_opaque_refs_and_fingerprints(self):
        with tempfile.TemporaryDirectory() as tmp:
            descriptor = self.descriptor().validate()
            provider = DurableFakeProvider(descriptor)
            executor = DurableRuntimeV3DispatchExecutor(
                Path(tmp), providers={"codefix": provider}
            )
            executor.register_package(
                provider_id="codefix",
                package_ref="package:reviewed-001",
            )
            files = list(Path(tmp).glob("*.json"))
            self.assertEqual(len(files), 1)
            payload = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(
                set(payload),
                {"schema_version", "payload_sha256", "manifest"},
            )
            manifest = payload["manifest"]
            self.assertEqual(
                set(manifest),
                {
                    "schema_version",
                    "runtime_ref",
                    "provider_id",
                    "package_ref",
                    "descriptor",
                    "descriptor_fingerprint",
                },
            )
            descriptor_payload = manifest["descriptor"]
            self.assertEqual(
                set(descriptor_payload),
                {
                    "schema_version",
                    "task_id",
                    "runtime_ref",
                    "compiled_plan_fingerprint",
                    "invocation_bundle_fingerprint",
                    "authority_fingerprint",
                    "source_binding_bundle_fingerprint",
                    "query_bundle_fingerprint",
                },
            )
            self.assertNotIn("compiled_plan", descriptor_payload)
            self.assertNotIn("invocation_bundle", descriptor_payload)
            self.assertNotIn("source_binding_bundle", descriptor_payload)
            self.assertNotIn("query_bundle", descriptor_payload)
            self.assertEqual(manifest["package_ref"], "package:reviewed-001")
            encoded = repr(payload)
            for forbidden in (
                "SELECT * FROM",
                "diff --git",
                "/srv/workspace/private",
                "secret-value",
            ):
                self.assertNotIn(forbidden, encoded)

    def test_descriptor_drift_after_registration_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            descriptor = self.descriptor().validate()
            provider = DurableFakeProvider(descriptor)
            executor = DurableRuntimeV3DispatchExecutor(
                Path(tmp), providers={"codefix": provider}
            )
            executor.register_package(
                provider_id="codefix",
                package_ref="package:reviewed-001",
            )
            provider.descriptor = self.descriptor(
                compiled_plan_fingerprint=GOOD5
            ).validate()
            with self.assertRaisesRegex(
                RuntimeV3DispatchError,
                "RUNTIME_V3_PROVIDER_DESCRIPTOR_CHANGED",
            ):
                executor.describe(descriptor.runtime_ref)
            self.assertEqual(provider.execute_calls, [])

    def test_missing_or_non_durable_provider_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            executor = DurableRuntimeV3DispatchExecutor(Path(tmp))
            with self.assertRaisesRegex(
                RuntimeV3DispatchError,
                "RUNTIME_V3_DURABLE_PROVIDER_REQUIRED",
            ):
                executor.register_provider(
                    "bad",
                    type(
                        "BadProvider",
                        (),
                        {
                            "durable": False,
                            "describe_package": lambda self, ref: self.descriptor,
                            "execute_package": lambda self, ref, **kwargs: None,
                        },
                    )(),
                )
            with self.assertRaisesRegex(
                RuntimeV3DispatchError,
                "RUNTIME_V3_PROVIDER_NOT_REGISTERED",
            ):
                executor.register_package(
                    provider_id="missing",
                    package_ref="package:reviewed-001",
                )

    def test_tampered_manifest_is_rejected_before_provider_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            descriptor = self.descriptor().validate()
            provider = DurableFakeProvider(descriptor)
            executor = DurableRuntimeV3DispatchExecutor(
                Path(tmp), providers={"codefix": provider}
            )
            executor.register_package(
                provider_id="codefix",
                package_ref="package:reviewed-001",
            )
            path = next(Path(tmp).glob("*.json"))
            envelope = json.loads(path.read_text(encoding="utf-8"))
            envelope["manifest"]["package_ref"] = "package:tampered"
            path.write_text(json.dumps(envelope), encoding="utf-8")
            with self.assertRaisesRegex(
                RuntimeV3DispatchError,
                "RUNTIME_V3_MANIFEST_PAYLOAD_INTEGRITY_MISMATCH",
            ):
                executor.execute(
                    descriptor.runtime_ref,
                    expected_descriptor_fingerprint=descriptor.fingerprint,
                    approval_fingerprint=APPROVAL,
                    approver_ref=APPROVER,
                )
            self.assertEqual(provider.execute_calls, [])


if __name__ == "__main__":
    unittest.main()
