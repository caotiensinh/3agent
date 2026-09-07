import unittest

from three_agent.runtime_dispatch import (
    RUNTIME_V3_DISPATCH_DESCRIPTOR_SCHEMA,
    RuntimeV3DispatchDescriptor,
    RuntimeV3DispatchError,
    validate_runtime_v3_executor,
)


GOOD = "sha256:" + "1" * 64
GOOD2 = "sha256:" + "2" * 64
GOOD3 = "sha256:" + "3" * 64
GOOD4 = "sha256:" + "4" * 64
GOOD5 = "sha256:" + "5" * 64


class FakeExecutor:
    def describe(self, runtime_ref):
        return runtime_ref

    def execute(self, runtime_ref, **kwargs):
        return runtime_ref, kwargs


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
        for executor in (None, object(), type("DescribeOnly", (), {"describe": lambda self, ref: ref})()):
            with self.subTest(executor=type(executor).__name__):
                with self.assertRaises(RuntimeV3DispatchError):
                    validate_runtime_v3_executor(executor)


if __name__ == "__main__":
    unittest.main()
