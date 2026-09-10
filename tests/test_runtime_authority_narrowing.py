import unittest

from three_agent.capability_authority import (
    CapabilityAuthorityDenied,
    TaskCapabilityAuthority,
)
from three_agent.task_contract import TaskContractCompiler


class RuntimeAuthorityNarrowingTests(unittest.TestCase):
    @staticmethod
    def _parent(*, task_id: str = "TASK-PARENT") -> TaskCapabilityAuthority:
        contract = TaskContractCompiler().compile(
            task_id=task_id,
            task_type="code_fix",
            sensitivity="internal",
            risk_level="medium",
            write_scope=("src", "tests"),
        )
        return TaskCapabilityAuthority.from_contract(contract)

    def test_child_can_only_narrow_parent_authority(self):
        parent = self._parent()
        child = parent.derive_child(
            task_id="TASK-CHILD",
            allowed_tools=("apply_patch",),
            write_scope=("src/runtime",),
            network_scope="deny",
        )

        self.assertEqual(child.sensitivity, parent.sensitivity)
        self.assertEqual(child.allowed_tools, ("apply_patch",))
        self.assertEqual(child.write_scope, ("src/runtime",))
        self.assertEqual(child.network_scope, "deny")
        self.assertNotEqual(child.fingerprint, parent.fingerprint)
        self.assertTrue(
            child.require(
                "apply_patch",
                resource_kind="path",
                resource_ref="src/runtime/node.py",
                effect="write",
            ).allowed
        )
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied, "WRITE_SCOPE_NOT_AUTHORIZED"
        ):
            child.require(
                "apply_patch",
                resource_kind="path",
                resource_ref="src/outside.py",
                effect="write",
            )

    def test_child_cannot_add_capability_missing_from_parent(self):
        parent = self._parent()
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied, "CHILD_CAPABILITY_ESCALATION"
        ):
            parent.derive_child(
                task_id="TASK-CHILD-CAP",
                allowed_tools=parent.allowed_tools + ("web_gateway",),
            )

    def test_child_cannot_expand_or_escape_parent_write_scope(self):
        parent = self._parent()
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied, "CHILD_WRITE_SCOPE_ESCALATION"
        ):
            parent.derive_child(
                task_id="TASK-CHILD-WRITE",
                write_scope=("docs",),
            )
        with self.assertRaisesRegex(ValueError, "safe relative path"):
            parent.derive_child(
                task_id="TASK-CHILD-TRAVERSAL",
                write_scope=("src/../tests",),
            )

    def test_child_cannot_switch_to_broader_or_different_network_scope(self):
        parent = self._parent()
        self.assertEqual(parent.network_scope, "internal_only")
        denied = parent.derive_child(
            task_id="TASK-CHILD-DENIED-NETWORK",
            network_scope="deny",
        )
        self.assertEqual(denied.network_scope, "deny")
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied, "CHILD_NETWORK_SCOPE_ESCALATION"
        ):
            parent.derive_child(
                task_id="TASK-CHILD-NETWORK",
                network_scope="allowlisted_egress",
            )

    def test_grandchild_cannot_regain_authority_removed_from_child(self):
        parent = self._parent()
        child = parent.derive_child(
            task_id="TASK-CHILD-SRC-ONLY",
            write_scope=("src",),
        )
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied, "CHILD_WRITE_SCOPE_ESCALATION"
        ):
            child.derive_child(
                task_id="TASK-GRANDCHILD",
                write_scope=("tests",),
            )

    def test_empty_child_tool_set_is_valid_and_fail_closed(self):
        parent = self._parent()
        child = parent.derive_child(
            task_id="TASK-CHILD-NO-TOOLS",
            allowed_tools=(),
            write_scope="none",
            network_scope="deny",
        )
        self.assertEqual(child.allowed_tools, ())
        self.assertEqual(child.write_scope, "none")
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied, "CAPABILITY_NOT_ALLOWED"
        ):
            child.require(
                "apply_patch",
                resource_kind="path",
                resource_ref="src/runtime.py",
                effect="write",
            )


if __name__ == "__main__":
    unittest.main()
