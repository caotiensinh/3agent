from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from .capability_authority import TaskCapabilityAuthority
from .harness_acceptance import AcceptanceContract, HarnessAcceptanceError
from .prompt_compiler import PromptCompilation, PromptCompiler
from .task_contract import TaskContract

CANONICAL_TASK_SCHEMA = "workspace-canonical-task/v1"
HARNESS_TASK_COMPILER_VERSION = "workspace-harness-task-compiler/deterministic-v1"


class HarnessTaskCompilationError(ValueError):
    """A task cannot be safely bound to canonical intent and acceptance."""


@dataclass(frozen=True)
class CanonicalTaskSpec:
    """In-memory canonical task representation.

    `compiled_intent` remains local working data and is deliberately excluded
    from canonical metadata and fingerprints. The digests bind it without
    creating another persistent raw prompt copy.
    """

    task_id: str
    task_type: str
    sensitivity: str
    risk_level: str
    compiled_intent: str
    prompt_compiler_version: str
    original_sha256: str
    compiled_sha256: str
    task_contract_schema: str
    authority_fingerprint: str
    acceptance_fingerprint: str
    schema_version: str = CANONICAL_TASK_SCHEMA
    compiler_version: str = HARNESS_TASK_COMPILER_VERSION

    def canonical_dict(self) -> dict[str, str]:
        payload = asdict(self)
        payload.pop("compiled_intent", None)
        return {key: str(value) for key, value in payload.items()}

    def canonical_json(self) -> str:
        return json.dumps(
            self.canonical_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()
        return "sha256:" + digest

    def assert_authority_binding(self, task_contract: TaskContract) -> None:
        """Fail closed if execution authority changed after task compilation."""
        current = TaskCapabilityAuthority.from_contract(task_contract)
        if task_contract.task_id != self.task_id:
            raise HarnessTaskCompilationError("TaskContract task_id changed after compilation")
        if current.fingerprint != self.authority_fingerprint:
            raise HarnessTaskCompilationError(
                "TaskContract authority changed after canonical task compilation"
            )


class HarnessTaskCompiler:
    """Bind local prompt intent to immutable execution authority and acceptance.

    This compiler never derives tools, network scope, write scope, model
    authority, or data authority from user text. Those remain exclusively in
    the validated TaskContract / TaskCapabilityAuthority path.
    """

    @staticmethod
    def _compile_prompt(user_prompt: str) -> PromptCompilation:
        return PromptCompiler.compile(user_prompt)

    def compile(
        self,
        *,
        user_prompt: str,
        task_contract: TaskContract,
        acceptance_contract: AcceptanceContract,
    ) -> CanonicalTaskSpec:
        try:
            task_contract.validate()
            acceptance_contract.validate()
        except (ValueError, HarnessAcceptanceError) as exc:
            raise HarnessTaskCompilationError(str(exc)) from exc

        if task_contract.task_id != acceptance_contract.task_id:
            raise HarnessTaskCompilationError(
                "TaskContract and AcceptanceContract must bind the same task_id"
            )

        prompt = self._compile_prompt(user_prompt)
        authority = TaskCapabilityAuthority.from_contract(task_contract)

        return CanonicalTaskSpec(
            task_id=task_contract.task_id,
            task_type=task_contract.task_type,
            sensitivity=task_contract.sensitivity,
            risk_level=task_contract.risk_level,
            compiled_intent=prompt.compiled_text,
            prompt_compiler_version=prompt.compiler_version,
            original_sha256=prompt.original_sha256,
            compiled_sha256=prompt.compiled_sha256,
            task_contract_schema=task_contract.schema_version,
            authority_fingerprint=authority.fingerprint,
            acceptance_fingerprint=acceptance_contract.fingerprint,
        )
