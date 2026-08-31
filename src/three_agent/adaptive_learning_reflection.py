"""Trusted parent-side coordinator for WorkSpace Phase 4B reflection.

This module owns domain binding, summary sanitization, isolated worker invocation,
deterministic candidate construction, Phase 1/2 validation, replay suppression,
and the only allowed persistence call: LearningStagingGateway.stage().
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .adaptive_learning_admission import VerifiedLearningSourceEnvelope
from .adaptive_learning_checkpoint import LearningStagingGateway
from .adaptive_learning_contract import EvidenceReference, ExperienceRecord, KnowledgeCandidate
from .adaptive_learning_evaluation import AdaptiveLearningDomainValidator
from .adaptive_learning_reflection_contract import (
    BoundedReflectionPacket,
    REFLECTION_RESULT_SCHEMA,
    ReflectionContractError,
    ReflectionDomainBinding,
    ReflectionResult,
    parse_strict_reflection_result,
)
from .adaptive_learning_reflection_worker import (
    ReflectionWorkerConfig,
    assert_loopback_ollama_base_url,
)
from .privacy import redact_sensitive_text
from .runtime_efficiency import sanitize_untrusted_payload

RECEIPT_SCHEMA = "workspace-learning-reflection-receipt/v1"
_MAX_SOURCE_SUMMARY_BYTES = 32 * 1024
_MAX_SUMMARY_BYTES = 8 * 1024
_MAX_SUMMARY_CHARS = 3500
_MAX_STDERR_BYTES = 4096
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ASSIGNMENT_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)"
    r"\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.I | re.S,
)
_LOCAL_PATH_RE = re.compile(
    r"(?i)(?:\b[A-Z]:\\(?:Users|ProgramData|Windows)\\[^\s]+|/(?:home|Users|var/lib|srv|etc)/[^\s]+)"
)


class ReflectionError(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _candidate_identity(
    envelope: VerifiedLearningSourceEnvelope,
    binding: ReflectionDomainBinding,
) -> str:
    digest = _sha256(
        {
            "schema_version": "workspace-learning-reflection-candidate-identity/v1",
            "admission_id": envelope.admission_id,
            "domain": binding.domain,
        }
    )
    return "candidate:" + digest.split(":", 1)[1]


def _experience_identity(
    envelope: VerifiedLearningSourceEnvelope,
    binding: ReflectionDomainBinding,
) -> str:
    digest = _sha256(
        {
            "schema_version": "workspace-learning-reflection-experience-identity/v1",
            "admission_id": envelope.admission_id,
            "domain": binding.domain,
        }
    )
    return "experience:" + digest.split(":", 1)[1]


class TrustedReflectionContentBroker:
    """Prepare bounded redacted learning text before any model invocation."""

    @staticmethod
    def _extra_redact(text: str) -> str:
        value = _PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", text)
        value = _JWT_RE.sub("[REDACTED_JWT]", value)
        value = _ASSIGNMENT_SECRET_RE.sub(
            lambda m: f"{m.group(1)}=[REDACTED_SECRET]",
            value,
        )
        value = _LOCAL_PATH_RE.sub("[REDACTED_LOCAL_PATH]", value)
        return value

    def sanitize_summary(self, summary: str) -> str:
        raw = str(summary or "")
        if not raw.strip() or len(raw.encode("utf-8")) > _MAX_SOURCE_SUMMARY_BYTES:
            raise ReflectionError("REFLECTION_SOURCE_SUMMARY_SIZE_INVALID")
        normalized, findings = sanitize_untrusted_payload(raw)
        if findings:
            raise ReflectionError("REFLECTION_SUMMARY_INSTRUCTION_RISK")
        if not isinstance(normalized, str):
            raise ReflectionError("REFLECTION_SOURCE_SUMMARY_INVALID")
        cleaned = self._extra_redact(redact_sensitive_text(normalized))
        cleaned = "\n".join(line.rstrip() for line in cleaned.splitlines()).strip()
        if (
            not cleaned
            or len(cleaned) > _MAX_SUMMARY_CHARS
            or len(cleaned.encode("utf-8")) > _MAX_SUMMARY_BYTES
        ):
            raise ReflectionError("REFLECTION_SUMMARY_SIZE_INVALID")
        return cleaned

    def build_packet(
        self,
        envelope: VerifiedLearningSourceEnvelope,
        binding: ReflectionDomainBinding,
        summary: str,
        *,
        allowed_action: str = "create",
        target_item_id: str | None = None,
        base_item_sha256: str | None = None,
    ) -> BoundedReflectionPacket:
        envelope.to_payload()
        binding.validate(envelope)
        if envelope.capability_grants:
            raise ReflectionError("REFLECTION_SOURCE_CAPABILITY_GRANT_FORBIDDEN")
        if envelope.sensitivity == "secret":
            raise ReflectionError("REFLECTION_SECRET_NOT_SUPPORTED")
        return BoundedReflectionPacket(
            admission_id=envelope.admission_id,
            admission_provenance_sha256=envelope.provenance_sha256,
            binding_sha256=binding.sha256,
            task_id=envelope.task_id,
            domain=binding.domain,
            sensitivity=envelope.sensitivity,
            risk_level=envelope.risk_level,
            outcome=envelope.outcome,
            evidence_hashes=tuple(envelope.evidence_hashes),
            summary=self.sanitize_summary(summary),
            output_schema_version=REFLECTION_RESULT_SCHEMA,
            allowed_action=str(allowed_action).strip().lower(),
            target_item_id=target_item_id,
            base_item_sha256=base_item_sha256,
        ).validate()


@dataclass(frozen=True)
class ReflectionWorkerExecutionConfig:
    base_url: str
    model: str
    timeout_seconds: int = 180
    keep_alive: str = "2m"

    def validate(self) -> "ReflectionWorkerExecutionConfig":
        assert_loopback_ollama_base_url(self.base_url)
        ReflectionWorkerConfig(
            self.base_url,
            self.model,
            self.timeout_seconds,
            self.keep_alive,
        ).validate()
        return self


class IsolatedReflectionRunner:
    """Invoke a no-tool reflection module in a separate Python process."""

    def __init__(
        self,
        config: ReflectionWorkerExecutionConfig,
        *,
        executor: Callable[..., Any] = subprocess.run,
        python_executable: str | None = None,
    ):
        self.config = config.validate()
        self.executor = executor
        self.python_executable = str(python_executable or sys.executable)

    def _environment(self) -> dict[str, str]:
        env = {
            "PYTHONIOENCODING": "utf-8",
            "WORKSPACE_REFLECTION_OLLAMA_BASE_URL": assert_loopback_ollama_base_url(
                self.config.base_url
            ),
            "WORKSPACE_REFLECTION_MODEL": self.config.model,
            "WORKSPACE_REFLECTION_TIMEOUT_SECONDS": str(int(self.config.timeout_seconds)),
            "WORKSPACE_REFLECTION_KEEP_ALIVE": self.config.keep_alive,
        }
        for name in ("SYSTEMROOT", "WINDIR"):
            value = os.environ.get(name)
            if value:
                env[name] = value
        return env

    def run(self, packet: BoundedReflectionPacket) -> ReflectionResult:
        packet.validate()
        encoded = _canonical(packet.to_payload())
        command = (
            self.python_executable,
            "-I",
            "-m",
            "three_agent.adaptive_learning_reflection_worker",
        )
        try:
            with tempfile.TemporaryDirectory(prefix="workspace-reflection-") as tmp:
                completed = self.executor(
                    command,
                    input=encoded,
                    text=True,
                    encoding="utf-8",
                    errors="strict",
                    capture_output=True,
                    timeout=int(self.config.timeout_seconds) + 30,
                    cwd=tmp,
                    env=self._environment(),
                    shell=False,
                    close_fds=True,
                )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ReflectionError("REFLECTION_WORKER_EXECUTION_FAILED") from exc
        if int(getattr(completed, "returncode", 1)) != 0:
            stderr = str(getattr(completed, "stderr", "") or "")
            if len(stderr.encode("utf-8", errors="ignore")) > _MAX_STDERR_BYTES:
                stderr = stderr[:_MAX_STDERR_BYTES]
            raise ReflectionError("REFLECTION_WORKER_FAILED")
        stdout = getattr(completed, "stdout", "")
        try:
            return parse_strict_reflection_result(stdout)
        except ReflectionContractError as exc:
            raise ReflectionError(exc.reason_code) from exc


@dataclass(frozen=True)
class ReflectionReceipt:
    receipt_id: str
    admission_id: str
    domain: str
    binding_sha256: str
    status: str
    result: str | None
    candidate_sha256: str | None
    reason_codes: tuple[str, ...]
    created_at: str
    updated_at: str
    record_sha256: str
    schema_version: str = RECEIPT_SCHEMA

    def signing_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["reason_codes"] = list(self.reason_codes)
        payload.pop("record_sha256")
        return payload

    def to_payload(self) -> dict[str, Any]:
        payload = self.signing_payload()
        payload["record_sha256"] = self.record_sha256
        return payload


class ReflectionReceiptStore:
    """Parent-owned metadata-only deduplication receipts.

    Receipts are not promotion authority and are intentionally outside the
    authenticated learning DB. Deleting one may permit recomputation, but the
    deterministic candidate identity still prevents a second candidate identity
    for the same admission/domain pair.
    """

    def __init__(self, root: Path):
        self.root = Path(root)

    @staticmethod
    def _receipt_id(admission_id: str, domain: str) -> str:
        digest = _sha256(
            {
                "schema_version": RECEIPT_SCHEMA,
                "admission_id": admission_id,
                "domain": domain,
            }
        )
        return "reflection-receipt:" + digest.split(":", 1)[1]

    def _path(self, admission_id: str, domain: str) -> Path:
        receipt_id = self._receipt_id(admission_id, domain)
        return self.root / (receipt_id.split(":", 1)[1] + ".json")

    @staticmethod
    def _record(
        *,
        admission_id: str,
        domain: str,
        binding_sha256: str,
        status: str,
        result: str | None,
        candidate_sha256: str | None,
        reason_codes: tuple[str, ...],
        created_at: str,
        updated_at: str,
    ) -> ReflectionReceipt:
        base = {
            "schema_version": RECEIPT_SCHEMA,
            "receipt_id": ReflectionReceiptStore._receipt_id(admission_id, domain),
            "admission_id": admission_id,
            "domain": domain,
            "binding_sha256": binding_sha256,
            "status": status,
            "result": result,
            "candidate_sha256": candidate_sha256,
            "reason_codes": list(reason_codes),
            "created_at": created_at,
            "updated_at": updated_at,
        }
        return ReflectionReceipt(
            receipt_id=base["receipt_id"],
            admission_id=admission_id,
            domain=domain,
            binding_sha256=binding_sha256,
            status=status,
            result=result,
            candidate_sha256=candidate_sha256,
            reason_codes=reason_codes,
            created_at=created_at,
            updated_at=updated_at,
            record_sha256=_sha256(base),
        )

    @staticmethod
    def _parse(payload: Any) -> ReflectionReceipt:
        fields = {
            "schema_version",
            "receipt_id",
            "admission_id",
            "domain",
            "binding_sha256",
            "status",
            "result",
            "candidate_sha256",
            "reason_codes",
            "created_at",
            "updated_at",
            "record_sha256",
        }
        if (
            not isinstance(payload, dict)
            or set(payload) != fields
            or payload.get("schema_version") != RECEIPT_SCHEMA
        ):
            raise ReflectionError("REFLECTION_RECEIPT_INVALID")
        reasons = payload.get("reason_codes")
        if not isinstance(reasons, list) or len(reasons) > 32:
            raise ReflectionError("REFLECTION_RECEIPT_INVALID")
        receipt = ReflectionReceipt(
            receipt_id=str(payload["receipt_id"]),
            admission_id=str(payload["admission_id"]),
            domain=str(payload["domain"]),
            binding_sha256=str(payload["binding_sha256"]),
            status=str(payload["status"]),
            result=None if payload["result"] is None else str(payload["result"]),
            candidate_sha256=(
                None
                if payload["candidate_sha256"] is None
                else str(payload["candidate_sha256"])
            ),
            reason_codes=tuple(str(x) for x in reasons),
            created_at=str(payload["created_at"]),
            updated_at=str(payload["updated_at"]),
            record_sha256=str(payload["record_sha256"]),
        )
        if receipt.status not in {"claimed", "completed"}:
            raise ReflectionError("REFLECTION_RECEIPT_INVALID")
        if not _SHA.fullmatch(receipt.binding_sha256):
            raise ReflectionError("REFLECTION_RECEIPT_INVALID")
        if receipt.candidate_sha256 is not None and not _SHA.fullmatch(
            receipt.candidate_sha256
        ):
            raise ReflectionError("REFLECTION_RECEIPT_INVALID")
        if receipt.record_sha256 != _sha256(receipt.signing_payload()):
            raise ReflectionError("REFLECTION_RECEIPT_HASH_MISMATCH")
        return receipt

    def read(self, admission_id: str, domain: str) -> ReflectionReceipt | None:
        path = self._path(admission_id, domain)
        if not path.exists():
            return None
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024:
                raise ReflectionError("REFLECTION_RECEIPT_INVALID")
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReflectionError("REFLECTION_RECEIPT_INVALID") from exc
        return self._parse(payload)

    def claim(self, packet: BoundedReflectionPacket) -> ReflectionReceipt:
        packet.validate()
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            if os.name == "posix":
                self.root.chmod(0o700)
        except OSError:
            pass
        path = self._path(packet.admission_id, packet.domain)
        now = _now_z()
        receipt = self._record(
            admission_id=packet.admission_id,
            domain=packet.domain,
            binding_sha256=packet.binding_sha256,
            status="claimed",
            result=None,
            candidate_sha256=None,
            reason_codes=(),
            created_at=now,
            updated_at=now,
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(_canonical(receipt.to_payload()))
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError as exc:
            existing = self.read(packet.admission_id, packet.domain)
            code = (
                "REFLECTION_ALREADY_COMPLETED"
                if existing and existing.status == "completed"
                else "REFLECTION_CLAIM_RECOVERY_REQUIRED"
            )
            raise ReflectionError(code) from exc
        except OSError as exc:
            raise ReflectionError("REFLECTION_RECEIPT_WRITE_FAILED") from exc
        return receipt

    def complete(
        self,
        claimed: ReflectionReceipt,
        *,
        result: str,
        candidate_sha256: str | None = None,
        reason_codes: tuple[str, ...] = (),
    ) -> ReflectionReceipt:
        current = self.read(claimed.admission_id, claimed.domain)
        if (
            current is None
            or current.record_sha256 != claimed.record_sha256
            or current.status != "claimed"
        ):
            raise ReflectionError("REFLECTION_RECEIPT_CONCURRENT_CHANGE")
        now = _now_z()
        completed = self._record(
            admission_id=claimed.admission_id,
            domain=claimed.domain,
            binding_sha256=claimed.binding_sha256,
            status="completed",
            result=result,
            candidate_sha256=candidate_sha256,
            reason_codes=tuple(reason_codes),
            created_at=claimed.created_at,
            updated_at=now,
        )
        path = self._path(claimed.admission_id, claimed.domain)
        temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(temp, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(_canonical(completed.to_payload()))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, path)
            if os.name == "posix":
                path.chmod(0o600)
        except OSError as exc:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
            raise ReflectionError("REFLECTION_RECEIPT_WRITE_FAILED") from exc
        return completed


@dataclass(frozen=True)
class ReflectionOutcome:
    result: str
    admission_id: str
    domain: str
    candidate_id: str | None = None
    candidate_sha256: str | None = None


class ReflectionCoordinator:
    """Higher-trust coordinator. The child model never receives this object."""

    def __init__(
        self,
        staging_gateway: LearningStagingGateway,
        runner: IsolatedReflectionRunner,
        receipt_store: ReflectionReceiptStore,
        *,
        broker: TrustedReflectionContentBroker | None = None,
    ):
        self.staging_gateway = staging_gateway
        self.runner = runner
        self.receipt_store = receipt_store
        self.broker = broker or TrustedReflectionContentBroker()

    @staticmethod
    def _candidate_from_result(
        envelope: VerifiedLearningSourceEnvelope,
        binding: ReflectionDomainBinding,
        packet: BoundedReflectionPacket,
        result: ReflectionResult,
    ) -> KnowledgeCandidate:
        if result.result != "CANDIDATE":
            raise ReflectionError("REFLECTION_RESULT_NOT_CANDIDATE")
        if result.action != packet.allowed_action:
            raise ReflectionError("REFLECTION_ACTION_MISMATCH")
        created_at = _now_z()
        evidence = tuple(
            EvidenceReference(
                ref_id="evidence:" + evidence_hash.split(":", 1)[1],
                sha256=evidence_hash,
                source_type="task_artifact",
                source_task_id=envelope.task_id,
                sensitivity=envelope.sensitivity,
                collection_mode="local_artifact",
                created_at=created_at,
            ).validate()
            for evidence_hash in envelope.evidence_hashes
        )
        experience = ExperienceRecord(
            experience_id=_experience_identity(envelope, binding),
            domain=binding.domain,
            task_id=envelope.task_id,
            outcome=envelope.outcome,
            sensitivity=envelope.sensitivity,
            summary=packet.summary,
            evidence=evidence,
            created_at=created_at,
        ).validate()
        kwargs: dict[str, Any] = {}
        if packet.allowed_action != "create":
            kwargs["target_item_id"] = packet.target_item_id
            kwargs["base_item_sha256"] = packet.base_item_sha256
        candidate = KnowledgeCandidate.from_experiences(
            candidate_id=_candidate_identity(envelope, binding),
            domain=binding.domain,
            kind=result.kind,
            title=result.title.strip(),
            content=result.content.strip(),
            scope=result.scope.strip(),
            sensitivity=envelope.sensitivity,
            risk_level=envelope.risk_level,
            ownership="learner_managed",
            action=packet.allowed_action,
            execution_mode=result.execution_mode,
            experiences=(experience,),
            created_at=created_at,
            **kwargs,
        )
        reasons = AdaptiveLearningDomainValidator.validate(candidate)
        if reasons:
            raise ReflectionError(
                "REFLECTION_DOMAIN_VALIDATION_BLOCKED:" + ",".join(reasons)
            )
        return candidate

    def reflect_and_stage(
        self,
        envelope: VerifiedLearningSourceEnvelope,
        binding: ReflectionDomainBinding,
        summary: str,
        *,
        allowed_action: str = "create",
        target_item_id: str | None = None,
        base_item_sha256: str | None = None,
    ) -> ReflectionOutcome:
        packet = self.broker.build_packet(
            envelope,
            binding,
            summary,
            allowed_action=allowed_action,
            target_item_id=target_item_id,
            base_item_sha256=base_item_sha256,
        )
        claimed = self.receipt_store.claim(packet)
        result = self.runner.run(packet)
        if result.result == "NO_LEARNING_VALUE":
            self.receipt_store.complete(
                claimed,
                result="NO_LEARNING_VALUE",
                reason_codes=("NO_LEARNING_VALUE",),
            )
            return ReflectionOutcome(
                result="NO_LEARNING_VALUE",
                admission_id=envelope.admission_id,
                domain=binding.domain,
            )
        try:
            candidate = self._candidate_from_result(envelope, binding, packet, result)
        except ReflectionError as exc:
            reason = exc.reason_code.split(":", 1)[0]
            self.receipt_store.complete(
                claimed,
                result="REJECTED",
                reason_codes=(reason,),
            )
            raise
        self.staging_gateway.stage(candidate)
        self.receipt_store.complete(
            claimed,
            result="STAGED",
            candidate_sha256=candidate.sha256,
        )
        return ReflectionOutcome(
            result="STAGED",
            admission_id=envelope.admission_id,
            domain=binding.domain,
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
        )
