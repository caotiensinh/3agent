from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Iterable


class SkillSecurityError(RuntimeError):
    pass


# Enterprise-lean hard limits. SKILL.md stays compact procedure. Stable reference
# material may be disclosed on demand, but is separately registered, hashed,
# scanned, and bounded; it never becomes executable authority.
MAX_SKILL_BYTES = 3072
MAX_SKILLS_PER_LOAD = 2
MAX_LOADED_SKILL_BYTES = 4096
MAX_SKILL_REFERENCES = 8
MAX_SKILL_REFERENCE_BYTES = 16 * 1024
MAX_SKILL_REFERENCE_TOTAL_BYTES = 64 * 1024

_SKILL_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_REFERENCE_ID_RE = _SKILL_NAME_RE
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_FRONTMATTER = {"allowed-tools", "hooks", "mcp", "mcp-servers"}
_DANGEROUS_FENCE_RE = re.compile(
    r"(?im)^\s*(?:curl|wget|sudo|ssh|scp|rsync|nc|ncat|bash|sh|powershell|pwsh|"
    r"git\s+push|chmod|chown|rm\s+-rf)\b"
)
_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:~\/\.(?:ssh|aws|gnupg)|\/etc\/shadow|(?:^|[\s/])\.netrc\b|"
    r"\bid_(?:rsa|ed25519)\b)"
)
_SECRET_LITERAL_RE = re.compile(
    r"(?:\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bsk-[A-Za-z0-9_-]{20,}\b|"
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
_EXTERNAL_URL_RE = re.compile(r"https?://", re.IGNORECASE)
_PREPROMPT_EXEC_RE = re.compile(r"!\s*`[^`\n]+`")
_BIDI_OR_TAG_RE = re.compile(r"[\u202a-\u202e\u2066-\u2069\U000E0000-\U000E007F]")
_FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_REFERENCE_INJECTION_RE = re.compile(
    r"(?i)\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions\b"
    r"|\b(?:bypass|override)\s+(?:the\s+)?(?:security|approval|policy|system|developer)\b"
)
_ALLOWED_REFERENCE_CONTENT_CLASSES = frozenset(
    {"reviewed-reference", "vendor-runbook", "project-runbook", "examples"}
)
_REFERENCE_REQUIRED_FIELDS = frozenset(
    {"path", "sha256", "size_bytes", "provenance", "content_class"}
)
_REFERENCE_OPTIONAL_FIELDS = frozenset({"vendor_family", "version"})


def _canonical_instruction_text(raw: bytes) -> str:
    """Decode reviewed text and normalize only newline encoding.

    Git may check out text as CRLF on Windows while a security review was
    recorded against LF content. Newline representation is transport metadata,
    not instruction authority, so integrity digests and declared reference sizes
    are defined over UTF-8 text with canonical LF line endings.
    """

    text = raw.decode("utf-8")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _skill_digest(raw: bytes) -> str:
    canonical = _canonical_instruction_text(raw).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _frontmatter(text: str) -> tuple[dict[str, str], str]:
    if not text.startswith("---\n"):
        raise SkillSecurityError("SKILL.md must start with YAML frontmatter")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise SkillSecurityError("SKILL.md frontmatter is not closed")
    metadata: dict[str, str] = {}
    for raw in text[4:end].splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip().strip('"').strip("'")
    return metadata, text[end + 5 :].strip()


def _scan_instruction_text(name: str, text: str) -> None:
    metadata, body = _frontmatter(text)
    forbidden = sorted(_FORBIDDEN_FRONTMATTER.intersection(key.casefold() for key in metadata))
    if forbidden:
        raise SkillSecurityError(f"Skill {name} contains forbidden authority metadata: {', '.join(forbidden)}")
    if _BIDI_OR_TAG_RE.search(text):
        raise SkillSecurityError(f"Skill {name} contains invisible/bidirectional instruction characters")
    if _PREPROMPT_EXEC_RE.search(text):
        raise SkillSecurityError(f"Skill {name} contains pre-prompt command execution syntax")
    if _SENSITIVE_PATH_RE.search(body):
        raise SkillSecurityError(f"Skill {name} references sensitive host credential paths")
    if _SECRET_LITERAL_RE.search(body):
        raise SkillSecurityError(f"Skill {name} contains a secret-looking literal")
    if _EXTERNAL_URL_RE.search(body):
        raise SkillSecurityError(f"Skill {name} contains an external runtime URL")
    for fence in _FENCE_RE.findall(body):
        if _DANGEROUS_FENCE_RE.search(fence):
            raise SkillSecurityError(f"Skill {name} contains a risky executable command block")


def _scan_reference_text(name: str, reference_id: str, text: str) -> None:
    """Apply the E2 passive-reference safety policy to one reviewed reference.

    Reference documents are knowledge only. Source URLs belong in registry
    provenance, not in model-visible reference text, and executable command blocks
    remain outside this production skill tier.
    """

    label = f"{name}/{reference_id}"
    if not text.strip():
        raise SkillSecurityError(f"Skill reference is empty: {label}")
    if _BIDI_OR_TAG_RE.search(text):
        raise SkillSecurityError(f"Skill reference contains invisible/bidirectional characters: {label}")
    if _PREPROMPT_EXEC_RE.search(text):
        raise SkillSecurityError(f"Skill reference contains pre-prompt command execution syntax: {label}")
    if _SENSITIVE_PATH_RE.search(text):
        raise SkillSecurityError(f"Skill reference names sensitive credential paths: {label}")
    if _SECRET_LITERAL_RE.search(text):
        raise SkillSecurityError(f"Skill reference contains a secret-looking literal: {label}")
    if _EXTERNAL_URL_RE.search(text):
        raise SkillSecurityError(f"Skill reference contains an external runtime URL: {label}")
    if _REFERENCE_INJECTION_RE.search(text):
        raise SkillSecurityError(f"Skill reference contains prompt-injection-like instructions: {label}")
    for fence in _FENCE_RE.findall(text):
        if _DANGEROUS_FENCE_RE.search(fence):
            raise SkillSecurityError(f"Skill reference contains a risky executable command block: {label}")


def _validate_enterprise_baseline(payload: dict) -> None:
    """Reject a declared enterprise baseline that weakens hard WorkSpace limits.

    Older isolated fixtures may omit the optional baseline and remain compatible.
    Production registry metadata is therefore descriptive plus fail-closed when
    present; the code constants above remain the absolute upper bounds.
    """

    baseline = payload.get("enterprise_baseline")
    if baseline is None:
        return
    if not isinstance(baseline, dict):
        raise SkillSecurityError("Invalid enterprise skill baseline")

    required_false = (
        "network_access",
        "credential_access",
        "persistent_self_modify",
        "external_code_vendored",
        "raw_sensitive_logging",
    )
    if baseline.get("instruction_only") is not True:
        raise SkillSecurityError("Enterprise skill baseline must remain instruction_only=true")
    for field in required_false:
        if baseline.get(field) is not False:
            raise SkillSecurityError(f"Enterprise skill baseline must declare {field}=false")
    if baseline.get("model_authority") != "advisory":
        raise SkillSecurityError("Enterprise skill baseline model_authority must be advisory")
    if baseline.get("enterprise_tier") != "E2":
        raise SkillSecurityError("Production enterprise skill baseline must be E2")

    limits = {
        "max_skill_bytes": MAX_SKILL_BYTES,
        "max_skills_per_load": MAX_SKILLS_PER_LOAD,
        "max_loaded_skill_bytes": MAX_LOADED_SKILL_BYTES,
    }
    for field, hard_limit in limits.items():
        value = baseline.get(field)
        if not isinstance(value, int) or value < 1 or value > hard_limit:
            raise SkillSecurityError(
                f"Enterprise skill baseline {field} must be between 1 and {hard_limit}"
            )


def _reference_manifest(entry: dict, name: str) -> dict[str, dict]:
    raw_references = entry.get("references", {})
    if raw_references is None:
        raw_references = {}
    if not isinstance(raw_references, dict):
        raise SkillSecurityError(f"Skill references registry must be an object: {name}")
    if len(raw_references) > MAX_SKILL_REFERENCES:
        raise SkillSecurityError(
            f"Skill {name} exceeds reference count limit of {MAX_SKILL_REFERENCES}"
        )

    normalized: dict[str, dict] = {}
    seen_paths: set[str] = set()
    total_bytes = 0
    for reference_id in sorted(raw_references):
        if not isinstance(reference_id, str) or not _REFERENCE_ID_RE.fullmatch(reference_id):
            raise SkillSecurityError(f"Invalid skill reference id: {name}/{reference_id}")
        meta = raw_references[reference_id]
        if not isinstance(meta, dict):
            raise SkillSecurityError(f"Invalid skill reference metadata: {name}/{reference_id}")
        fields = set(meta)
        if not _REFERENCE_REQUIRED_FIELDS.issubset(fields) or fields - (
            _REFERENCE_REQUIRED_FIELDS | _REFERENCE_OPTIONAL_FIELDS
        ):
            raise SkillSecurityError(f"Invalid skill reference metadata fields: {name}/{reference_id}")

        raw_path = str(meta.get("path") or "").strip()
        posix = PurePosixPath(raw_path)
        if (
            not raw_path
            or posix.is_absolute()
            or len(posix.parts) != 2
            or posix.parts[0] != "references"
            or posix.parts[1] in {".", ".."}
            or posix.suffix.lower() != ".md"
            or any(part in {"", ".", ".."} for part in posix.parts)
        ):
            raise SkillSecurityError(f"Unsafe skill reference path: {name}/{reference_id}")
        normalized_path = posix.as_posix()
        if normalized_path in seen_paths:
            raise SkillSecurityError(f"Duplicate skill reference path: {name}/{normalized_path}")
        seen_paths.add(normalized_path)

        digest = str(meta.get("sha256") or "").strip().lower()
        if not _SHA256_RE.fullmatch(digest):
            raise SkillSecurityError(f"Invalid skill reference SHA-256: {name}/{reference_id}")
        size_bytes = meta.get("size_bytes")
        if (
            not isinstance(size_bytes, int)
            or isinstance(size_bytes, bool)
            or not 1 <= size_bytes <= MAX_SKILL_REFERENCE_BYTES
        ):
            raise SkillSecurityError(f"Invalid skill reference size: {name}/{reference_id}")
        total_bytes += size_bytes
        if total_bytes > MAX_SKILL_REFERENCE_TOTAL_BYTES:
            raise SkillSecurityError(
                f"Skill {name} exceeds total reference byte limit of {MAX_SKILL_REFERENCE_TOTAL_BYTES}"
            )

        provenance = meta.get("provenance")
        if not isinstance(provenance, list) or not provenance or not all(
            isinstance(item, str) and item.strip() for item in provenance
        ):
            raise SkillSecurityError(f"Skill reference provenance is missing or invalid: {name}/{reference_id}")
        content_class = str(meta.get("content_class") or "").strip()
        if content_class not in _ALLOWED_REFERENCE_CONTENT_CLASSES:
            raise SkillSecurityError(f"Unsupported skill reference content class: {name}/{reference_id}")

        copied = dict(meta)
        copied["path"] = normalized_path
        copied["sha256"] = digest
        copied["size_bytes"] = size_bytes
        copied["content_class"] = content_class
        for optional in _REFERENCE_OPTIONAL_FIELDS:
            if optional in copied:
                value = copied[optional]
                if value is not None:
                    text = str(value).strip()
                    if not text or len(text) > 160:
                        raise SkillSecurityError(
                            f"Invalid skill reference {optional}: {name}/{reference_id}"
                        )
                    copied[optional] = text
        normalized[reference_id] = copied

    return normalized


class ApprovedSkillLoader:
    """Load only repository-local skills that passed the recorded security review.

    The loader supports compact instruction-only SKILL.md files plus optional
    reviewed read-only ``references/*.md`` packs. References are knowledge, not
    executable resources: each file must be registered, content-addressed,
    provenance-bound, size-bounded, and safe-scanned. ``scripts/`` and all other
    unreviewed resources remain prohibited in E2 production skills.
    """

    def __init__(self, root: Path):
        self.root = Path(root)
        self.registry_path = self.root / "registry.json"

    def _registry(self) -> dict:
        if not self.registry_path.exists():
            return {"schema_version": 1, "policy": "no-registry-no-skills", "skills": {}}
        payload = json.loads(self.registry_path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != 1 or not isinstance(payload.get("skills"), dict):
            raise SkillSecurityError("Unsupported or invalid skill registry")
        _validate_enterprise_baseline(payload)
        return payload

    def _review_path(self, entry: dict, name: str) -> Path:
        review = entry.get("review")
        if not isinstance(review, str) or not review.strip():
            raise SkillSecurityError(f"Skill security review is missing: {name}")

        project_root = self.root.resolve().parent
        path = (project_root / review).resolve()
        if path != project_root and project_root not in path.parents:
            raise SkillSecurityError(f"Skill review path escapes repository root: {name}")
        if not path.is_file():
            raise SkillSecurityError(f"Skill security review file does not exist: {name}")
        return path

    @staticmethod
    def _enforce_authority(entry: dict, name: str) -> None:
        if entry.get("instruction_only") is not True:
            raise SkillSecurityError(f"Executable third-party skills are not allowed by this loader: {name}")
        for field in (
            "network_access",
            "credential_access",
            "persistent_self_modify",
            "external_code_vendored",
        ):
            if entry.get(field) is not False:
                raise SkillSecurityError(f"Skill {name} must explicitly declare {field}=false")
        provenance = entry.get("provenance")
        if not isinstance(provenance, list) or not provenance or not all(
            isinstance(item, str) and item.strip() for item in provenance
        ):
            raise SkillSecurityError(f"Skill provenance is missing or invalid: {name}")

    def _validated_references(self, name: str, entry: dict, skill_dir: Path) -> dict[str, str]:
        manifest = _reference_manifest(entry, name)
        references_dir = skill_dir / "references"

        if not manifest:
            if references_dir.exists() or references_dir.is_symlink():
                raise SkillSecurityError(f"Skill contains unregistered references directory: {name}")
            return {}
        if references_dir.is_symlink() or not references_dir.is_dir():
            raise SkillSecurityError(f"Approved references directory is missing or unsafe: {name}")

        registered_paths = {str(meta["path"]) for meta in manifest.values()}
        actual_paths: set[str] = set()
        for item in references_dir.iterdir():
            if item.is_symlink() or not item.is_file():
                raise SkillSecurityError(f"Reviewed skill reference is not a regular file: {name}/{item.name}")
            actual_paths.add(f"references/{item.name}")
        if actual_paths != registered_paths:
            missing = sorted(registered_paths - actual_paths)
            extra = sorted(actual_paths - registered_paths)
            detail = ", ".join([*(f"missing:{item}" for item in missing), *(f"extra:{item}" for item in extra)])
            raise SkillSecurityError(f"Skill reference registry/files mismatch: {name}: {detail}")

        validated: dict[str, str] = {}
        resolved_skill = skill_dir.resolve()
        resolved_references = references_dir.resolve()
        for reference_id, meta in manifest.items():
            posix = PurePosixPath(str(meta["path"]))
            path = skill_dir.joinpath(*posix.parts)
            resolved = path.resolve()
            if resolved.parent != resolved_references or resolved_skill not in resolved.parents:
                raise SkillSecurityError(f"Skill reference path escapes approved directory: {name}/{reference_id}")
            raw = path.read_bytes()
            try:
                text = _canonical_instruction_text(raw)
            except UnicodeDecodeError as exc:
                raise SkillSecurityError(f"Skill reference must be UTF-8: {name}/{reference_id}") from exc
            canonical = text.encode("utf-8")
            if len(canonical) != int(meta["size_bytes"]):
                raise SkillSecurityError(f"Skill reference size mismatch: {name}/{reference_id}")
            if hashlib.sha256(canonical).hexdigest() != str(meta["sha256"]):
                raise SkillSecurityError(f"Skill reference integrity mismatch: {name}/{reference_id}")
            _scan_reference_text(name, reference_id, text)
            validated[reference_id] = text.strip()
        return validated

    def _validate_skill(self, name: str, entry: dict) -> str:
        self._enforce_authority(entry, name)
        self._review_path(entry, name)

        skill_dir = (self.root / name).resolve()
        root_resolved = self.root.resolve()
        if root_resolved not in skill_dir.parents:
            raise SkillSecurityError(f"Skill path escapes approved root: {name}")
        if not skill_dir.is_dir():
            raise SkillSecurityError(f"Approved skill directory is missing: {name}")

        entries = list(skill_dir.iterdir())
        if any(item.is_symlink() for item in entries):
            raise SkillSecurityError(f"Reviewed instruction-only skill contains a symlink: {name}")
        unexpected = sorted(item.name for item in entries if item.name not in {"SKILL.md", "references"})
        if unexpected:
            raise SkillSecurityError(
                f"Reviewed instruction-only skill contains unreviewed resources: {name}: {', '.join(unexpected)}"
            )
        references_entry = skill_dir / "references"
        if references_entry.exists() and not references_entry.is_dir():
            raise SkillSecurityError(f"Skill references path is not a directory: {name}")

        path = skill_dir / "SKILL.md"
        if not path.is_file():
            raise SkillSecurityError(f"Approved SKILL.md is missing: {name}")
        raw = path.read_bytes()
        if len(raw) > MAX_SKILL_BYTES:
            raise SkillSecurityError(
                f"Skill exceeds enterprise-lean {MAX_SKILL_BYTES}-byte review limit: {name}"
            )
        actual = _skill_digest(raw)
        expected = str(entry.get("sha256", ""))
        if not expected or actual != expected:
            raise SkillSecurityError(f"Skill integrity mismatch: {name}")

        text = _canonical_instruction_text(raw)
        metadata, body = _frontmatter(text)
        if metadata.get("name") != name:
            raise SkillSecurityError(f"Skill manifest name mismatch: {name}")
        if not metadata.get("description"):
            raise SkillSecurityError(f"Skill description is required: {name}")
        if not body:
            raise SkillSecurityError(f"Skill body is empty: {name}")
        _scan_instruction_text(name, text)
        self._validated_references(name, entry, skill_dir)
        return body

    def audit_registry(self) -> list[str]:
        registry = self._registry()
        approved = registry["skills"]
        if not self.root.exists():
            if approved:
                raise SkillSecurityError("Skill registry exists but skill root is missing")
            return []

        directory_names = {
            item.name
            for item in self.root.iterdir()
            if item.is_dir() and not item.name.startswith(".")
        }
        registered_names = set(approved)
        unregistered = sorted(directory_names - registered_names)
        if unregistered:
            raise SkillSecurityError("Unregistered skill directories detected: " + ", ".join(unregistered))

        audited: list[str] = []
        for name in sorted(registered_names):
            if not _SKILL_NAME_RE.fullmatch(name):
                raise SkillSecurityError(f"Invalid skill name: {name}")
            entry = approved[name]
            if not isinstance(entry, dict):
                raise SkillSecurityError(f"Invalid registry entry: {name}")
            if entry.get("enabled") is True:
                self._validate_skill(name, entry)
                audited.append(name)
        return audited

    def _approved_entry_for_agent(self, agent_id: str, name: str) -> dict:
        if not _SKILL_NAME_RE.fullmatch(name):
            raise SkillSecurityError(f"Invalid skill name: {name}")
        registry = self._registry()
        entry = registry["skills"].get(name)
        if not isinstance(entry, dict) or entry.get("enabled") is not True:
            raise SkillSecurityError(f"Skill is not approved/enabled: {name}")
        if agent_id not in entry.get("agent_ids", []):
            raise SkillSecurityError(f"Skill {name} is not approved for agent {agent_id}")
        self._validate_skill(name, entry)
        return entry

    def list_references_for_agent(self, agent_id: str, name: str) -> tuple[dict[str, object], ...]:
        """Return compact metadata for reviewed references attached to one skill."""

        entry = self._approved_entry_for_agent(agent_id, name)
        manifest = _reference_manifest(entry, name)
        return tuple(
            {
                "reference_id": reference_id,
                "path": meta["path"],
                "sha256": meta["sha256"],
                "size_bytes": meta["size_bytes"],
                "content_class": meta["content_class"],
                "provenance_count": len(meta["provenance"]),
                "vendor_family": meta.get("vendor_family"),
                "version": meta.get("version"),
            }
            for reference_id, meta in sorted(manifest.items())
        )

    def load_reference_for_agent(self, agent_id: str, name: str, reference_id: str) -> str:
        """Load one exact reviewed reference after revalidating the complete skill package."""

        if not _REFERENCE_ID_RE.fullmatch(str(reference_id or "")):
            raise SkillSecurityError(f"Invalid skill reference id: {name}/{reference_id}")
        entry = self._approved_entry_for_agent(agent_id, name)
        skill_dir = (self.root / name).resolve()
        references = self._validated_references(name, entry, skill_dir)
        text = references.get(reference_id)
        if text is None:
            raise SkillSecurityError(f"Skill reference is not approved: {name}/{reference_id}")
        return f"## Approved local skill reference: {name}/{reference_id}\n\n{text}"

    def load_for_agent(self, agent_id: str, names: Iterable[str]) -> list[str]:
        registry = self._registry()
        approved = registry["skills"]
        ordered_names = tuple(dict.fromkeys(names))
        if len(ordered_names) > MAX_SKILLS_PER_LOAD:
            raise SkillSecurityError(
                f"Skill load exceeds enterprise-lean limit of {MAX_SKILLS_PER_LOAD}: "
                + ", ".join(ordered_names)
            )

        blocks: list[str] = []
        loaded_bytes = 0

        for name in ordered_names:
            if not _SKILL_NAME_RE.fullmatch(name):
                raise SkillSecurityError(f"Invalid skill name: {name}")
            entry = approved.get(name)
            if not isinstance(entry, dict) or entry.get("enabled") is not True:
                raise SkillSecurityError(f"Skill is not approved/enabled: {name}")
            if agent_id not in entry.get("agent_ids", []):
                raise SkillSecurityError(f"Skill {name} is not approved for agent {agent_id}")

            body = self._validate_skill(name, entry)
            block = f"## Approved local skill: {name}\n\n{body}"
            loaded_bytes += len(block.encode("utf-8"))
            if loaded_bytes > MAX_LOADED_SKILL_BYTES:
                raise SkillSecurityError(
                    f"Loaded skill text exceeds enterprise-lean {MAX_LOADED_SKILL_BYTES}-byte prompt budget"
                )
            blocks.append(block)

        return blocks
