from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Iterable


class SkillSecurityError(RuntimeError):
    pass


# Enterprise-lean hard limits. Skill text is procedure, not storage.
# If a procedure needs more than this, move stable reference material out of the
# always-loaded skill path or implement the rule deterministically in code.
MAX_SKILL_BYTES = 3072
MAX_SKILLS_PER_LOAD = 2
MAX_LOADED_SKILL_BYTES = 4096

_SKILL_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
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


def _canonical_instruction_text(raw: bytes) -> str:
    """Decode reviewed instruction text and normalize only newline encoding.

    Git may check out text as CRLF on Windows while a security review was
    recorded against LF content. Newline representation is transport metadata,
    not instruction authority, so the integrity digest is defined over UTF-8
    text with canonical LF line endings. All other bytes/content remain security
    significant.
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


class ApprovedSkillLoader:
    """Load only repository-local skills that passed the recorded security review.

    The loader deliberately supports instruction-only skills. Any skill that asks
    for direct network, credential, persistent self-modification, or vendored
    executable authority is outside this trust tier and is rejected.

    Skill disclosure is also resource-bounded: at most two compact skill bodies
    may enter one model profile. This keeps reviewed procedure useful without
    turning the context window into a policy/document store.
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
        unexpected = sorted(item.name for item in entries if item.name != "SKILL.md")
        if unexpected:
            raise SkillSecurityError(
                f"Reviewed instruction-only skill contains unreviewed resources: {name}: {', '.join(unexpected)}"
            )

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
