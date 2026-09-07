from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

OLD_DEFAULT_FINGERPRINT = {
    "product_name": "WorkSpace",
    "environment": "test",
    "confidentiality_mode": "development-test",
    "test_mode_full_access": True,
    "internet_enabled": True,
    "internet_mode": "legacy_test",
    "public_search_enabled": False,
    "allow_all_outbound_in_test": True,
    "execution_enabled": True,
    "allow_all_commands_in_test": True,
}

CANONICAL_SEARCH_HOSTS = [
    "html.duckduckgo.com",
    "lite.duckduckgo.com",
    "www.bing.com",
]


def _matches_old_generated_default(data: dict[str, Any]) -> bool:
    internet = data.get("internet_gateway")
    execution = data.get("execution_gateway")
    if not isinstance(internet, dict) or not isinstance(execution, dict):
        return False
    return (
        data.get("product_name") == OLD_DEFAULT_FINGERPRINT["product_name"]
        and data.get("environment") == OLD_DEFAULT_FINGERPRINT["environment"]
        and str(data.get("confidentiality_mode", "")).strip().lower()
        == OLD_DEFAULT_FINGERPRINT["confidentiality_mode"]
        and data.get("test_mode_full_access") is OLD_DEFAULT_FINGERPRINT["test_mode_full_access"]
        and internet.get("enabled") is OLD_DEFAULT_FINGERPRINT["internet_enabled"]
        and str(internet.get("mode", "")).strip().lower()
        == OLD_DEFAULT_FINGERPRINT["internet_mode"]
        and internet.get("public_search_enabled")
        is OLD_DEFAULT_FINGERPRINT["public_search_enabled"]
        and internet.get("allow_all_outbound_in_test")
        is OLD_DEFAULT_FINGERPRINT["allow_all_outbound_in_test"]
        and execution.get("enabled") is OLD_DEFAULT_FINGERPRINT["execution_enabled"]
        and execution.get("allow_all_commands_in_test")
        is OLD_DEFAULT_FINGERPRINT["allow_all_commands_in_test"]
    )


def _adaptive_learning_enabled(data: dict[str, Any]) -> bool:
    adaptive = data.get("adaptive_learning")
    return isinstance(adaptive, dict) and adaptive.get("enabled") is True


def _matches_secure_public_research(data: dict[str, Any]) -> bool:
    internet = data.get("internet_gateway")
    execution = data.get("execution_gateway")
    if not isinstance(internet, dict) or not isinstance(execution, dict):
        return False
    return (
        data.get("product_name") == OLD_DEFAULT_FINGERPRINT["product_name"]
        and data.get("environment") == "public-research-zone"
        and str(data.get("confidentiality_mode", "")).strip().lower() == "public-research"
        and data.get("test_mode_full_access") is False
        and internet.get("enabled") is True
        and str(internet.get("mode", "")).strip().lower() == "strict"
        and internet.get("public_search_enabled") is True
        and internet.get("allow_all_outbound_in_test") is False
        and internet.get("allowed_search_hosts") == CANONICAL_SEARCH_HOSTS
        and internet.get("allowed_content_hosts") == []
        and internet.get("max_response_bytes") == 4 * 1024 * 1024
        and internet.get("max_query_chars") == 240
        and internet.get("grant_ttl_seconds") == 120
        and internet.get("direct_egress") is True
        and execution.get("enabled") is True
        and execution.get("allow_all_commands_in_test") is False
    )


def _apply_secure_web_search(
    data: dict[str, Any], *, adaptive_compatible: bool
) -> dict[str, Any]:
    migrated = json.loads(json.dumps(data))
    if adaptive_compatible:
        # Preserve the provenance-backed environment label and use the supported
        # public mode. The dedicated public-research isolation zone intentionally
        # forbids mounting adaptive-learning state.
        migrated["environment"] = data["environment"]
        migrated["confidentiality_mode"] = "public"
    else:
        migrated["environment"] = "public-research-zone"
        migrated["confidentiality_mode"] = "public-research"
    migrated["test_mode_full_access"] = False

    internet = migrated.setdefault("internet_gateway", {})
    internet.update(
        {
            "enabled": True,
            "mode": "strict",
            "public_search_enabled": True,
            "allow_all_outbound_in_test": False,
            "allowed_search_hosts": list(CANONICAL_SEARCH_HOSTS),
            "allowed_content_hosts": [],
            "max_response_bytes": 4 * 1024 * 1024,
            "max_query_chars": 240,
            "grant_ttl_seconds": 120,
            "direct_egress": True,
            "audit_log": str(internet.get("audit_log") or "data/activity/internet.jsonl"),
        }
    )

    execution = migrated.setdefault("execution_gateway", {})
    execution["enabled"] = True
    execution["allow_all_commands_in_test"] = False
    execution["audit_log"] = str(
        execution.get("audit_log") or "data/activity/execution.jsonl"
    )
    return migrated


def migrate_payload(data: dict[str, Any]) -> tuple[dict[str, Any], bool, str]:
    if not _matches_old_generated_default(data):
        return data, False, "custom-or-already-migrated"

    adaptive_compatible = _adaptive_learning_enabled(data)
    migrated = _apply_secure_web_search(
        data, adaptive_compatible=adaptive_compatible
    )
    reason = (
        "migrated-generated-default-adaptive-compatible"
        if adaptive_compatible
        else "migrated-generated-default"
    )
    return migrated, True, reason


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_json_object(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _repair_prior_adaptive_migration(
    data: dict[str, Any], backup: Path
) -> tuple[dict[str, Any], bool, str]:
    if not (_adaptive_learning_enabled(data) and _matches_secure_public_research(data)):
        return data, False, "not-prior-adaptive-migration"

    original = _read_json_object(backup)
    if original is None or not _matches_old_generated_default(original):
        return data, False, "adaptive-repair-provenance-missing"
    if not _adaptive_learning_enabled(original):
        return data, False, "adaptive-repair-provenance-missing"
    if data.get("adaptive_learning") != original.get("adaptive_learning"):
        return data, False, "adaptive-repair-provenance-mismatch"

    repaired = json.loads(json.dumps(data))
    repaired["environment"] = original["environment"]
    repaired["confidentiality_mode"] = "public"
    return repaired, True, "repaired-adaptive-public-research-conflict"


def migrate_file(path: Path) -> tuple[bool, str, Path | None]:
    if not path.is_file():
        return False, "config-missing", None

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("WorkSpace config root must be a JSON object")

    provenance_backup = path.with_name(path.name + ".pre-public-research.bak")
    repaired, repaired_changed, repaired_reason = _repair_prior_adaptive_migration(
        data, provenance_backup
    )
    if repaired_changed:
        repair_backup = path.with_name(path.name + ".pre-adaptive-public-repair.bak")
        if not repair_backup.exists():
            shutil.copy2(path, repair_backup)
        _atomic_write_json(path, repaired)
        return True, repaired_reason, repair_backup
    if repaired_reason.startswith("adaptive-repair-provenance-"):
        return False, repaired_reason, None

    migrated, changed, reason = migrate_payload(data)
    if not changed:
        return False, reason, None

    if not provenance_backup.exists():
        shutil.copy2(path, provenance_backup)
    _atomic_write_json(path, migrated)
    return True, reason, provenance_backup


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Migrate only the legacy bootstrap-generated WorkSpace development-test "
            "config to secure public Web Search policy. Adaptive-learning configs "
            "remain outside the dedicated public-research isolation zone."
        )
    )
    parser.add_argument("--config", required=True, help="Path to the active WorkSpace JSON config")
    args = parser.parse_args()

    config_path = Path(args.config).expanduser().resolve()
    changed, reason, backup = migrate_file(config_path)
    if changed:
        print(f"CONFIG_MIGRATION=changed reason={reason}")
        print(f"CONFIG_BACKUP={backup}")
        if reason in {
            "migrated-generated-default-adaptive-compatible",
            "repaired-adaptive-public-research-conflict",
        }:
            print("WEB_SEARCH_POLICY=public strict direct-egress adaptive-compatible")
        else:
            print("WEB_SEARCH_POLICY=public-research strict direct-egress")
    else:
        print(f"CONFIG_MIGRATION=unchanged reason={reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
