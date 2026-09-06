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


def migrate_payload(data: dict[str, Any]) -> tuple[dict[str, Any], bool, str]:
    if not _matches_old_generated_default(data):
        return data, False, "custom-or-already-migrated"

    migrated = json.loads(json.dumps(data))
    migrated["environment"] = "local"
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

    return migrated, True, "migrated-generated-default"


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


def migrate_file(path: Path) -> tuple[bool, str, Path | None]:
    if not path.is_file():
        return False, "config-missing", None

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("WorkSpace config root must be a JSON object")

    migrated, changed, reason = migrate_payload(data)
    if not changed:
        return False, reason, None

    backup = path.with_name(path.name + ".pre-public-research.bak")
    if not backup.exists():
        shutil.copy2(path, backup)
    _atomic_write_json(path, migrated)
    return True, reason, backup


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Migrate only the legacy bootstrap-generated WorkSpace development-test "
            "config to the secure local public-research policy. Custom configs are untouched."
        )
    )
    parser.add_argument("--config", required=True, help="Path to the active WorkSpace JSON config")
    args = parser.parse_args()

    config_path = Path(args.config).expanduser().resolve()
    changed, reason, backup = migrate_file(config_path)
    if changed:
        print(f"CONFIG_MIGRATION=changed reason={reason}")
        print(f"CONFIG_BACKUP={backup}")
        print("WEB_SEARCH_POLICY=public-research strict direct-egress")
    else:
        print(f"CONFIG_MIGRATION=unchanged reason={reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
