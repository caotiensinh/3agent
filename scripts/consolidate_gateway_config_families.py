from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "three_agent"
SECURITY = SRC / "security_monitoring"
ARTIFACTS = ROOT / "artifacts" / "consolidation"


def run(command: list[str], *, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
    )


def failure_keys(output: str) -> set[str]:
    keys: set[str] = set()
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(("FAILED ", "ERROR ")):
            keys.add(stripped.split(" - ", 1)[0])
    return keys


def targeted_tests() -> list[str]:
    result = run(
        [
            "git",
            "grep",
            "-lE",
            "knowledge_gateway|KnowledgeGatewayV2|ui_config_v2|SecurityMonitoringUIConfigManager",
            "--",
            "tests/*.py",
        ]
    )
    return sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})


def consolidate_knowledge_gateway() -> None:
    canonical_path = SRC / "knowledge_gateway.py"
    variant_path = SRC / "knowledge_gateway_v2.py"
    canonical = canonical_path.read_text(encoding="utf-8").rstrip()
    variant = variant_path.read_text(encoding="utf-8")
    marker = "EXTENDED_UPLOAD_EXTENSIONS ="
    if marker not in variant:
        raise RuntimeError("knowledge_gateway_v2 body marker missing")
    body = marker + variant.split(marker, 1)[1]
    addition = (
        "\n\n\n# Extended business-document ingestion and bounded attachment retrieval.\n"
        "from .document_extractors import (\n"
        "    DOCUMENT_EXTENSIONS,\n"
        "    DocumentExtractionError,\n"
        "    extract_document,\n"
        ")\n\n"
        + body.strip()
        + "\n"
    )
    canonical_path.write_text(canonical + addition, encoding="utf-8")


def consolidate_ui_config() -> None:
    canonical_path = SECURITY / "ui_config.py"
    variant_path = SECURITY / "ui_config_v2.py"
    canonical = canonical_path.read_text(encoding="utf-8").rstrip()
    variant = variant_path.read_text(encoding="utf-8")
    marker = "REAL_NETWORK_CONFIRMATION ="
    if marker not in variant:
        raise RuntimeError("ui_config_v2 body marker missing")
    body = marker + variant.split(marker, 1)[1]
    addition = (
        "\n\n\n# Hardened confirmation, audit, and rollback layer for the canonical UI config boundary.\n"
        "import hashlib\n"
        "from datetime import datetime, timezone\n\n"
        + body.strip()
        + "\n"
    )
    canonical_path.write_text(canonical + addition, encoding="utf-8")


def rewrite_references() -> None:
    replacements = {
        "knowledge_gateway_v2": "knowledge_gateway",
        "ui_config_v2": "ui_config",
    }
    excluded = {
        (SRC / "knowledge_gateway_v2.py").resolve(),
        (SECURITY / "ui_config_v2.py").resolve(),
        Path(__file__).resolve(),
    }
    allowed = {".py", ".toml", ".sh", ".ps1", ".yml", ".yaml"}
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    for name in tracked:
        if not name:
            continue
        path = (ROOT / name).resolve()
        if path in excluded:
            continue
        if path.suffix.lower() not in allowed and path.name != "pyproject.toml":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        new = text
        for old, canonical in replacements.items():
            new = new.replace(old, canonical)
        if new != text:
            path.write_text(new, encoding="utf-8")


def remove_variants() -> None:
    (SRC / "knowledge_gateway_v2.py").unlink()
    (SECURITY / "ui_config_v2.py").unlink()


def smoke_test() -> None:
    sys.path.insert(0, str(ROOT / "src"))
    from three_agent.document_extractors import DOCUMENT_EXTENSIONS  # noqa: PLC0415
    from three_agent.knowledge_gateway import (  # noqa: PLC0415
        EXTENDED_UPLOAD_EXTENSIONS,
        KnowledgeGateway,
        KnowledgeGatewayV2,
    )
    from three_agent.security_monitoring.ui_config import (  # noqa: PLC0415
        REAL_NETWORK_CONFIRMATION,
        SecurityMonitoringUIConfigManager,
        SecurityMonitoringUIConfigManagerV2,
        safe_default_payload,
    )

    assert issubclass(KnowledgeGatewayV2, KnowledgeGateway)
    assert DOCUMENT_EXTENSIONS <= EXTENDED_UPLOAD_EXTENSIONS
    assert issubclass(SecurityMonitoringUIConfigManagerV2, SecurityMonitoringUIConfigManager)
    assert REAL_NETWORK_CONFIRMATION == "ENABLE_APPROVED_REAL_NETWORK_MONITORING"

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        gateway = KnowledgeGatewayV2(root, object())
        upload = gateway.ingest_upload("note.txt", b"bounded local document")
        assert upload.document_count == 1

        config_path = (root / "monitoring.json").resolve()
        manager = SecurityMonitoringUIConfigManagerV2(config_path, path_source="test")
        before = manager.get()
        assert before["authority"]["strong_confirmation_required"] is True
        result = manager.save(
            safe_default_payload(config_path),
            actor_id="consolidation-smoke-test",
        )
        assert result["audit_recorded"] is True
        assert result["save_executes_network"] is False


def main() -> int:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    tests = targeted_tests()
    (ARTIFACTS / "gateway_config_tests.txt").write_text(
        "\n".join(tests) + ("\n" if tests else ""), encoding="utf-8"
    )

    baseline = run([sys.executable, "-m", "pytest", "-q", *tests]) if tests else None
    before = baseline.stdout if baseline else ""
    (ARTIFACTS / "gateway_config_pytest_before.txt").write_text(before, encoding="utf-8")
    baseline_failures = failure_keys(before)

    consolidate_knowledge_gateway()
    consolidate_ui_config()
    rewrite_references()
    remove_variants()

    stale = run(
        [
            "git",
            "grep",
            "-nE",
            "knowledge_gateway_v2|ui_config_v2",
            "--",
            "src/three_agent",
            "tests",
            "pyproject.toml",
        ]
    )
    if stale.returncode == 0 and stale.stdout.strip():
        print(stale.stdout)
        return 71

    run([sys.executable, "-m", "compileall", "-q", "src/three_agent", "tests"], check=True)
    smoke_test()

    final = run([sys.executable, "-m", "pytest", "-q", *tests]) if tests else None
    after = final.stdout if final else ""
    (ARTIFACTS / "gateway_config_pytest_after.txt").write_text(after, encoding="utf-8")
    final_failures = failure_keys(after)
    new_failures = sorted(final_failures - baseline_failures)
    removed_failures = sorted(baseline_failures - final_failures)

    payload = {
        "schema": "workspace-source-consolidation/v2",
        "families": {
            "knowledge_gateway": ["src/three_agent/knowledge_gateway.py"],
            "security_monitoring/ui_config": ["src/three_agent/security_monitoring/ui_config.py"],
        },
        "removed": [
            "src/three_agent/knowledge_gateway_v2.py",
            "src/three_agent/security_monitoring/ui_config_v2.py",
        ],
        "baseline_returncode": baseline.returncode if baseline else 0,
        "final_returncode": final.returncode if final else 0,
        "baseline_failures": sorted(baseline_failures),
        "final_failures": sorted(final_failures),
        "new_failures": new_failures,
        "removed_failures": removed_failures,
        "remaining_variant_files": [
            str(path.relative_to(ROOT))
            for path in (SRC / "knowledge_gateway_v2.py", SECURITY / "ui_config_v2.py")
            if path.exists()
        ],
    }
    (ARTIFACTS / "gateway_config_families.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    if payload["remaining_variant_files"]:
        return 72
    if new_failures:
        return 73
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
