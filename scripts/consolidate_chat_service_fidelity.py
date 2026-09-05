from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "three_agent"
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
    result = run([
        "git", "grep", "-lE",
        "chat_service_fidelity_v2|ContractAwareProjectChatService|OUTPUT_CONTRACT_POLICY_VERSION|current-request-output-contract",
        "--", "tests/*.py",
    ])
    return sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})


def consolidate() -> None:
    canonical = SRC / "chat_service_fidelity.py"
    variant = SRC / "chat_service_fidelity_v2.py"
    if canonical.exists():
        raise RuntimeError("canonical chat_service_fidelity.py already exists; semantic comparison required")
    canonical.write_text(variant.read_text(encoding="utf-8"), encoding="utf-8")


def rewrite_references() -> None:
    replacements = (
        ("three_agent.chat_service_fidelity_v2", "three_agent.chat_service_fidelity"),
        ("from .chat_service_fidelity_v2", "from .chat_service_fidelity"),
        ("import .chat_service_fidelity_v2", "import .chat_service_fidelity"),
    )
    variant = (SRC / "chat_service_fidelity_v2.py").resolve()
    excluded = {variant, Path(__file__).resolve()}
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
        for old, replacement in replacements:
            new = new.replace(old, replacement)
        if new != text:
            path.write_text(new, encoding="utf-8")


def smoke_test() -> None:
    sys.path.insert(0, str(ROOT / "src"))
    from three_agent.chat_service_fidelity import (
        OUTPUT_CONTRACT_POLICY_VERSION,
        ContractAwareProjectChatService,
    )

    assert OUTPUT_CONTRACT_POLICY_VERSION == "current-request-output-contract/v1"
    assert ContractAwareProjectChatService.__name__ == "ContractAwareProjectChatService"


def main() -> int:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    tests = targeted_tests()
    (ARTIFACTS / "chat_service_fidelity_tests.txt").write_text(
        "\n".join(tests) + ("\n" if tests else ""), encoding="utf-8"
    )

    baseline = run([sys.executable, "-m", "pytest", "-q", *tests]) if tests else None
    before = baseline.stdout if baseline else ""
    (ARTIFACTS / "chat_service_fidelity_pytest_before.txt").write_text(before, encoding="utf-8")
    baseline_failures = failure_keys(before)

    consolidate()
    rewrite_references()
    (SRC / "chat_service_fidelity_v2.py").unlink()

    stale = run([
        "git", "grep", "-nE",
        "three_agent\\.chat_service_fidelity_v2|from \\.chat_service_fidelity_v2|import \\.chat_service_fidelity_v2",
        "--", "src/three_agent", "tests", "pyproject.toml",
    ])
    if stale.returncode == 0 and stale.stdout.strip():
        print(stale.stdout)
        return 91

    run([sys.executable, "-m", "compileall", "-q", "src/three_agent", "tests"], check=True)
    smoke_test()

    final = run([sys.executable, "-m", "pytest", "-q", *tests]) if tests else None
    after = final.stdout if final else ""
    (ARTIFACTS / "chat_service_fidelity_pytest_after.txt").write_text(after, encoding="utf-8")
    final_failures = failure_keys(after)
    new_failures = sorted(final_failures - baseline_failures)
    removed_failures = sorted(baseline_failures - final_failures)

    payload = {
        "schema": "workspace-source-consolidation/chat-service-fidelity-v1",
        "family": ["src/three_agent/chat_service_fidelity.py"],
        "removed": ["src/three_agent/chat_service_fidelity_v2.py"],
        "baseline_returncode": baseline.returncode if baseline else 0,
        "final_returncode": final.returncode if final else 0,
        "baseline_failures": sorted(baseline_failures),
        "final_failures": sorted(final_failures),
        "new_failures": new_failures,
        "removed_failures": removed_failures,
        "remaining_variant_files": sorted(
            str(path.relative_to(ROOT)) for path in SRC.glob("chat_service_fidelity_v*.py")
        ),
    }
    (ARTIFACTS / "chat_service_fidelity_family.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    if payload["remaining_variant_files"]:
        return 92
    if new_failures:
        return 93
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
