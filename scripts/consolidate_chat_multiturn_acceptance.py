from __future__ import annotations

import json
import re
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
        "chat_multiturn_acceptance_v2|DiagnosticRecordingLLM|DiagnosticContractAwareProjectChatService|safe_runtime_failure_code",
        "--", "tests/*.py",
    ])
    return sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})


def consolidate() -> None:
    canonical_path = SRC / "chat_multiturn_acceptance.py"
    variant_path = SRC / "chat_multiturn_acceptance_v2.py"
    canonical = canonical_path.read_text(encoding="utf-8").rstrip()
    variant = variant_path.read_text(encoding="utf-8")
    variant = re.sub(r"^from __future__ import annotations\n\n", "", variant, count=1)
    # The V2 diagnostic layer intentionally references the base module namespace.
    # After flattening, bind that name to the current canonical module rather than
    # importing a physical version sibling or recursively importing ourselves.
    variant = variant.replace(
        "from . import chat_multiturn_acceptance as acceptance\n",
        "acceptance = sys.modules[__name__]\n",
        1,
    )
    variant = variant.replace(
        "from .chat_multiturn_acceptance import PromptEvidence\n",
        "",
        1,
    )
    canonical_path.write_text(
        canonical
        + "\n\n\n# Canonical metadata-only runtime diagnostics for multi-turn acceptance.\n"
        + variant.strip()
        + "\n",
        encoding="utf-8",
    )


def rewrite_references() -> None:
    replacements = (
        ("three_agent.chat_multiturn_acceptance_v2", "three_agent.chat_multiturn_acceptance"),
        ("from .chat_multiturn_acceptance_v2", "from .chat_multiturn_acceptance"),
        ("import .chat_multiturn_acceptance_v2", "import .chat_multiturn_acceptance"),
    )
    excluded = {
        (SRC / "chat_multiturn_acceptance_v2.py").resolve(),
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
        for old, replacement in replacements:
            new = new.replace(old, replacement)
        if new != text:
            path.write_text(new, encoding="utf-8")


def smoke_test() -> None:
    sys.path.insert(0, str(ROOT / "src"))
    from three_agent.chat_multiturn_acceptance import (
        DiagnosticContractAwareProjectChatService,
        DiagnosticRecordingLLM,
        RuntimePromptEvidence,
        safe_runtime_failure_code,
    )

    assert DiagnosticRecordingLLM.__name__ == "DiagnosticRecordingLLM"
    assert DiagnosticContractAwareProjectChatService.__name__ == "DiagnosticContractAwareProjectChatService"
    assert RuntimePromptEvidence.__name__ == "RuntimePromptEvidence"
    assert safe_runtime_failure_code(TimeoutError()) == "llm_transport_timeout"


def main() -> int:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    tests = targeted_tests()
    (ARTIFACTS / "chat_multiturn_acceptance_tests.txt").write_text(
        "\n".join(tests) + ("\n" if tests else ""), encoding="utf-8"
    )

    baseline = run([sys.executable, "-m", "pytest", "-q", *tests]) if tests else None
    before = baseline.stdout if baseline else ""
    (ARTIFACTS / "chat_multiturn_acceptance_pytest_before.txt").write_text(before, encoding="utf-8")
    baseline_failures = failure_keys(before)

    consolidate()
    rewrite_references()
    (SRC / "chat_multiturn_acceptance_v2.py").unlink()

    stale = run([
        "git", "grep", "-nE",
        "three_agent\\.chat_multiturn_acceptance_v2|from \\.chat_multiturn_acceptance_v2|import \\.chat_multiturn_acceptance_v2",
        "--", "src/three_agent", "tests", "pyproject.toml",
    ])
    if stale.returncode == 0 and stale.stdout.strip():
        print(stale.stdout)
        return 101

    run([sys.executable, "-m", "compileall", "-q", "src/three_agent", "tests"], check=True)
    smoke_test()

    final = run([sys.executable, "-m", "pytest", "-q", *tests]) if tests else None
    after = final.stdout if final else ""
    (ARTIFACTS / "chat_multiturn_acceptance_pytest_after.txt").write_text(after, encoding="utf-8")
    final_failures = failure_keys(after)
    new_failures = sorted(final_failures - baseline_failures)
    removed_failures = sorted(baseline_failures - final_failures)

    payload = {
        "schema": "workspace-source-consolidation/chat-multiturn-acceptance-v1",
        "family": ["src/three_agent/chat_multiturn_acceptance.py"],
        "removed": ["src/three_agent/chat_multiturn_acceptance_v2.py"],
        "baseline_returncode": baseline.returncode if baseline else 0,
        "final_returncode": final.returncode if final else 0,
        "baseline_failures": sorted(baseline_failures),
        "final_failures": sorted(final_failures),
        "new_failures": new_failures,
        "removed_failures": removed_failures,
        "remaining_variant_files": sorted(
            str(path.relative_to(ROOT)) for path in SRC.glob("chat_multiturn_acceptance_v*.py")
        ),
    }
    (ARTIFACTS / "chat_multiturn_acceptance_family.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    if payload["remaining_variant_files"]:
        return 102
    if new_failures:
        return 103
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
