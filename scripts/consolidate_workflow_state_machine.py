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
        "workflow_state_machine_v4|WorkflowStateMachineV4Controller|BudgetedWorkflowStateMachineV4Controller|EXECUTION_PROFILE_V4",
        "--", "tests/*.py",
    ])
    return sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})


def _strip_future(text: str) -> str:
    return re.sub(r"^from __future__ import annotations\n\n", "", text, count=1)


def consolidate() -> None:
    canonical_path = SRC / "workflow_state_machine.py"
    v4_path = SRC / "workflow_state_machine_v4.py"
    budgeted_path = SRC / "workflow_state_machine_v4_budgeted.py"

    canonical = canonical_path.read_text(encoding="utf-8").rstrip()
    v4 = _strip_future(v4_path.read_text(encoding="utf-8"))
    budgeted = _strip_future(budgeted_path.read_text(encoding="utf-8"))

    v4 = re.sub(
        r"^from \.workflow_state_machine import \(\n.*?^\)\n\n",
        "",
        v4,
        flags=re.M | re.S,
    )
    budgeted = re.sub(
        r"^from \.workflow_state_machine import WorkflowStateError\n",
        "",
        budgeted,
        flags=re.M,
    )
    budgeted = re.sub(
        r"^from \.workflow_state_machine_v4 import WorkflowStateMachineV4Controller\n",
        "",
        budgeted,
        flags=re.M,
    )

    canonical_path.write_text(
        canonical
        + "\n\n\n# Canonical bounded-parallel Workflow V4 execution.\n"
        + v4.strip()
        + "\n\n\n# Canonical aggregate-budget enforcement for bounded parallel execution.\n"
        + budgeted.strip()
        + "\n",
        encoding="utf-8",
    )


def rewrite_references() -> None:
    # Rewrite only production-module import paths. Test-helper module names such as
    # `test_workflow_state_machine_v4` are not production topology and must remain.
    replacements = (
        ("three_agent.workflow_state_machine_v4_budgeted", "three_agent.workflow_state_machine"),
        ("three_agent.workflow_state_machine_v4", "three_agent.workflow_state_machine"),
        ("from .workflow_state_machine_v4_budgeted", "from .workflow_state_machine"),
        ("from .workflow_state_machine_v4", "from .workflow_state_machine"),
        ("import .workflow_state_machine_v4_budgeted", "import .workflow_state_machine"),
        ("import .workflow_state_machine_v4", "import .workflow_state_machine"),
    )
    excluded = {
        (SRC / "workflow_state_machine_v4.py").resolve(),
        (SRC / "workflow_state_machine_v4_budgeted.py").resolve(),
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
        for old, canonical in replacements:
            new = new.replace(old, canonical)
        if new != text:
            path.write_text(new, encoding="utf-8")


def smoke_test() -> None:
    sys.path.insert(0, str(ROOT / "src"))
    from three_agent.workflow_state_machine import (
        BudgetedWorkflowStateMachineV4Controller,
        EXECUTION_PROFILE_V4,
        WorkflowStateMachineController,
        WorkflowStateMachineV4Controller,
    )

    assert issubclass(WorkflowStateMachineV4Controller, WorkflowStateMachineController)
    assert issubclass(BudgetedWorkflowStateMachineV4Controller, WorkflowStateMachineV4Controller)
    assert EXECUTION_PROFILE_V4 == "workspace-bounded-parallel-dag/v1"


def main() -> int:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    tests = targeted_tests()
    (ARTIFACTS / "workflow_state_machine_tests.txt").write_text(
        "\n".join(tests) + ("\n" if tests else ""), encoding="utf-8"
    )

    baseline = run([sys.executable, "-m", "pytest", "-q", *tests]) if tests else None
    before = baseline.stdout if baseline else ""
    (ARTIFACTS / "workflow_state_machine_pytest_before.txt").write_text(before, encoding="utf-8")
    baseline_failures = failure_keys(before)

    consolidate()
    rewrite_references()
    (SRC / "workflow_state_machine_v4.py").unlink()
    (SRC / "workflow_state_machine_v4_budgeted.py").unlink()

    stale = run([
        "git", "grep", "-nE",
        "three_agent\\.workflow_state_machine_v4(_budgeted)?|from \\.workflow_state_machine_v4(_budgeted)?|import \\.workflow_state_machine_v4(_budgeted)?",
        "--", "src/three_agent", "tests", "pyproject.toml",
    ])
    if stale.returncode == 0 and stale.stdout.strip():
        print(stale.stdout)
        return 81

    run([sys.executable, "-m", "compileall", "-q", "src/three_agent", "tests"], check=True)
    smoke_test()

    final = run([sys.executable, "-m", "pytest", "-q", *tests]) if tests else None
    after = final.stdout if final else ""
    (ARTIFACTS / "workflow_state_machine_pytest_after.txt").write_text(after, encoding="utf-8")
    final_failures = failure_keys(after)
    new_failures = sorted(final_failures - baseline_failures)
    removed_failures = sorted(baseline_failures - final_failures)

    payload = {
        "schema": "workspace-source-consolidation/workflow-state-machine-v1",
        "family": ["src/three_agent/workflow_state_machine.py"],
        "removed": [
            "src/three_agent/workflow_state_machine_v4.py",
            "src/three_agent/workflow_state_machine_v4_budgeted.py",
        ],
        "baseline_returncode": baseline.returncode if baseline else 0,
        "final_returncode": final.returncode if final else 0,
        "baseline_failures": sorted(baseline_failures),
        "final_failures": sorted(final_failures),
        "new_failures": new_failures,
        "removed_failures": removed_failures,
        "remaining_variant_files": sorted(
            str(path.relative_to(ROOT)) for path in SRC.glob("workflow_state_machine_v*.py")
        ),
    }
    (ARTIFACTS / "workflow_state_machine_family.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    if payload["remaining_variant_files"]:
        return 82
    if new_failures:
        return 83
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
