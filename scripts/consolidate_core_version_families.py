from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import tempfile
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
    result = run(
        [
            "git",
            "grep",
            "-lE",
            "chat_context|chat_history|ConversationHistoryStore|ProjectConversationStore|ChatHistoryStore",
            "--",
            "tests/*.py",
        ]
    )
    return sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})


def strip_all_block(text: str) -> str:
    return re.sub(r"\n__all__\s*=\s*\[.*?\]\s*\Z", "\n", text, flags=re.S)


def consolidate_context() -> None:
    base = (SRC / "chat_context.py").read_text(encoding="utf-8")
    v2 = (SRC / "chat_context_v2.py").read_text(encoding="utf-8")
    v3 = (SRC / "chat_context_v3.py").read_text(encoding="utf-8")

    v2 = re.sub(r"^from __future__ import annotations\n\n", "", v2)
    v2 = re.sub(r"^from typing import Any, Sequence\n\n", "", v2)
    v2 = re.sub(
        r"^from \.chat_context import \(\n.*?^\)\n\n",
        "",
        v2,
        flags=re.M | re.S,
    )
    v2 = strip_all_block(v2)

    v3 = re.sub(r"^from __future__ import annotations\n\n", "", v3)
    v3 = re.sub(r"^from typing import Any, Iterable, Sequence\n\n", "", v3)
    v3 = re.sub(
        r"^from \.chat_context import \(\n.*?^\)\n",
        "",
        v3,
        flags=re.M | re.S,
    )
    v3 = re.sub(
        r"^from \.chat_context_v2 import classify_context_request\n\n",
        "",
        v3,
        flags=re.M,
    )

    combined = (
        base.rstrip()
        + "\n\n\n# Internal snapshots preserve the former base/v2 call chain after physical flattening.\n"
        + "_classify_legacy_context = classify_context_request\n"
        + "_build_legacy_context = build_conversation_context\n\n"
        + v2.strip()
        + "\n\n\n"
        + v3.strip()
        + "\n"
    )
    (SRC / "chat_context.py").write_text(combined, encoding="utf-8")


def consolidate_history() -> None:
    h1 = (SRC / "chat_history.py").read_text(encoding="utf-8")
    h2 = (SRC / "chat_history_v2.py").read_text(encoding="utf-8")
    h3 = (SRC / "chat_history_v3.py").read_text(encoding="utf-8")

    h2 = re.sub(r"^from __future__ import annotations\n\n", "", h2)
    h2 = re.sub(r"^from typing import Any\n\n", "", h2)
    h2 = re.sub(r"^from \.chat_history import ChatHistoryStore\n\n", "", h2)

    h3 = re.sub(r"^from __future__ import annotations\n\n", "", h3)
    h3 = re.sub(r"^import re\nimport uuid\nfrom typing import Any\n\n", "", h3)
    h3 = re.sub(
        r"^from \.chat_history_v2 import ConversationHistoryStore\n\n",
        "",
        h3,
        flags=re.M,
    )

    (SRC / "chat_history.py").write_text(
        h1.rstrip() + "\n\n\n" + h2.strip() + "\n\n\n" + h3.strip() + "\n",
        encoding="utf-8",
    )


def rewrite_references() -> None:
    replacements = {
        "chat_context_v2": "chat_context",
        "chat_context_v3": "chat_context",
        "chat_history_v2": "chat_history",
        "chat_history_v3": "chat_history",
    }
    allowed = {".py", ".toml", ".sh", ".ps1", ".yml", ".yaml"}
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    excluded = {
        SRC / "chat_context_v2.py",
        SRC / "chat_context_v3.py",
        SRC / "chat_history_v2.py",
        SRC / "chat_history_v3.py",
        Path(__file__).resolve(),
    }
    for name in raw.decode().split("\0"):
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
    for path in (
        SRC / "chat_context_v2.py",
        SRC / "chat_context_v3.py",
        SRC / "chat_history_v2.py",
        SRC / "chat_history_v3.py",
    ):
        path.unlink()


def smoke_test() -> None:
    sys.path.insert(0, str(ROOT / "src"))
    from three_agent.chat_context import (  # noqa: PLC0415
        CONTEXT_MODE_CONTINUITY,
        CONTEXT_MODE_FOLLOW_UP,
        build_conversation_context,
        classify_context_request,
    )
    from three_agent.chat_history import (  # noqa: PLC0415
        ChatHistoryStore,
        ConversationHistoryStore,
        ProjectConversationStore,
    )

    assert classify_context_request("tiếp theo ?")[0] == CONTEXT_MODE_FOLLOW_UP
    plan = build_conversation_context(
        [
            {
                "role": "user",
                "content": "Bước một kiểm tra địa chỉ IP",
                "status": "completed",
                "job_id": "j1",
            },
            {
                "role": "assistant",
                "content": "Đã kiểm tra xong.",
                "status": "completed",
                "job_id": "j2",
            },
        ],
        "bước tiếp theo là gì?",
    )
    assert plan.mode in {CONTEXT_MODE_FOLLOW_UP, CONTEXT_MODE_CONTINUITY}
    assert plan.message_count == 2

    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "chat.sqlite3"
        base = ChatHistoryStore(db)
        base.initialize()
        lifecycle = ConversationHistoryStore(db)
        lifecycle.initialize()
        projects = ProjectConversationStore(db)
        projects.initialize()
        cid = projects.create_conversation("owner-a", "Network review")
        projects.record_message(cid, role="user", content="check network", job_id="j1")
        project = projects.create_project("owner-a", "Ops")
        moved = projects.move_conversation("owner-a", cid, project["project_id"])
        assert moved["project_id"] == project["project_id"]


def main() -> int:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    tests = targeted_tests()
    (ARTIFACTS / "core_family_tests.txt").write_text(
        "\n".join(tests) + ("\n" if tests else ""), encoding="utf-8"
    )

    baseline = run([sys.executable, "-m", "pytest", "-q", *tests]) if tests else None
    baseline_output = baseline.stdout if baseline else ""
    (ARTIFACTS / "core_family_pytest_before.txt").write_text(
        baseline_output, encoding="utf-8"
    )
    baseline_failures = failure_keys(baseline_output)

    consolidate_context()
    consolidate_history()
    rewrite_references()
    remove_variants()

    stale = run(
        [
            "git",
            "grep",
            "-nE",
            "chat_context_v[23]|chat_history_v[23]",
            "--",
            "src",
            "tests",
            "pyproject.toml",
        ]
    )
    if stale.returncode == 0 and stale.stdout.strip():
        print(stale.stdout)
        raise SystemExit("stale version-family reference remains")

    run([sys.executable, "-m", "compileall", "-q", "src/three_agent", "tests"], check=True)
    smoke_test()

    final = run([sys.executable, "-m", "pytest", "-q", *tests]) if tests else None
    final_output = final.stdout if final else ""
    (ARTIFACTS / "core_family_pytest_after.txt").write_text(
        final_output, encoding="utf-8"
    )
    final_failures = failure_keys(final_output)
    new_failures = sorted(final_failures - baseline_failures)
    removed_failures = sorted(baseline_failures - final_failures)

    payload = {
        "schema": "workspace-source-consolidation/v2",
        "families": {
            "chat_context": ["src/three_agent/chat_context.py"],
            "chat_history": ["src/three_agent/chat_history.py"],
        },
        "removed": [
            "src/three_agent/chat_context_v2.py",
            "src/three_agent/chat_context_v3.py",
            "src/three_agent/chat_history_v2.py",
            "src/three_agent/chat_history_v3.py",
        ],
        "baseline_returncode": baseline.returncode if baseline else 0,
        "final_returncode": final.returncode if final else 0,
        "baseline_failures": sorted(baseline_failures),
        "final_failures": sorted(final_failures),
        "new_failures": new_failures,
        "removed_failures": removed_failures,
        "remaining_core_variant_files": sorted(
            str(path.relative_to(ROOT)) for path in SRC.glob("chat_context_v*.py")
        )
        + sorted(str(path.relative_to(ROOT)) for path in SRC.glob("chat_history_v*.py")),
    }
    (ARTIFACTS / "core_families.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(payload, indent=2, ensure_ascii=False))

    if payload["remaining_core_variant_files"]:
        return 62
    if new_failures:
        return 63
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
