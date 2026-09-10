from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/live-chat-multiturn-acceptance.yml"


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _push_block(text: str) -> str:
    try:
        return text.split("  push:\n", 1)[1].split("\npermissions:\n", 1)[0]
    except IndexError as exc:
        raise AssertionError("live multi-turn workflow push block is missing") from exc


def test_live_multiturn_tracks_llm_dependency() -> None:
    push_block = _push_block(_workflow_text())
    assert "- 'src/three_agent/llm.py'" in push_block


def test_live_multiturn_keeps_trusted_gpu_runner_contract() -> None:
    text = _workflow_text()
    assert "runs-on: [self-hosted, Linux, X64, r9, rtx5090]" in text
    assert "grep -c 'RTX 5090'" in text
    assert "--live" in text
    assert "--source-sha \"$GITHUB_SHA\"" in text
