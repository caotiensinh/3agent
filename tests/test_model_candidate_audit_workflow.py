from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "model-candidate-audit-ci.yml"


def _text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_model_candidate_audit_trigger_remains_path_scoped() -> None:
    text = _text()
    trigger = text.split("on:\n", 1)[1].split("\npermissions:\n", 1)[0]

    assert "  pull_request:\n" in trigger
    assert "    paths:\n" in trigger
    assert "      - 'config/model-candidates/**'\n" in trigger
    assert "  workflow_dispatch:\n" in trigger
    assert "  push:\n" not in trigger


def test_runner_context_is_not_used_before_runner_assignment() -> None:
    text = _text()
    job_env = text.split("    env:\n", 1)[1].split("    steps:\n", 1)[0]

    assert "runner.temp" not in job_env
    assert "HF_HOME:" not in job_env
    assert "EVIDENCE_DIR:" not in job_env
    assert "Initialize ephemeral audit paths" in text
    assert '"$RUNNER_TEMP/workspace-hf-home" >> "$GITHUB_ENV"' in text
    assert '"$RUNNER_TEMP/workspace-model-evidence" >> "$GITHUB_ENV"' in text


def test_candidate_evidence_remains_ephemeral_and_review_only() -> None:
    text = _text()

    assert "permissions:\n  contents: read\n" in text
    assert "persist-credentials: false" in text
    assert "runtime_download'] is False" in text
    assert "approval']['approved'] is False" in text
    assert 'rm -rf "$EVIDENCE_DIR" "$HF_HOME"' in text
