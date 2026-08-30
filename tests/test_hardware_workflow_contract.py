from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = {
    "benchmark": ROOT / ".github" / "workflows" / "benchmark-context-packing.yml",
    "efficiency": ROOT / ".github" / "workflows" / "evaluate-efficiency-concurrency.yml",
}


def _job_env_prefix(text: str) -> str:
    """Return workflow text before the first steps block.

    Runner context is not available while GitHub validates job-level env. Keeping
    this check textual avoids adding a YAML dependency just to protect the Actions
    contract.
    """

    marker = "    steps:\n"
    assert marker in text
    return text.split(marker, 1)[0]


def test_hardware_workflows_are_manual_and_exact_runner_scoped():
    benchmark = WORKFLOWS["benchmark"].read_text(encoding="utf-8")
    efficiency = WORKFLOWS["efficiency"].read_text(encoding="utf-8")

    for text in (benchmark, efficiency):
        assert "  workflow_dispatch:" in text
        assert "runs-on: [self-hosted, Linux, X64, rtx5090]" in text
        assert "\n  push:" not in text
        assert "\n  pull_request:" not in text
        assert "ollama pull" not in text.lower()
        assert "nvidia-driver" not in text.lower()
        assert "apt install" not in text.lower()
        assert "${{ runner.temp }}" not in _job_env_prefix(text)
        assert "$RUNNER_TEMP/" in text

    assert "inputs.confirm == 'BENCHMARK'" in benchmark
    assert "inputs.confirm == 'EVALUATE'" in efficiency


def test_hardware_workflow_outputs_remain_metadata_only_contracts():
    benchmark = WORKFLOWS["benchmark"].read_text(encoding="utf-8")
    efficiency = WORKFLOWS["efficiency"].read_text(encoding="utf-8")

    assert "environment.json" in benchmark
    assert "verification.json" in benchmark
    assert "suite.json" in benchmark
    assert "workspace-benchmark-verify" in benchmark

    assert "environment.json" in efficiency
    assert "observation.json" in efficiency
    assert "workspace-eval-efficiency-observe" in efficiency


def test_context_benchmark_candidate_preserves_authorization_and_read_only_boundary():
    benchmark = WORKFLOWS["benchmark"].read_text(encoding="utf-8")

    assert "permissions:\n  contents: read\n" in benchmark
    assert "      exact_body_dedupe:\n" in benchmark
    assert "        type: choice\n" in benchmark
    assert "        default: 'false'\n" in benchmark
    assert "          - 'false'\n          - 'true'\n" in benchmark
    assert (
        "      WORKSPACE_EVIDENCE_EXACT_BODY_DEDUPE: "
        "${{ inputs.exact_body_dedupe }}\n"
    ) in benchmark
    assert (
        "name: context-packing-benchmark-${{ inputs.source_ref }}-dedupe-"
        "${{ inputs.exact_body_dedupe }}"
    ) in benchmark
