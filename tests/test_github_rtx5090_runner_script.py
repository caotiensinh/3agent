from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "setup_github_rtx5090_runner.sh"


def _text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_runner_bootstrap_is_fail_closed_and_token_safe():
    text = _text()

    assert "set -Eeuo pipefail" in text
    assert "set +x" in text
    assert "umask 077" in text
    assert "read -r -s -p \"Paste GitHub runner registration token" in text
    assert "cleanup_secret" in text
    assert "GITHUB_RUNNER_TOKEN" in text
    assert "echo \"$TOKEN\"" not in text
    assert "printf '%s\\n' \"$TOKEN\"" not in text
    assert "cat >" not in text.split("# ---------- Registration token ----------", 1)[1].split("# ---------- Persistent service ----------", 1)[0]


def test_runner_download_is_official_and_digest_verified():
    text = _text()

    assert "https://api.github.com/repos/actions/runner/releases/latest" in text
    assert "https://github.com/actions/runner/releases/download/" in text
    assert "digest" in text
    assert "sha256sum -c -" in text
    assert "--proto '=https'" in text
    assert "--tlsv1.2" in text


def test_runner_uses_dedicated_identity_and_runner_local_service_metadata():
    text = _text()

    assert 'RUNNER_USER="${WORKSPACE_RUNNER_USER:-github-runner}"' in text
    assert "useradd --create-home --shell /bin/bash" in text
    assert 'runuser -u "$RUNNER_USER"' in text
    assert '"$RUNNER_DIR/.service"' in text
    assert "systemctl enable" in text
    assert "systemctl restart" in text
    assert "needrestart/conf.d/actions_runner_services.conf" in text
    assert "systemctl list-unit-files" not in text


def test_runner_requires_real_rtx5090_and_local_ollama_without_installing_infrastructure():
    text = _text()

    assert "nvidia-smi --query-gpu=name" in text
    assert '"RTX 5090"' in text
    assert "http://127.0.0.1:11434/api/tags" in text
    assert "ollama pull" in text  # opt-in only via --pull-model
    assert "--pull-model" in text

    lowered = text.lower()
    assert "apt install" not in lowered
    assert "apt-get install" not in lowered
    assert "nvidia-driver" not in lowered
    assert "docker install" not in lowered
    assert "redis" not in lowered


def test_runner_is_idempotent_and_refuses_to_take_over_another_registration():
    text = _text()

    assert 'if [[ -f "$RUNNER_DIR/.runner" && -x "$RUNNER_DIR/run.sh" ]]' in text
    assert "Existing configured runner detected; preserving its registration." in text
    assert "Refusing to reconfigure it." in text
    assert "agentName" in text
    assert "gitHubUrl" in text


def test_runner_labels_match_benchmark_lane():
    text = _text()

    assert 'RUNNER_NAME="${WORKSPACE_RUNNER_NAME:-workspace-rtx5090-01}"' in text
    assert 'RUNNER_LABELS="${WORKSPACE_RUNNER_LABELS:-rtx5090,workspace-benchmark}"' in text
    assert "--unattended" in text
    assert "--replace" in text
    assert "--labels" in text
    assert "--work" in text
