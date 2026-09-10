from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "install_github_rtx5090_runner_remote.sh"


def _text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_remote_bootstrap_is_single_host_path_without_clone():
    text = _text()
    lowered = text.lower()

    assert "set -Eeuo pipefail" in text
    assert "set +x" in text
    assert "umask 077" in text
    assert 'REPO="caotiensinh/3agent"' in text
    assert 'BRANCH="main"' in text
    assert "/branches/${BRANCH}" in text
    assert "/contents/${SCRIPT_PATH}?ref=${source_sha}" in text
    assert "git clone" not in lowered
    assert "git checkout" not in lowered


def test_remote_bootstrap_pins_and_verifies_git_blob_before_sudo_execution():
    text = _text()

    assert "Pinned source SHA" in text
    assert "hashlib.sha1" in text
    assert "b'blob '" in text
    assert "Git blob verification failed" in text
    assert 'sudo bash "$tmp_script"' in text
    assert "--pull-model" in text


def test_remote_bootstrap_keeps_secret_input_on_terminal_boundary():
    text = _text()

    assert "/dev/tty" in text
    assert '</dev/tty' in text
    assert "GITHUB_RUNNER_TOKEN" not in text
    assert "--token" not in text


def test_remote_bootstrap_has_no_infrastructure_side_effects_of_its_own():
    lowered = _text().lower()

    assert "apt install" not in lowered
    assert "apt-get install" not in lowered
    assert "docker" not in lowered
    assert "nvidia-driver" not in lowered
    assert "systemctl" not in lowered
