from pathlib import Path


INSTALLER = Path(__file__).resolve().parents[1] / "scripts" / "install_workspace_secure_boundary.sh"


def _installer_text() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def test_confidential_core_is_not_authorized_for_broker_unix_ipc() -> None:
    source = _installer_text()

    # The high-assurance boundary has three trust zones. Confidential Core may
    # use local Ollama, but only Public Research may reach the egress broker.
    assert "Deliberately do NOT add workspace-core to the egress IPC group." in source
    assert 'usermod -a -G "$IPC_GROUP" "$CORE_USER"' not in source
    assert 'CORE_UID="$(id -u "$CORE_USER")"' in source
    assert '--allow-uid ${PUBLIC_UID}' in source
    assert '--allow-uid ${CORE_UID}' not in source
    assert (
        "Confidential Core UID=${CORE_UID}: localhost Ollama only; "
        "no broker membership and no Internet/LAN egress."
    ) in source
