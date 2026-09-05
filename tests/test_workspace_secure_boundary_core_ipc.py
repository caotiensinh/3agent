from pathlib import Path


INSTALLER = Path(__file__).resolve().parents[1] / "scripts" / "install_workspace_secure_boundary.sh"


def _installer_text() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def test_core_is_authorized_for_broker_unix_ipc() -> None:
    source = _installer_text()

    assert 'usermod -a -G "$IPC_GROUP" "$CORE_USER"' in source
    assert 'CORE_UID="$(id -u "$CORE_USER")"' in source
    assert '--allow-uid ${PUBLIC_UID} --allow-uid ${CORE_UID}' in source
    assert "Deliberately do NOT add workspace-core to the egress IPC group." not in source
