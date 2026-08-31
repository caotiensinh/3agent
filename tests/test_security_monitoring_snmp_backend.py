import json
import os
import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.contracts import MonitoringContractError, SecretReference
from three_agent.security_monitoring.snmp_backend import (
    FileSecretResolver,
    PySnmpV3Backend,
    SnmpV3Credential,
)

POSIX = os.name == "posix"


class SnmpBackendTests(unittest.TestCase):
    def _secret(self, root: Path, name="device-1", *, mode=0o640):
        path = root / f"{name}.json"
        path.write_text(
            json.dumps(
                {
                    "username": "monitor",
                    "auth_key": "authkey-1234",
                    "priv_key": "privkey-1234",
                    "auth_protocol": "sha256",
                    "priv_protocol": "aes128",
                }
            ),
            encoding="utf-8",
        )
        os.chmod(path, mode)
        return path

    @unittest.skipUnless(POSIX, "file-secret success path requires authoritative POSIX mode bits")
    def test_resolver_loads_only_opaque_reference_from_locked_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._secret(root)
            credential = FileSecretResolver(root).resolve_snmpv3(SecretReference("secret-ref:device-1"))
            self.assertEqual(credential.username, "monitor")
            self.assertEqual(credential.auth_protocol, "sha256")
            self.assertEqual(credential.priv_protocol, "aes128")

    @unittest.skipUnless(POSIX, "POSIX permission denial is validated on POSIX lanes")
    def test_world_readable_secret_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._secret(root, mode=0o644)
            with self.assertRaisesRegex(MonitoringContractError, "WORLD_ACCESS"):
                FileSecretResolver(root).resolve_snmpv3(SecretReference("secret-ref:device-1"))

    @unittest.skipUnless(POSIX, "POSIX file-secret path validation is exercised on POSIX lanes")
    def test_symlink_secret_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = self._secret(root, name="real")
            link = root / "link.json"
            link.symlink_to(real)
            with self.assertRaisesRegex(MonitoringContractError, "SYMLINK"):
                FileSecretResolver(root).resolve_snmpv3(SecretReference("secret-ref:link"))

    @unittest.skipUnless(POSIX, "file-secret backend is production-supported on POSIX in ver.0.0.1")
    def test_backend_never_passes_secret_reference_string_to_query_driver(self):
        captured = {}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._secret(root)

            def query(**kwargs):
                captured.update(kwargs)
                return [{"interface": "eth0", "rx_bytes": 1, "tx_bytes": 2, "speed_bps": 1000}]

            backend = PySnmpV3Backend(FileSecretResolver(root), query=query, max_rows=8, max_calls=4)
            rows = backend.read_interface_counters(
                target_host="192.0.2.10",
                credential_ref=SecretReference("secret-ref:device-1"),
                timeout_seconds=2,
            )
            self.assertEqual(rows[0]["interface"], "eth0")
            self.assertEqual(captured["target_host"], "192.0.2.10")
            self.assertNotIn("credential_ref", captured)
            self.assertNotIn("secret-ref:device-1", repr(captured))
            self.assertEqual(captured["credential"].username, "monitor")
            self.assertEqual(captured["max_rows"], 8)
            self.assertEqual(captured["max_calls"], 4)

    @unittest.skipIf(POSIX, "non-POSIX fail-closed behavior is exercised on Windows lanes")
    def test_file_secret_backend_fails_closed_without_posix_permission_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._secret(root)
            with self.assertRaisesRegex(MonitoringContractError, "REQUIRES_POSIX_PERMISSIONS"):
                FileSecretResolver(root).resolve_snmpv3(SecretReference("secret-ref:device-1"))

    def test_sha1_md5_des_credentials_are_rejected_by_policy(self):
        for auth_protocol, priv_protocol in (("sha1", "aes128"), ("md5", "aes128"), ("sha256", "des")):
            with self.subTest(auth_protocol=auth_protocol, priv_protocol=priv_protocol):
                with self.assertRaises(MonitoringContractError):
                    SnmpV3Credential(
                        username="monitor",
                        auth_key="authkey-1234",
                        priv_key="privkey-1234",
                        auth_protocol=auth_protocol,
                        priv_protocol=priv_protocol,
                    ).validate()


if __name__ == "__main__":
    unittest.main()
