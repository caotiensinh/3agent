import json
import os
import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.contracts import MonitoringContractError, SecretReference
from three_agent.security_monitoring.snmp_backend import FileSecretResolver, PySnmpV3Backend


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

    def test_resolver_loads_only_opaque_reference_from_locked_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._secret(root)
            credential = FileSecretResolver(root).resolve_snmpv3(SecretReference("secret-ref:device-1"))
            self.assertEqual(credential.username, "monitor")
            self.assertEqual(credential.auth_protocol, "sha256")
            self.assertEqual(credential.priv_protocol, "aes128")

    def test_world_readable_secret_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._secret(root, mode=0o644)
            with self.assertRaisesRegex(MonitoringContractError, "WORLD_ACCESS"):
                FileSecretResolver(root).resolve_snmpv3(SecretReference("secret-ref:device-1"))

    def test_symlink_secret_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = self._secret(root, name="real")
            link = root / "link.json"
            link.symlink_to(real)
            with self.assertRaisesRegex(MonitoringContractError, "SYMLINK"):
                FileSecretResolver(root).resolve_snmpv3(SecretReference("secret-ref:link"))

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

    def test_sha1_md5_des_credentials_are_rejected_by_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "weak.json"
            path.write_text(
                json.dumps(
                    {
                        "username": "monitor",
                        "auth_key": "authkey-1234",
                        "priv_key": "privkey-1234",
                        "auth_protocol": "sha1",
                        "priv_protocol": "des",
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(path, 0o640)
            with self.assertRaises(MonitoringContractError):
                FileSecretResolver(root).resolve_snmpv3(SecretReference("secret-ref:weak"))


if __name__ == "__main__":
    unittest.main()
