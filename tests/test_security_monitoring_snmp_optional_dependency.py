import importlib.util
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SnmpOptionalDependencyTests(unittest.TestCase):
    def test_pysnmp_remains_optional_not_core_dependency(self):
        payload = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        core = tuple(str(item).lower() for item in payload["project"]["dependencies"])
        monitoring_extra = tuple(
            str(item).lower()
            for item in payload["project"]["optional-dependencies"]["monitoring-snmp"]
        )
        self.assertFalse(any(item.startswith("pysnmp") for item in core))
        self.assertTrue(any(item.startswith("pysnmp") for item in monitoring_extra))

    def test_supported_pysnmp_v3arch_symbols_when_extra_is_installed(self):
        if importlib.util.find_spec("pysnmp") is None:
            self.skipTest("monitoring-snmp optional extra is not installed in this lane")

        from pysnmp.hlapi.v3arch.asyncio import (
            SnmpEngine,
            UdpTransportTarget,
            UsmUserData,
            USM_AUTH_HMAC192_SHA256,
            USM_PRIV_CFB128_AES,
            walk_cmd,
        )

        self.assertTrue(callable(SnmpEngine))
        self.assertTrue(callable(UdpTransportTarget.create))
        self.assertTrue(callable(UsmUserData))
        self.assertIsNotNone(USM_AUTH_HMAC192_SHA256)
        self.assertIsNotNone(USM_PRIV_CFB128_AES)
        self.assertTrue(callable(walk_cmd))


if __name__ == "__main__":
    unittest.main()
