import unittest


class SnmpOptionalDependencyTests(unittest.TestCase):
    def test_ci_installs_supported_pysnmp_v3arch_symbols(self):
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
