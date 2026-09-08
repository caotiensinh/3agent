from __future__ import annotations

import socket
import threading
import unittest
from types import SimpleNamespace

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.office_it_tools import probe_tcp


class RawPrinterFixedPortE2ETests(unittest.TestCase):
    """Prove the RAW printer probe actually executes against its fixed TCP/9100 contract."""

    @staticmethod
    def _authority() -> TaskCapabilityAuthority:
        return TaskCapabilityAuthority.from_model_authority(
            SimpleNamespace(
                task_id="pc-diagnostics-raw-printer-fixed-port-e2e",
                sensitivity="internal",
                allowed_sources=("user_prompt", "local_system"),
                allowed_tools=("network.printer.raw_probe",),
                write_scope="none",
                network_scope="internal_only",
            )
        )

    def test_raw_printer_probe_connects_to_loopback_tcp_9100(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 9100))
        listener.listen(1)
        accepted = threading.Event()

        def accept_once() -> None:
            try:
                conn, _ = listener.accept()
                accepted.set()
                conn.close()
            finally:
                listener.close()

        worker = threading.Thread(target=accept_once, daemon=True)
        worker.start()
        try:
            result = probe_tcp(
                "network.printer.raw_probe",
                "127.0.0.1",
                authority=self._authority(),
                timeout=1.0,
            )
            self.assertEqual(result["port"], 9100)
            self.assertTrue(result["connected"], result)
            self.assertTrue(accepted.wait(timeout=1.0))
        finally:
            if listener.fileno() != -1:
                listener.close()
            worker.join(timeout=1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
