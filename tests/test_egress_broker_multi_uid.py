import base64
import json
import struct
import unittest
from unittest.mock import Mock, patch

from three_agent.egress_broker import EgressBroker, build_parser


class _Connection:
    def __init__(self) -> None:
        self.sent = bytearray()

    def sendall(self, payload: bytes) -> None:
        self.sent.extend(payload)


class EgressBrokerMultiUidTests(unittest.TestCase):
    def _broker(self) -> EgressBroker:
        broker = object.__new__(EgressBroker)
        broker.allowed_uids = frozenset({1001, 1002})
        broker._dispatch = Mock(return_value=b"public-result")
        return broker

    def test_parser_accumulates_repeated_allow_uid_flags(self) -> None:
        args = build_parser().parse_args(
            [
                "--config",
                "config/workspace.public-research.json",
                "--allow-uid",
                "1001",
                "--allow-uid",
                "1002",
            ]
        )
        self.assertEqual(args.allow_uid, [1001, 1002])

    def test_any_explicitly_allowed_peer_uid_can_use_broker(self) -> None:
        request = json.dumps(
            {
                "agent_id": "research",
                "task_id": "TASK-IPC-1",
                "action": "search",
                "endpoint": "https://html.duckduckgo.com/html/",
                "params": {"q": "public documentation"},
            },
            separators=(",", ":"),
        ).encode("utf-8")
        connection = _Connection()
        broker = self._broker()

        with (
            patch("three_agent.egress_broker._peer_uid", return_value=1002),
            patch(
                "three_agent.egress_broker._recv_exact",
                side_effect=[struct.pack("!I", len(request)), request],
            ),
        ):
            broker._serve_connection(connection)

        response_size = struct.unpack("!I", connection.sent[:4])[0]
        response = json.loads(bytes(connection.sent[4 : 4 + response_size]).decode("utf-8"))
        self.assertTrue(response["ok"])
        self.assertEqual(base64.b64decode(response["body_b64"]), b"public-result")
        broker._dispatch.assert_called_once()

    def test_unlisted_peer_uid_is_rejected_before_payload_read(self) -> None:
        connection = _Connection()
        broker = self._broker()

        with (
            patch("three_agent.egress_broker._peer_uid", return_value=2000),
            patch("three_agent.egress_broker._recv_exact") as receive,
        ):
            with self.assertRaisesRegex(PermissionError, "peer UID rejected"):
                broker._serve_connection(connection)

        receive.assert_not_called()
        broker._dispatch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
