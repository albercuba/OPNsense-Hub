from __future__ import annotations

import asyncio
import io
import unittest
from uuid import UUID

import opnsense_hub_connector as connector_module
from opnsense_hub_connector import (
    ConnectorError,
    ConnectorServer,
    build_connector_url,
    build_parser,
    close_writer,
    parse_listen,
    read_connector_token,
    validate_listener_exposure,
)
from websockets.asyncio.server import serve

DEVICE_ID = UUID("01234567-89ab-cdef-0123-456789abcdef")


class TokenAndArgumentTests(unittest.TestCase):
    def test_build_connector_url_uses_wss_and_exact_device_path(self) -> None:
        self.assertEqual(
            build_connector_url("https://hub.example.com/", DEVICE_ID),
            "wss://hub.example.com/api/v1/connector/devices/"
            "01234567-89ab-cdef-0123-456789abcdef",
        )
        self.assertEqual(
            build_connector_url("wss://hub.example.com:8443", DEVICE_ID),
            "wss://hub.example.com:8443/api/v1/connector/devices/"
            "01234567-89ab-cdef-0123-456789abcdef",
        )

    def test_build_connector_url_rejects_insecure_or_sensitive_urls(self) -> None:
        invalid_urls = (
            "http://hub.example.com",
            "ws://hub.example.com",
            "https://user:secret@hub.example.com",
            "https://hub.example.com/prefix",
            "https://hub.example.com?token=secret",
            "https://hub.example.com#fragment",
        )
        for value in invalid_urls:
            with self.subTest(value=value), self.assertRaises(ConnectorError):
                build_connector_url(value, DEVICE_ID)

    def test_token_comes_from_environment_or_stdin_and_is_trimmed(self) -> None:
        self.assertEqual(
            read_connector_token(
                environ={"OPNSENSE_HUB_CONNECTOR_TOKEN": "  env-token\n"},
                stdin=io.StringIO("stdin-token\n"),
            ),
            "env-token",
        )
        self.assertEqual(
            read_connector_token(
                environ={},
                stdin=io.StringIO("stdin-token\n"),
            ),
            "stdin-token",
        )

    def test_empty_or_whitespace_token_is_rejected(self) -> None:
        for token in ("", "   \n", "two tokens\n"):
            with self.subTest(token=token), self.assertRaises(ConnectorError):
                read_connector_token(environ={}, stdin=io.StringIO(token))

    def test_cli_has_no_token_argument_and_defaults_to_loopback(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "--hub-url",
                "https://hub.example.com",
                "--device",
                str(DEVICE_ID),
            ]
        )
        self.assertEqual(args.listen, ("127.0.0.1", 8443))
        self.assertFalse(args.allow_non_loopback)
        self.assertNotIn("--token", parser.format_help())
        self.assertEqual(parse_listen("[::1]:9443"), ("::1", 9443))

    def test_non_loopback_listener_requires_explicit_override(self) -> None:
        validate_listener_exposure("127.0.0.1", False)
        validate_listener_exposure("0.0.0.0", True)
        with self.assertRaises(ConnectorError):
            validate_listener_exposure("0.0.0.0", False)


class ConnectorRelayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.authorization_headers: list[str | None] = []
        self.websocket_server = await serve(self._echo_websocket, "127.0.0.1", 0)
        sockets = self.websocket_server.sockets
        assert sockets
        websocket_port = int(sockets[0].getsockname()[1])
        self.connector = ConnectorServer(
            connector_url=f"ws://127.0.0.1:{websocket_port}/connector",
            token="test-connector-token",
            listen_host="127.0.0.1",
            listen_port=0,
            connect_timeout=1,
            idle_timeout=1,
        )
        await self.connector.start()

    async def asyncTearDown(self) -> None:
        await self.connector.stop()
        self.websocket_server.close()
        await self.websocket_server.wait_closed()

    async def _echo_websocket(self, websocket: object) -> None:
        request = websocket.request  # type: ignore[attr-defined]
        self.authorization_headers.append(request.headers.get("Authorization"))
        async for message in websocket:  # type: ignore[attr-defined]
            await websocket.send(message)  # type: ignore[attr-defined]

    async def test_each_tcp_connection_uses_bearer_auth_and_relays_binary(self) -> None:
        payloads = [b"\x00\x01opaque TLS bytes\xff", bytes(range(256)) * 300]
        for payload in payloads:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", self.connector.bound_port
            )
            writer.write(payload)
            await writer.drain()
            echoed = await asyncio.wait_for(
                reader.readexactly(len(payload)), timeout=2
            )
            self.assertEqual(echoed, payload)
            writer.close()
            await writer.wait_closed()

        for _ in range(50):
            if len(self.authorization_headers) == 2:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(
            self.authorization_headers,
            ["Bearer test-connector-token", "Bearer test-connector-token"],
        )

    async def test_idle_timeout_closes_local_connection(self) -> None:
        await self.connector.stop()
        self.connector = ConnectorServer(
            connector_url=self.connector.connector_url,
            token="test-connector-token",
            listen_host="127.0.0.1",
            listen_port=0,
            connect_timeout=1,
            idle_timeout=0.05,
        )
        await self.connector.start()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", self.connector.bound_port
        )
        self.assertEqual(await asyncio.wait_for(reader.read(1), timeout=1), b"")
        writer.close()
        await writer.wait_closed()

    async def test_writer_shutdown_is_bounded(self) -> None:
        class StuckWriter:
            def __init__(self) -> None:
                self.closed = False

            def close(self) -> None:
                self.closed = True

            async def wait_closed(self) -> None:
                await asyncio.Event().wait()

        writer = StuckWriter()
        original_timeout = connector_module.CLOSE_TIMEOUT
        connector_module.CLOSE_TIMEOUT = 0.01
        try:
            await asyncio.wait_for(close_writer(writer), timeout=0.2)  # type: ignore[arg-type]
        finally:
            connector_module.CLOSE_TIMEOUT = original_timeout
        self.assertTrue(writer.closed)


if __name__ == "__main__":
    unittest.main()
