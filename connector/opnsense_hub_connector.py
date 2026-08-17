#!/usr/bin/env python3
"""Expose an OPNsense Hub device connector as a local TCP listener."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import ipaddress
import os
import signal
import sys
import uuid
from collections.abc import Callable, Mapping
from typing import TextIO
from urllib.parse import SplitResult, urlsplit, urlunsplit

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidHandshake

TOKEN_ENV_VAR = "OPNSENSE_HUB_CONNECTOR_TOKEN"
DEFAULT_LISTEN = "127.0.0.1:8443"
DEFAULT_CONNECT_TIMEOUT = 15.0
DEFAULT_IDLE_TIMEOUT = 300.0
PING_INTERVAL = 20.0
PING_TIMEOUT = 20.0
CLOSE_TIMEOUT = 10.0
CHUNK_SIZE = 64 * 1024


class ConnectorError(Exception):
    """Base class for expected connector failures."""


class RelayIdleTimeout(ConnectorError):
    """Raised when a relayed connection has no payload activity."""


class RelayProtocolError(ConnectorError):
    """Raised when the Hub sends an unsupported WebSocket message."""


def parse_device(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("device must be a valid UUID") from exc


def positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return timeout


def parse_listen(value: str) -> tuple[str, int]:
    parsed = urlsplit(f"//{value.strip()}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise argparse.ArgumentTypeError("listen port must be between 1 and 65535") from exc

    if (
        not parsed.hostname
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or not 1 <= port <= 65_535
    ):
        raise argparse.ArgumentTypeError(
            "listen must be HOST:PORT, for example 127.0.0.1:8443"
        )
    return parsed.hostname, port


def normalize_browser_host(value: str) -> str:
    candidate = value.strip()
    if not candidate or any(character.isspace() for character in candidate):
        raise argparse.ArgumentTypeError("browser host must be a hostname or IP address")

    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]

    if any(character in candidate for character in "/?#@"):
        raise argparse.ArgumentTypeError(
            "browser host must not include a scheme, path, port, query, or credentials"
        )

    if ":" in candidate:
        try:
            ipaddress.IPv6Address(candidate)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                "browser host must not include a port"
            ) from exc

    return candidate


def build_connector_url(hub_url: str, device_id: uuid.UUID) -> str:
    parsed = urlsplit(hub_url.strip())
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ConnectorError("Hub URL contains an invalid port") from exc

    if parsed.scheme.lower() not in {"https", "wss"}:
        raise ConnectorError("Hub URL must use https:// or wss://")
    if not parsed.hostname:
        raise ConnectorError("Hub URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ConnectorError("Hub URL must not include credentials")
    if parsed.query or parsed.fragment:
        raise ConnectorError("Hub URL must not include a query or fragment")
    if parsed.path not in {"", "/"}:
        raise ConnectorError("Hub URL must not include a path")
    if parsed_port is not None and not 1 <= parsed_port <= 65_535:
        raise ConnectorError("Hub URL contains an invalid port")

    websocket_url = SplitResult(
        scheme="wss",
        netloc=parsed.netloc,
        path=f"/api/v1/connector/devices/{device_id}",
        query="",
        fragment="",
    )
    return urlunsplit(websocket_url)


def read_connector_token(
    *,
    environ: Mapping[str, str] | None = None,
    stdin: TextIO | None = None,
    prompt: Callable[[str], str] = getpass.getpass,
) -> str:
    environment = os.environ if environ is None else environ
    input_stream = sys.stdin if stdin is None else stdin

    token = environment.get(TOKEN_ENV_VAR)
    if token is None:
        if input_stream.isatty():
            token = prompt("Connector token: ")
        else:
            token = input_stream.readline()

    token = token.strip()
    if not token:
        raise ConnectorError(
            f"connector token is required on stdin or in {TOKEN_ENV_VAR}"
        )
    if any(character.isspace() for character in token):
        raise ConnectorError("connector token must not contain whitespace")
    return token


def format_host_port(host: str, port: int) -> str:
    display_host = f"[{host}]" if ":" in host else host
    return f"{display_host}:{port}"


def is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_listener_exposure(host: str, allow_non_loopback: bool) -> None:
    if not is_loopback_host(host) and not allow_non_loopback:
        raise ConnectorError(
            "non-loopback listeners require the explicit --allow-non-loopback flag"
        )


async def close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(
        OSError,
        ConnectionError,
        asyncio.CancelledError,
        asyncio.TimeoutError,
    ):
        await asyncio.wait_for(writer.wait_closed(), timeout=CLOSE_TIMEOUT)


class ConnectorServer:
    def __init__(
        self,
        *,
        connector_url: str,
        token: str,
        listen_host: str,
        listen_port: int,
        connect_timeout: float,
        idle_timeout: float,
    ) -> None:
        self.connector_url = connector_url
        self._token = token
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self._server: asyncio.Server | None = None
        self._connections: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()

    @property
    def bound_port(self) -> int:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("connector server has not started")
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._accept,
            host=self.listen_host,
            port=self.listen_port,
            limit=CHUNK_SIZE,
        )

    def _accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.create_task(
            self._handle_connection(reader, writer),
            name="opnsense-hub-connector-connection",
        )
        self._connections.add(task)
        task.add_done_callback(self._connection_done)

    def _connection_done(self, task: asyncio.Task[None]) -> None:
        self._connections.discard(task)
        if task.cancelled():
            return
        exception = task.exception()
        if exception is not None:
            print(
                f"Connector connection failed ({type(exception).__name__}).",
                file=sys.stderr,
            )

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self._writers.add(writer)
        try:
            async with connect(
                self.connector_url,
                additional_headers={
                    "Authorization": f"Bearer {self._token}",
                },
                open_timeout=self.connect_timeout,
                ping_interval=PING_INTERVAL,
                ping_timeout=PING_TIMEOUT,
                close_timeout=CLOSE_TIMEOUT,
                max_size=None,
                compression=None,
            ) as websocket:
                await self._relay(reader, writer, websocket)
        except RelayIdleTimeout:
            print("Local connection closed after the idle timeout.", file=sys.stderr)
        except RelayProtocolError:
            print("Hub closed a connection after sending non-binary data.", file=sys.stderr)
        except (TimeoutError, OSError, InvalidHandshake):
            print("Unable to establish a connector connection to the Hub.", file=sys.stderr)
        except ConnectionClosed:
            pass
        except asyncio.CancelledError:
            raise
        finally:
            self._writers.discard(writer)
            await close_writer(writer)

    async def _relay(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        websocket: ClientConnection,
    ) -> None:
        loop = asyncio.get_running_loop()
        last_activity = [loop.time()]

        async def tcp_to_websocket() -> None:
            while data := await reader.read(CHUNK_SIZE):
                await websocket.send(data)
                last_activity[0] = loop.time()

        async def websocket_to_tcp() -> None:
            async for message in websocket:
                if not isinstance(message, bytes):
                    raise RelayProtocolError
                writer.write(message)
                await writer.drain()
                last_activity[0] = loop.time()

        async def close_when_idle() -> None:
            while True:
                remaining = self.idle_timeout - (loop.time() - last_activity[0])
                if remaining <= 0:
                    raise RelayIdleTimeout
                await asyncio.sleep(remaining)

        tasks = {
            asyncio.create_task(tcp_to_websocket()),
            asyncio.create_task(websocket_to_tcp()),
            asyncio.create_task(close_when_idle()),
        }
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(
                    self._server.wait_closed(), timeout=CLOSE_TIMEOUT
                )
            self._server = None

        writers = tuple(self._writers)
        tasks = tuple(self._connections)
        for writer in writers:
            writer.close()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait(tasks, timeout=CLOSE_TIMEOUT)
        for writer in writers:
            writer.close()
        self._writers.clear()
        self._connections.clear()


async def run_connector(args: argparse.Namespace, token: str) -> None:
    listen_host, listen_port = args.listen
    validate_listener_exposure(listen_host, args.allow_non_loopback)
    connector_url = build_connector_url(args.hub_url, args.device)
    browser_host = args.browser_host or listen_host
    server = ConnectorServer(
        connector_url=connector_url,
        token=token,
        listen_host=listen_host,
        listen_port=listen_port,
        connect_timeout=args.connect_timeout,
        idle_timeout=args.idle_timeout,
    )
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    installed_signals: list[signal.Signals] = []

    for shutdown_signal in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(shutdown_signal, stop_event.set)
        except (NotImplementedError, RuntimeError):
            continue
        installed_signals.append(shutdown_signal)

    try:
        await server.start()
        actual_port = server.bound_port
        print(f"Listening on {format_host_port(listen_host, actual_port)}")
        print(
            f"Open https://{format_host_port(browser_host, actual_port)}/ in the browser."
        )
        if not is_loopback_host(listen_host):
            print(
                "Warning: the connector listener is exposed beyond loopback.",
                file=sys.stderr,
            )
        await stop_event.wait()
    finally:
        await server.stop()
        for shutdown_signal in installed_signals:
            loop.remove_signal_handler(shutdown_signal)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Forward local browser TCP connections to an OPNsense device through "
            "OPNsense Hub. The connector token is accepted only from stdin or "
            f"{TOKEN_ENV_VAR}."
        )
    )
    parser.add_argument(
        "--hub-url",
        required=True,
        help="Hub origin using https:// or wss://",
    )
    parser.add_argument(
        "--device",
        required=True,
        type=parse_device,
        help="OPNsense device UUID",
    )
    parser.add_argument(
        "--listen",
        type=parse_listen,
        default=parse_listen(DEFAULT_LISTEN),
        metavar="HOST:PORT",
        help=f"local TCP listener (default: {DEFAULT_LISTEN})",
    )
    parser.add_argument(
        "--browser-host",
        type=normalize_browser_host,
        help="hostname to show in the browser URL (default: listen host)",
    )
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="explicitly allow an unauthenticated listener beyond loopback",
    )
    parser.add_argument(
        "--connect-timeout",
        type=positive_timeout,
        default=DEFAULT_CONNECT_TIMEOUT,
        metavar="SECONDS",
        help=f"WebSocket opening timeout (default: {DEFAULT_CONNECT_TIMEOUT:g})",
    )
    parser.add_argument(
        "--idle-timeout",
        type=positive_timeout,
        default=DEFAULT_IDLE_TIMEOUT,
        metavar="SECONDS",
        help=f"per-connection payload idle timeout (default: {DEFAULT_IDLE_TIMEOUT:g})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        token = read_connector_token()
        asyncio.run(run_connector(args, token))
    except KeyboardInterrupt:
        return 130
    except ConnectorError as exc:
        parser.error(str(exc))
    except OSError as exc:
        print(f"Unable to start the local listener: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
