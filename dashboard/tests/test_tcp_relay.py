from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from typing import Any
from uuid import UUID, uuid4

from app.services.tcp_relay import RELAY_CHUNK_SIZE, TcpRelayManager

LOOPBACK = "127.0.0.1"


async def _start_echo_server(
    on_connect: Callable[[], None] | None = None,
) -> asyncio.Server:
    async def echo(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if on_connect is not None:
            on_connect()
        try:
            while data := await reader.read(RELAY_CHUNK_SIZE):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass

    return await asyncio.start_server(echo, LOOPBACK, 0)


def _server_port(server: asyncio.Server) -> int:
    sockets = server.sockets
    assert sockets
    return int(sockets[0].getsockname()[1])


async def _unused_port() -> int:
    server = await asyncio.start_server(lambda _reader, writer: writer.close(), LOOPBACK, 0)
    port = _server_port(server)
    server.close()
    await server.wait_closed()
    return port


async def _close_server(server: asyncio.Server) -> None:
    server.close()
    await server.wait_closed()


async def _assert_connection_refused(port: int) -> None:
    try:
        await asyncio.wait_for(asyncio.open_connection(LOOPBACK, port), timeout=0.5)
    except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
        return
    raise AssertionError(f"connection to expired relay port {port} succeeded")


async def _assert_stream_closed(reader: asyncio.StreamReader) -> None:
    try:
        assert await asyncio.wait_for(reader.read(1), timeout=1) == b""
    except ConnectionError:
        pass


async def _close_client_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except ConnectionError:
        pass


def _run(test: Callable[[], Coroutine[Any, Any, None]]) -> None:
    asyncio.run(test())


def test_relay_forwards_exact_bytes_and_builds_device_url() -> None:
    async def scenario() -> None:
        echo_server = await _start_echo_server()
        relay_port = await _unused_port()
        device_id = uuid4()
        manager = TcpRelayManager(
            bind_host=LOOPBACK,
            port_min=relay_port,
            port_max=relay_port,
            ttl=5,
            idle_timeout=2,
            max_connections=2,
        )
        try:
            allocation = await manager.create_relay(
                device_id,
                LOOPBACK,
                _server_port(echo_server),
                LOOPBACK,
                "Relay.Example.Test.",
            )
            assert allocation.device_id == device_id
            assert allocation.port == relay_port
            assert relay_port <= allocation.port <= relay_port
            assert allocation.url == (
                f"https://d-{device_id.hex}.relay.example.test:{relay_port}/"
            )
            assert UUID(allocation.public_host.removeprefix("d-").split(".", 1)[0]) == device_id

            reader, writer = await asyncio.open_connection(LOOPBACK, allocation.port)
            payload = bytes(range(256)) * ((RELAY_CHUNK_SIZE * 2 // 256) + 17)
            writer.write(payload)
            await writer.drain()
            echoed = await asyncio.wait_for(reader.readexactly(len(payload)), timeout=2)
            assert echoed == payload
            await _close_client_writer(writer)
        finally:
            await manager.close_all()
            await _close_server(echo_server)

    _run(scenario)


def test_relay_rejects_nonmatching_source_before_upstream_connect() -> None:
    async def scenario() -> None:
        upstream_connected = asyncio.Event()
        echo_server = await _start_echo_server(upstream_connected.set)
        relay_port = await _unused_port()
        manager = TcpRelayManager(
            bind_host=LOOPBACK,
            port_min=relay_port,
            port_max=relay_port,
            ttl=5,
            idle_timeout=1,
            max_connections=1,
        )
        try:
            allocation = await manager.create_relay(
                uuid4(),
                LOOPBACK,
                _server_port(echo_server),
                "127.0.0.2",
                "relay.example.test",
            )
            reader, writer = await asyncio.open_connection(LOOPBACK, allocation.port)
            writer.write(b"must not reach upstream")
            await writer.drain()
            await _assert_stream_closed(reader)
            await asyncio.sleep(0.05)
            assert not upstream_connected.is_set()
            await _close_client_writer(writer)
        finally:
            await manager.close_all()
            await _close_server(echo_server)

    _run(scenario)


def test_relay_enforces_per_relay_connection_cap() -> None:
    async def scenario() -> None:
        upstream_connections = 0
        first_upstream_connection = asyncio.Event()

        def connected() -> None:
            nonlocal upstream_connections
            upstream_connections += 1
            first_upstream_connection.set()

        echo_server = await _start_echo_server(connected)
        relay_port = await _unused_port()
        manager = TcpRelayManager(
            bind_host=LOOPBACK,
            port_min=relay_port,
            port_max=relay_port,
            ttl=5,
            idle_timeout=2,
            max_connections=1,
        )
        first_writer: asyncio.StreamWriter | None = None
        second_writer: asyncio.StreamWriter | None = None
        try:
            allocation = await manager.create_relay(
                uuid4(),
                LOOPBACK,
                _server_port(echo_server),
                LOOPBACK,
                "relay.example.test",
            )
            first_reader, first_writer = await asyncio.open_connection(
                LOOPBACK, allocation.port
            )
            await asyncio.wait_for(first_upstream_connection.wait(), timeout=1)

            second_reader, second_writer = await asyncio.open_connection(
                LOOPBACK, allocation.port
            )
            await _assert_stream_closed(second_reader)
            await asyncio.sleep(0.05)
            assert upstream_connections == 1

            first_writer.write(b"still connected")
            await first_writer.drain()
            assert await asyncio.wait_for(
                first_reader.readexactly(len(b"still connected")), timeout=1
            ) == b"still connected"
        finally:
            if first_writer is not None:
                await _close_client_writer(first_writer)
            if second_writer is not None:
                await _close_client_writer(second_writer)
            await manager.close_all()
            await _close_server(echo_server)

    _run(scenario)


def test_hard_expiry_closes_listener_and_active_connection() -> None:
    async def scenario() -> None:
        upstream_connected = asyncio.Event()
        echo_server = await _start_echo_server(upstream_connected.set)
        relay_port = await _unused_port()
        manager = TcpRelayManager(
            bind_host=LOOPBACK,
            port_min=relay_port,
            port_max=relay_port,
            ttl=0.15,
            idle_timeout=5,
            max_connections=1,
        )
        writer: asyncio.StreamWriter | None = None
        try:
            allocation = await manager.create_relay(
                uuid4(),
                LOOPBACK,
                _server_port(echo_server),
                LOOPBACK,
                "relay.example.test",
            )
            reader, writer = await asyncio.open_connection(LOOPBACK, allocation.port)
            await asyncio.wait_for(upstream_connected.wait(), timeout=1)
            await _assert_stream_closed(reader)
            await _assert_connection_refused(allocation.port)
        finally:
            if writer is not None:
                await _close_client_writer(writer)
            await manager.close_all()
            await _close_server(echo_server)

    _run(scenario)


def test_idle_timeout_and_explicit_cleanup_close_connections_and_ports() -> None:
    async def scenario() -> None:
        echo_server = await _start_echo_server()
        first_port = await _unused_port()
        manager = TcpRelayManager(
            bind_host=LOOPBACK,
            port_min=first_port,
            port_max=first_port,
            ttl=5,
            idle_timeout=0.1,
            max_connections=1,
        )
        device_id = uuid4()
        writer: asyncio.StreamWriter | None = None
        try:
            allocation = await manager.create_relay(
                device_id,
                LOOPBACK,
                _server_port(echo_server),
                LOOPBACK,
                "relay.example.test",
            )
            reader, writer = await asyncio.open_connection(LOOPBACK, allocation.port)
            await _assert_stream_closed(reader)

            replacement_reader, replacement_writer = await asyncio.open_connection(
                LOOPBACK, allocation.port
            )
            replacement_writer.write(b"new connection")
            await replacement_writer.drain()
            assert await asyncio.wait_for(
                replacement_reader.readexactly(len(b"new connection")), timeout=1
            ) == b"new connection"
            await _close_client_writer(replacement_writer)

            assert await manager.close_device(device_id) == 1
            await _assert_connection_refused(allocation.port)
            assert await manager.close_all() == 0
        finally:
            if writer is not None:
                await _close_client_writer(writer)
            await manager.close_all()
            await _close_server(echo_server)

    _run(scenario)
