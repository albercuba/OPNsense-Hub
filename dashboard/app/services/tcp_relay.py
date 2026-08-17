from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

RELAY_CHUNK_SIZE = 64 * 1024
RELAY_SHUTDOWN_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True, slots=True)
class TcpRelayAllocation:
    device_id: uuid.UUID
    bind_host: str
    public_host: str
    port: int
    url: str
    expires_at: datetime


@dataclass(slots=True)
class _ConnectionActivity:
    last_activity: float


@dataclass(slots=True)
class _RelayState:
    allocation: TcpRelayAllocation
    target_host: str
    target_port: int
    allowed_client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    server: asyncio.AbstractServer
    expires_at: float
    active_connections: int = 0
    writers: set[asyncio.StreamWriter] = field(default_factory=set)
    tasks: set[asyncio.Task[None]] = field(default_factory=set)
    expiry_task: asyncio.Task[None] | None = None
    closing: bool = False


class TcpRelayManager:
    """Manage short-lived raw TCP relays without terminating TLS."""

    def __init__(
        self,
        bind_host: str = "0.0.0.0",
        port_min: int = 20_000,
        port_max: int = 30_000,
        ttl: float = 300.0,
        idle_timeout: float = 60.0,
        max_connections: int = 4,
    ) -> None:
        bind_host = bind_host.strip()
        if not bind_host:
            raise ValueError("bind_host must not be empty")
        if not 1 <= port_min <= 65_535:
            raise ValueError("port_min must be between 1 and 65535")
        if not 1 <= port_max <= 65_535:
            raise ValueError("port_max must be between 1 and 65535")
        if port_min > port_max:
            raise ValueError("port_min must not exceed port_max")
        if ttl <= 0:
            raise ValueError("ttl must be greater than zero")
        if idle_timeout <= 0:
            raise ValueError("idle_timeout must be greater than zero")
        if max_connections < 1:
            raise ValueError("max_connections must be at least one")

        self.bind_host = bind_host
        self.port_min = port_min
        self.port_max = port_max
        self.ttl = float(ttl)
        self.idle_timeout = float(idle_timeout)
        self.max_connections = max_connections
        self._relays: dict[int, _RelayState] = {}
        self._lock = asyncio.Lock()
        self._random = random.SystemRandom()

    async def create_relay(
        self,
        device_id: uuid.UUID | str,
        target_host: str,
        target_port: int,
        allowed_client_ip: str,
        public_base_host: str,
    ) -> TcpRelayAllocation:
        normalized_device_id = self._parse_device_id(device_id)
        normalized_target_host = target_host.strip()
        if not normalized_target_host:
            raise ValueError("target_host must not be empty")
        if not 1 <= target_port <= 65_535:
            raise ValueError("target_port must be between 1 and 65535")
        normalized_client_ip = ipaddress.ip_address(allowed_client_ip)
        normalized_base_host = self._normalize_public_base_host(public_base_host)
        public_host = f"d-{normalized_device_id.hex}.{normalized_base_host}"

        candidates = list(range(self.port_min, self.port_max + 1))
        self._random.shuffle(candidates)
        last_error: OSError | None = None

        async with self._lock:
            for port in candidates:
                if port in self._relays:
                    continue

                state_holder: list[_RelayState | None] = [None]

                async def accept_client(
                    reader: asyncio.StreamReader,
                    writer: asyncio.StreamWriter,
                    holder: list[_RelayState | None] = state_holder,
                ) -> None:
                    relay_state = holder[0]
                    if relay_state is None:  # pragma: no cover - starts after assignment
                        await self._close_writer(writer)
                        return
                    await self._handle_client(relay_state, reader, writer)

                try:
                    server = await asyncio.start_server(
                        accept_client,
                        host=self.bind_host,
                        port=port,
                        limit=RELAY_CHUNK_SIZE,
                        start_serving=False,
                    )
                except OSError as exc:
                    last_error = exc
                    continue

                loop = asyncio.get_running_loop()
                allocation = TcpRelayAllocation(
                    device_id=normalized_device_id,
                    bind_host=self.bind_host,
                    public_host=public_host,
                    port=port,
                    url=f"https://{public_host}:{port}/",
                    expires_at=datetime.now(timezone.utc)
                    + timedelta(seconds=self.ttl),
                )
                state = _RelayState(
                    allocation=allocation,
                    target_host=normalized_target_host,
                    target_port=target_port,
                    allowed_client_ip=normalized_client_ip,
                    server=server,
                    expires_at=loop.time() + self.ttl,
                )
                state_holder[0] = state
                self._relays[port] = state
                try:
                    await server.start_serving()
                except BaseException:
                    self._relays.pop(port, None)
                    server.close()
                    await server.wait_closed()
                    raise
                state.expiry_task = asyncio.create_task(
                    self._expire_relay(state),
                    name=f"tcp-relay-expiry-{port}",
                )
                return allocation

        message = f"no available TCP relay port in {self.port_min}-{self.port_max}"
        if last_error is not None:
            raise RuntimeError(message) from last_error
        raise RuntimeError(message)

    async def close_allocation(self, allocation: TcpRelayAllocation) -> bool:
        async with self._lock:
            state = self._relays.get(allocation.port)
            if state is None or state.allocation != allocation:
                return False
            self._detach_relay(state)
        await self._shutdown_relay(state)
        return True

    async def close_device(self, device_id: uuid.UUID | str) -> int:
        normalized_device_id = self._parse_device_id(device_id)
        async with self._lock:
            states = [
                state
                for state in self._relays.values()
                if state.allocation.device_id == normalized_device_id
            ]
            for state in states:
                self._detach_relay(state)
        await asyncio.gather(
            *(self._shutdown_relay(state) for state in states),
            return_exceptions=False,
        )
        return len(states)

    async def close_all(self) -> int:
        async with self._lock:
            states = list(self._relays.values())
            for state in states:
                self._detach_relay(state)
        await asyncio.gather(
            *(self._shutdown_relay(state) for state in states),
            return_exceptions=False,
        )
        return len(states)

    async def _handle_client(
        self,
        state: _RelayState,
        downstream_reader: asyncio.StreamReader,
        downstream_writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            state.tasks.add(task)

        accepted = False
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            if state.closing or not self._peer_is_allowed(
                downstream_writer, state.allowed_client_ip
            ):
                return
            if state.active_connections >= self.max_connections:
                return

            state.active_connections += 1
            accepted = True
            state.writers.add(downstream_writer)

            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        state.target_host,
                        state.target_port,
                        limit=RELAY_CHUNK_SIZE,
                    ),
                    timeout=self.idle_timeout,
                )
            except (OSError, asyncio.TimeoutError):
                return

            if state.closing:
                return
            state.writers.add(upstream_writer)
            await self._forward_connection(
                downstream_reader,
                downstream_writer,
                upstream_reader,
                upstream_writer,
            )
        finally:
            if upstream_writer is not None:
                state.writers.discard(upstream_writer)
                await self._close_writer(upstream_writer)
            state.writers.discard(downstream_writer)
            await self._close_writer(downstream_writer)
            if accepted:
                state.active_connections -= 1
            if task is not None:
                state.tasks.discard(task)

    async def _forward_connection(
        self,
        downstream_reader: asyncio.StreamReader,
        downstream_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        loop = asyncio.get_running_loop()
        activity = _ConnectionActivity(last_activity=loop.time())
        pumps = {
            asyncio.create_task(
                self._pump(downstream_reader, upstream_writer, activity)
            ),
            asyncio.create_task(
                self._pump(upstream_reader, downstream_writer, activity)
            ),
        }
        idle_task = asyncio.create_task(
            self._close_when_idle(activity, downstream_writer, upstream_writer)
        )
        try:
            await asyncio.wait(pumps | {idle_task}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for pending_task in pumps | {idle_task}:
                pending_task.cancel()
            await asyncio.gather(*pumps, idle_task, return_exceptions=True)

    async def _pump(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        activity: _ConnectionActivity,
    ) -> None:
        loop = asyncio.get_running_loop()
        while chunk := await reader.read(RELAY_CHUNK_SIZE):
            activity.last_activity = loop.time()
            writer.write(chunk)
            await writer.drain()

    async def _close_when_idle(
        self,
        activity: _ConnectionActivity,
        downstream_writer: asyncio.StreamWriter,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        loop = asyncio.get_running_loop()
        while True:
            remaining = self.idle_timeout - (loop.time() - activity.last_activity)
            if remaining <= 0:
                downstream_writer.close()
                upstream_writer.close()
                return
            await asyncio.sleep(remaining)

    async def _expire_relay(self, state: _RelayState) -> None:
        delay = max(0.0, state.expires_at - asyncio.get_running_loop().time())
        try:
            await asyncio.sleep(delay)
            async with self._lock:
                if self._relays.get(state.allocation.port) is not state:
                    return
                self._detach_relay(state)
            await self._shutdown_relay(state)
        except asyncio.CancelledError:
            return

    def _detach_relay(self, state: _RelayState) -> None:
        state.closing = True
        self._relays.pop(state.allocation.port, None)
        state.server.close()

    async def _shutdown_relay(self, state: _RelayState) -> None:
        current_task = asyncio.current_task()
        expiry_task = state.expiry_task
        if expiry_task is not None and expiry_task is not current_task:
            expiry_task.cancel()

        state.server.close()
        writers = tuple(state.writers)
        for writer in writers:
            writer.close()

        connection_tasks = tuple(
            task for task in state.tasks if task is not current_task
        )
        for task in connection_tasks:
            task.cancel()

        cleanup = asyncio.gather(
            state.server.wait_closed(),
            *(self._wait_writer_closed(writer) for writer in writers),
            *connection_tasks,
            return_exceptions=True,
        )
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(cleanup, timeout=RELAY_SHUTDOWN_TIMEOUT_SECONDS)
        if expiry_task is not None and expiry_task is not current_task:
            with contextlib.suppress(asyncio.CancelledError):
                await expiry_task

    @staticmethod
    def _peer_is_allowed(
        writer: asyncio.StreamWriter,
        allowed_client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> bool:
        peername = writer.get_extra_info("peername")
        if not isinstance(peername, tuple) or not peername:
            return False
        try:
            peer_ip = ipaddress.ip_address(str(peername[0]))
        except ValueError:
            return False
        return peer_ip == allowed_client_ip

    @staticmethod
    async def _close_writer(writer: asyncio.StreamWriter) -> None:
        writer.close()
        await TcpRelayManager._wait_writer_closed(writer)

    @staticmethod
    async def _wait_writer_closed(writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(OSError, ConnectionError, asyncio.TimeoutError):
            await asyncio.wait_for(
                writer.wait_closed(), timeout=RELAY_SHUTDOWN_TIMEOUT_SECONDS
            )

    @staticmethod
    def _parse_device_id(device_id: uuid.UUID | str) -> uuid.UUID:
        if isinstance(device_id, uuid.UUID):
            return device_id
        try:
            return uuid.UUID(str(device_id))
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError("device_id must be a UUID") from exc

    @staticmethod
    def _normalize_public_base_host(public_base_host: str) -> str:
        base_host = public_base_host.strip().rstrip(".")
        if (
            not base_host
            or len(base_host) > 253
            or any(character.isspace() for character in base_host)
            or any(character in base_host for character in "/:@[]")
        ):
            raise ValueError("public_base_host must be a DNS hostname")
        try:
            ascii_host = base_host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("public_base_host must be a DNS hostname") from exc
        labels = ascii_host.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or any(not (character.isalnum() or character == "-") for character in label)
            for label in labels
        ):
            raise ValueError("public_base_host must be a DNS hostname")
        return ascii_host
