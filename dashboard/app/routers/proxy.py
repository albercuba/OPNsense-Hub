from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import uuid
from datetime import timezone
from typing import Annotated
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from starlette.websockets import WebSocketDisconnect

from ..audit import write_audit
from ..database import SessionLocal, get_db
from ..deps import current_user, has_company_access
from ..models import Device, User
from ..security import utc_now
from ..security.rate_limit import apply_rate_limit
from ..security.request_context import client_ip
from ..services.auth_service import session_from_request
from ..services.firmware_scheduler import tunnel_proxy_host
from ..services.proxy_auth import (
    create_connector_session,
    validate_connector_session,
    validate_connector_session_id,
)
from ..services.tcp_relay import TcpRelayManager
from ..web import render_template, settings
from ..wireguard import get_validated_hub_wireguard_config

router = APIRouter()
CONNECTOR_CHUNK_SIZE = 64 * 1024
_connector_connection_counts: dict[uuid.UUID, int] = {}
_connector_websockets: dict[uuid.UUID, set[WebSocket]] = {}
_connector_tasks: dict[uuid.UUID, set[asyncio.Task[None]]] = {}
_connector_connection_lock = asyncio.Lock()
_relay_device_locks: dict[uuid.UUID, asyncio.Lock] = {}
CONNECTOR_CLEANUP_TIMEOUT_SECONDS = 5

relay_manager = (
    TcpRelayManager(
        bind_host=settings.public_l4_relay_bind_host,
        port_min=settings.public_l4_relay_port_min,
        port_max=settings.public_l4_relay_port_max,
        ttl=settings.public_l4_relay_ttl_seconds,
        idle_timeout=settings.public_l4_relay_idle_timeout_seconds,
        max_connections=settings.public_l4_relay_max_connections,
    )
    if settings.public_l4_relay_enabled
    else TcpRelayManager()
)


def validate_proxy_device_target(device: Device) -> str:
    proxy_host = tunnel_proxy_host(device.wg_tunnel_ip)
    target_ip = ipaddress.ip_address(proxy_host)
    validated = get_validated_hub_wireguard_config()
    if not isinstance(target_ip, ipaddress.IPv4Address):
        raise ValueError("proxy target must be an IPv4 address")
    if target_ip not in validated.network:
        raise ValueError(
            f"proxy target {target_ip} is outside HUB_WG_CIDR {validated.network}"
        )
    if target_ip in {
        validated.hub_ip,
        validated.network.network_address,
        validated.network.broadcast_address,
    }:
        raise ValueError(f"proxy target {target_ip} is not a valid device tunnel IP")
    return str(target_ip)


def _require_dashboard_device(db: Session, user: User, device_id: uuid.UUID) -> Device:
    device = db.get(Device, device_id)
    if (
        device is None
        or device.revoked_at is not None
        or (device.status or "").lower() == "revoked"
        or not has_company_access(db, user, device.company_id)
    ):
        raise HTTPException(status_code=404)
    return device


def _proxy_base_hostname() -> str:
    try:
        parsed = urlparse(settings.proxy_public_url)
        _ = parsed.port
    except ValueError as exc:
        raise HTTPException(
            status_code=500, detail="PROXY_PUBLIC_URL is invalid"
        ) from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise HTTPException(status_code=500, detail="PROXY_PUBLIC_URL is invalid")
    return parsed.hostname.lower()


def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; "
        "script-src 'none'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    )
    return response


@router.post("/devices/{device_id}/proxy/open", response_class=HTMLResponse)
def open_device_connector(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = _require_dashboard_device(db, user, device_id)
    apply_rate_limit(
        request,
        "device-connector-open",
        str(user.id),
        settings.rate_limit_device_access_attempts,
        settings.rate_limit_device_access_window_seconds,
    )
    validate_proxy_device_target(device)
    dashboard_session = session_from_request(request, db)
    token = create_connector_session(db, user, device, dashboard_session)
    write_audit(
        db,
        request,
        "device.connector.open",
        user=user,
        company_id=device.company_id,
        device_id=device.id,
    )
    response = render_template(
        db,
        "proxy_handoff.html",
        {
            "request": request,
            "device": device,
            "connector_token": token,
            "connector_hub_url": settings.public_url.rstrip("/"),
            "connector_local_port": settings.connector_local_port,
            "connector_session_ttl_minutes": settings.connector_session_ttl_minutes,
            "public_l4_relay_enabled": settings.public_l4_relay_enabled,
        },
    )
    db.commit()
    return _no_store(response)


async def _replace_device_relay(
    device_id: uuid.UUID,
    target_host: str,
    target_port: int,
    source_ip: str,
    public_base_hostname: str,
):
    device_lock = _relay_device_locks.setdefault(device_id, asyncio.Lock())
    async with device_lock:
        await relay_manager.close_device(device_id)
        return await relay_manager.create_relay(
            device_id,
            target_host,
            target_port,
            source_ip,
            public_base_hostname,
        )


async def _close_device_relay(device_id: uuid.UUID) -> None:
    device_lock = _relay_device_locks.setdefault(device_id, asyncio.Lock())
    async with device_lock:
        await relay_manager.close_device(device_id)


@router.post("/devices/{device_id}/relay/open", response_class=HTMLResponse)
async def open_public_l4_relay(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    if not settings.public_l4_relay_enabled:
        raise HTTPException(status_code=404)
    if not settings.public_l4_relay_mtls_required:
        raise HTTPException(
            status_code=503,
            detail="public relay requires OPNsense-side mutual TLS enforcement",
        )
    device = _require_dashboard_device(db, user, device_id)
    apply_rate_limit(
        request,
        "device-relay-open",
        str(user.id),
        settings.rate_limit_device_access_attempts,
        settings.rate_limit_device_access_window_seconds,
    )
    target_host = validate_proxy_device_target(device)
    source_ip = client_ip(request)
    try:
        ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail="could not determine a stable client IP"
        ) from exc

    try:
        allocation = await _replace_device_relay(
            device.id,
            target_host,
            settings.opnsense_gui_port,
            source_ip,
            _proxy_base_hostname(),
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(
            status_code=503, detail="no public relay port is currently available"
        ) from exc

    try:
        db.expire_all()
        device = _require_dashboard_device(db, user, device_id)
        write_audit(
            db,
            request,
            "device.relay.open",
            user=user,
            company_id=device.company_id,
            device_id=device.id,
        )
        response = render_template(
            db,
            "relay_handoff.html",
            {
                "request": request,
                "device": device,
                "relay_url": allocation.url,
                "relay_expires_at": allocation.expires_at,
                "source_ip": source_ip,
            },
        )
        db.commit()
    except BaseException:
        db.rollback()
        await relay_manager.close_allocation(allocation)
        raise
    return _no_store(response)


def _bearer_token(websocket: WebSocket) -> str | None:
    authorization = websocket.headers.get("authorization")
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.removeprefix("Bearer ").strip()
    return token or None


async def _reserve_connector_connection(session_id: uuid.UUID) -> bool:
    async with _connector_connection_lock:
        current = _connector_connection_counts.get(session_id, 0)
        if current >= settings.connector_max_connections:
            return False
        _connector_connection_counts[session_id] = current + 1
        return True


async def _track_connector_connection(
    device_id: uuid.UUID, websocket: WebSocket
) -> None:
    task = asyncio.current_task()
    async with _connector_connection_lock:
        _connector_websockets.setdefault(device_id, set()).add(websocket)
        if task is not None:
            _connector_tasks.setdefault(device_id, set()).add(task)


async def _release_connector_connection(
    session_id: uuid.UUID, device_id: uuid.UUID, websocket: WebSocket
) -> None:
    task = asyncio.current_task()
    async with _connector_connection_lock:
        current = _connector_connection_counts.get(session_id, 0)
        if current <= 1:
            _connector_connection_counts.pop(session_id, None)
        else:
            _connector_connection_counts[session_id] = current - 1

        device_websockets = _connector_websockets.get(device_id)
        if device_websockets is not None:
            device_websockets.discard(websocket)
            if not device_websockets:
                _connector_websockets.pop(device_id, None)

        device_tasks = _connector_tasks.get(device_id)
        if device_tasks is not None and task is not None:
            device_tasks.discard(task)
            if not device_tasks:
                _connector_tasks.pop(device_id, None)


async def _close_tracked_connectors(
    websockets: tuple[WebSocket, ...],
    tasks: tuple[asyncio.Task[None], ...],
    *,
    code: int,
    reason: str,
) -> None:
    current_task = asyncio.current_task()
    pending_tasks = tuple(task for task in tasks if task is not current_task)
    for task in pending_tasks:
        task.cancel()

    async def close_websocket(websocket: WebSocket) -> None:
        with contextlib.suppress(RuntimeError, WebSocketDisconnect):
            await websocket.close(code=code, reason=reason)

    cleanup = asyncio.gather(
        *(close_websocket(websocket) for websocket in websockets),
        *pending_tasks,
        return_exceptions=True,
    )
    with contextlib.suppress(asyncio.TimeoutError):
        await asyncio.wait_for(cleanup, timeout=CONNECTOR_CLEANUP_TIMEOUT_SECONDS)


async def close_device_access(device_id: uuid.UUID) -> None:
    await _close_device_relay(device_id)
    async with _connector_connection_lock:
        websockets = tuple(_connector_websockets.pop(device_id, set()))
        tasks = tuple(_connector_tasks.pop(device_id, set()))
    await _close_tracked_connectors(
        websockets,
        tasks,
        code=4403,
        reason="device access revoked",
    )


async def close_all_access() -> None:
    await relay_manager.close_all()
    async with _connector_connection_lock:
        websockets = tuple(
            websocket
            for device_websockets in _connector_websockets.values()
            for websocket in device_websockets
        )
        tasks = tuple(
            task for device_tasks in _connector_tasks.values() for task in device_tasks
        )
        _connector_websockets.clear()
        _connector_tasks.clear()
    await _close_tracked_connectors(
        websockets,
        tasks,
        code=1001,
        reason="Hub shutting down",
    )


class ConnectorAuthorizationEnded(Exception):
    pass


def _connector_session_is_authorized(
    connector_session_id: uuid.UUID, device_id: uuid.UUID
) -> bool:
    db = SessionLocal()
    try:
        validate_connector_session_id(db, connector_session_id, device_id)
        return True
    except (HTTPException, ValueError):
        return False
    finally:
        db.close()


async def _monitor_connector_authorization(
    connector_session_id: uuid.UUID, device_id: uuid.UUID
) -> None:
    while True:
        await asyncio.sleep(settings.connector_authorization_recheck_seconds)
        authorized = await asyncio.to_thread(
            _connector_session_is_authorized,
            connector_session_id,
            device_id,
        )
        if not authorized:
            raise ConnectorAuthorizationEnded


async def _pipe_websocket_to_tcp(
    websocket: WebSocket, writer: asyncio.StreamWriter
) -> None:
    while True:
        message = await websocket.receive()
        message_type = message.get("type")
        if message_type == "websocket.disconnect":
            return
        data = message.get("bytes")
        if not isinstance(data, bytes):
            await websocket.close(code=1003, reason="binary frames required")
            return
        writer.write(data)
        await writer.drain()


async def _pipe_tcp_to_websocket(
    reader: asyncio.StreamReader, websocket: WebSocket
) -> None:
    while chunk := await reader.read(CONNECTOR_CHUNK_SIZE):
        await websocket.send_bytes(chunk)


async def _relay_connector_stream(
    websocket: WebSocket,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    connector_session_id: uuid.UUID,
    device_id: uuid.UUID,
) -> None:
    tasks = {
        asyncio.create_task(_pipe_websocket_to_tcp(websocket, writer)),
        asyncio.create_task(_pipe_tcp_to_websocket(reader, websocket)),
        asyncio.create_task(
            _monitor_connector_authorization(connector_session_id, device_id)
        ),
    }
    done: set[asyncio.Task[None]] = set()
    try:
        done, _pending = await asyncio.wait(
            tasks, return_when=asyncio.FIRST_COMPLETED
        )
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    for task in done:
        task.result()


@router.websocket("/api/v1/connector/devices/{device_id}")
async def connector_device_tunnel(websocket: WebSocket, device_id: uuid.UUID):
    token = _bearer_token(websocket)
    if token is None:
        await websocket.close(code=4401, reason="connector authorization required")
        return

    db = SessionLocal()
    try:
        connector_session, _user, device = validate_connector_session(
            db, token, device_id
        )
        target_host = validate_proxy_device_target(device)
        db.commit()
        db.refresh(connector_session)
        connector_session_id = connector_session.id
        connector_expires_at = connector_session.expires_at
    except (HTTPException, ValueError):
        db.rollback()
        await websocket.close(code=4401, reason="invalid connector authorization")
        return
    finally:
        db.close()

    if not await _reserve_connector_connection(connector_session_id):
        await websocket.close(code=4429, reason="connector connection limit reached")
        return

    writer: asyncio.StreamWriter | None = None
    await _track_connector_connection(device_id, websocket)
    try:
        if not await asyncio.to_thread(
            _connector_session_is_authorized, connector_session_id, device_id
        ):
            await websocket.close(code=4401, reason="invalid connector authorization")
            return

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    target_host,
                    settings.opnsense_gui_port,
                    limit=CONNECTOR_CHUNK_SIZE,
                ),
                timeout=settings.connector_upstream_connect_timeout_seconds,
            )
        except (OSError, asyncio.TimeoutError):
            await websocket.close(code=4502, reason="firewall connection failed")
            return

        if not await asyncio.to_thread(
            _connector_session_is_authorized, connector_session_id, device_id
        ):
            await websocket.close(code=4401, reason="invalid connector authorization")
            return

        await websocket.accept()
        expires_at = connector_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        remaining = max(0.0, (expires_at - utc_now()).total_seconds())
        if remaining <= 0:
            await websocket.close(code=4401, reason="connector session expired")
            return
        try:
            await asyncio.wait_for(
                _relay_connector_stream(
                    websocket,
                    reader,
                    writer,
                    connector_session_id,
                    device_id,
                ),
                timeout=min(remaining, settings.connector_connection_max_seconds),
            )
        except asyncio.TimeoutError:
            await websocket.close(code=1000, reason="connector session ended")
        except ConnectorAuthorizationEnded:
            await websocket.close(code=4403, reason="connector authorization ended")
    except (RuntimeError, WebSocketDisconnect):
        pass
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(OSError, ConnectionError):
                await writer.wait_closed()
        await _release_connector_connection(
            connector_session_id, device_id, websocket
        )
