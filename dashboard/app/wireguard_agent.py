from __future__ import annotations

import asyncio
import base64
import contextlib
import ipaddress
from contextlib import asynccontextmanager

from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, status
from pydantic import BaseModel, Field
from starlette.websockets import WebSocketDisconnect

from .config import get_settings
from .hardening import apply_startup_hardening
from .wireguard import (
    WireGuardError,
    _add_peer_local,
    _ensure_server_interface_local,
    _ensure_server_keypair_local,
    _get_runtime_peers_local,
    _remove_peer_local,
    _render_server_config_local,
    _runtime_peer_to_payload,
    _sync_peer_payloads_local,
    validate_public_key,
)

settings = get_settings()
CONNECTOR_CHUNK_SIZE = 64 * 1024


class PeerRequest(BaseModel):
    public_key: str
    tunnel_ip: str


class RemovePeerRequest(BaseModel):
    public_key: str


class PeerSyncRequest(BaseModel):
    peers: list[PeerRequest]


class ProbeResponse(BaseModel):
    reachable: bool
    message: str


class ProxyRequest(BaseModel):
    host: str
    port: int
    method: str
    path: str
    query: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    body_b64: str = ""


class ProxyResponse(BaseModel):
    status_code: int
    headers: list[tuple[str, str]]
    body_b64: str


def _peer_request_payload(peer: PeerRequest) -> dict[str, str]:
    return {"public_key": peer.public_key, "tunnel_ip": peer.tunnel_ip}


def require_agent_auth(
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    expected = settings.wg_agent_token
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WG_AGENT_TOKEN is not configured",
        )
    if authorization != f"Bearer {expected}":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not settings.wg_agent_mode:
        raise RuntimeError("wireguard_agent must run with WG_AGENT_MODE=true")
    apply_startup_hardening(settings)
    yield


app = FastAPI(title="OPNsense Hub WireGuard Agent", lifespan=lifespan)


@app.get("/health", dependencies=[Depends(require_agent_auth)])
def health():
    return {"status": "ok"}


@app.get("/server-public-key", dependencies=[Depends(require_agent_auth)])
def server_public_key():
    try:
        return {"public_key": _ensure_server_keypair_local()}
    except WireGuardError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/render-config", dependencies=[Depends(require_agent_auth)])
def render_config():
    try:
        _render_server_config_local()
        return {"status": "ok"}
    except WireGuardError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/interface", dependencies=[Depends(require_agent_auth)])
def interface():
    try:
        _ensure_server_interface_local()
        return {"exists": True}
    except WireGuardError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/interface", dependencies=[Depends(require_agent_auth)])
def ensure_interface():
    try:
        _ensure_server_interface_local()
        return {"status": "ok"}
    except WireGuardError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/bootstrap", dependencies=[Depends(require_agent_auth)])
def bootstrap(payload: PeerSyncRequest):
    try:
        _ensure_server_interface_local()
        _sync_peer_payloads_local([_peer_request_payload(peer) for peer in payload.peers])
        return {"status": "ok"}
    except WireGuardError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/sync-peers", dependencies=[Depends(require_agent_auth)])
def sync_peers(payload: PeerSyncRequest):
    try:
        _sync_peer_payloads_local([_peer_request_payload(peer) for peer in payload.peers])
        return {"status": "ok"}
    except WireGuardError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/peers", dependencies=[Depends(require_agent_auth)])
def peers():
    try:
        return {"peers": [_runtime_peer_to_payload(peer) for peer in _get_runtime_peers_local()]}
    except WireGuardError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/peers", dependencies=[Depends(require_agent_auth)])
def add_peer(payload: PeerRequest):
    try:
        _add_peer_local(payload.public_key, payload.tunnel_ip)
        return {"status": "ok"}
    except (ValueError, WireGuardError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/peers/remove", dependencies=[Depends(require_agent_auth)])
def remove_peer(payload: RemovePeerRequest):
    try:
        validate_public_key(payload.public_key)
        _remove_peer_local(payload.public_key)
        return {"status": "ok"}
    except WireGuardError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _validate_connect_target(host: str, port: int) -> None:
    try:
        target_ip = ipaddress.ip_address(host)
        network = ipaddress.ip_network(settings.hub_wg_cidr, strict=False)
    except ValueError as exc:
        raise WireGuardError("invalid WireGuard connect target") from exc
    if not isinstance(target_ip, ipaddress.IPv4Address) or not isinstance(
        network, ipaddress.IPv4Network
    ):
        raise WireGuardError("WireGuard connect target must be IPv4")
    if target_ip not in network:
        raise WireGuardError("WireGuard connect target is outside HUB_WG_CIDR")
    if port != settings.opnsense_gui_port:
        raise WireGuardError("WireGuard connect target port is not permitted")


@app.get("/probe-webgui", dependencies=[Depends(require_agent_auth)])
async def probe_webgui(host: Annotated[str, Query()], port: Annotated[int, Query()]):
    try:
        _validate_connect_target(host, port)
    except WireGuardError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    url = f"https://{host}:{port}/"
    try:
        async with httpx.AsyncClient(
            verify=settings.proxy_verify_tls,
            follow_redirects=False,
            timeout=settings.firewall_health_check_timeout_seconds,
        ) as client:
            await client.get(url)
    except httpx.RequestError as exc:
        error_detail = str(exc) or repr(exc)
        return ProbeResponse(
            reachable=False,
            message=f"WebGUI unreachable at {url}: {exc.__class__.__name__}: {error_detail}",
        )
    return ProbeResponse(reachable=True, message=f"WebGUI reachable at {url}")


@app.post("/proxy-request", dependencies=[Depends(require_agent_auth)])
async def proxy_request(payload: ProxyRequest):
    try:
        _validate_connect_target(payload.host, payload.port)
    except WireGuardError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    method = payload.method.upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        raise HTTPException(status_code=405, detail="method is not supported")
    path = payload.path if payload.path.startswith("/") else "/" + payload.path
    if ".." in path.split("/"):
        raise HTTPException(status_code=400, detail="invalid proxy path")
    url = f"https://{payload.host}:{payload.port}{path}"
    if payload.query:
        url += "?" + payload.query
    try:
        body = base64.b64decode(payload.body_b64.encode("ascii"), validate=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid request body") from exc
    if len(body) > settings.max_proxy_request_bytes:
        raise HTTPException(status_code=413, detail="proxy request body is too large")
    try:
        async with httpx.AsyncClient(
            verify=settings.proxy_verify_tls,
            follow_redirects=False,
            timeout=settings.connector_upstream_connect_timeout_seconds,
        ) as client:
            response = await client.request(
                method,
                url,
                headers=payload.headers,
                content=body,
            )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="firewall proxy request failed") from exc
    if len(response.content) > settings.max_proxy_response_bytes:
        raise HTTPException(status_code=502, detail="firewall proxy response is too large")
    return ProxyResponse(
        status_code=response.status_code,
        headers=list(response.headers.multi_items()),
        body_b64=base64.b64encode(response.content).decode("ascii"),
    )


async def _pipe_agent_websocket_to_tcp(
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


async def _pipe_tcp_to_agent_websocket(
    reader: asyncio.StreamReader, websocket: WebSocket
) -> None:
    while chunk := await reader.read(CONNECTOR_CHUNK_SIZE):
        await websocket.send_bytes(chunk)


@app.websocket("/connect")
async def connect_to_wireguard_peer(
    websocket: WebSocket,
    host: Annotated[str, Query()],
    port: Annotated[int, Query()],
):
    expected = settings.wg_agent_token
    if not expected or websocket.headers.get("authorization") != f"Bearer {expected}":
        await websocket.close(code=4401, reason="wireguard agent authorization required")
        return
    try:
        _validate_connect_target(host, port)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, limit=CONNECTOR_CHUNK_SIZE),
            timeout=settings.connector_upstream_connect_timeout_seconds,
        )
    except (OSError, asyncio.TimeoutError, WireGuardError):
        await websocket.close(code=4502, reason="firewall connection failed")
        return

    await websocket.accept()
    tasks = {
        asyncio.create_task(_pipe_agent_websocket_to_tcp(websocket, writer)),
        asyncio.create_task(_pipe_tcp_to_agent_websocket(reader, websocket)),
    }
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except WebSocketDisconnect:
        pass
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        writer.close()
        with contextlib.suppress(OSError, ConnectionError):
            await writer.wait_closed()
