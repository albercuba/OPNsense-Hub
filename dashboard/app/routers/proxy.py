from __future__ import annotations

import ipaddress
import re
import uuid
from http.cookies import SimpleCookie
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..database import get_db
from ..deps import current_user, has_company_access
from ..models import Device, User
from ..services.firmware_scheduler import device_webgui_url
from ..web import settings

router = APIRouter()
PROXY_REQUEST_HEADER_BLOCKLIST = {
    "connection",
    "content-length",
    "cookie",
    "host",
    "keep-alive",
    "origin",
    "proxy-authenticate",
    "proxy-authorization",
    "referer",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def proxy_cookie_prefix(device_id: uuid.UUID) -> str:
    return f"opnhub_{device_id.hex}_"


def proxy_path_prefix(device_id: uuid.UUID) -> str:
    return f"/proxy/devices/{device_id}"


def proxy_upstream_cookie_header(request: Request, device_id: uuid.UUID) -> str:
    prefix = proxy_cookie_prefix(device_id)
    upstream_cookies = []
    for name, value in request.cookies.items():
        if name.startswith(prefix):
            upstream_cookies.append(f"{name[len(prefix) :]}={value}")
    return "; ".join(upstream_cookies)


def proxy_request_headers(request: Request, device_id: uuid.UUID) -> dict[str, str]:
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in PROXY_REQUEST_HEADER_BLOCKLIST
    }
    cookie_header = proxy_upstream_cookie_header(request, device_id)
    if cookie_header:
        headers["cookie"] = cookie_header
    return headers


def proxy_downstream_set_cookie_headers(
    set_cookie_headers: list[str], device_id: uuid.UUID
) -> list[str]:
    rewritten = []
    prefix = proxy_cookie_prefix(device_id)
    path_prefix = proxy_path_prefix(device_id)
    for header in set_cookie_headers:
        cookies = SimpleCookie()
        cookies.load(header)
        for name, morsel in cookies.items():
            morsel.set(prefix + name, morsel.value, morsel.coded_value)
            morsel["path"] = path_prefix
            morsel["domain"] = ""
            rewritten.append(morsel.OutputString())
    return rewritten


def proxy_rewrite_location(
    location: str, device_id: uuid.UUID, upstream_base: str
) -> str:
    path_prefix = proxy_path_prefix(device_id)
    if location.startswith(upstream_base):
        return path_prefix + "/" + location.removeprefix(upstream_base).lstrip("/")
    if location.startswith("/") and not location.startswith(path_prefix + "/"):
        return path_prefix + location
    return location


def proxy_rewrite_absolute_path(match: re.Match[str], path_prefix: str) -> str:
    prefix = match.group("prefix")
    path = match.group("path")
    if path.startswith(("/", "proxy/devices/")):
        return match.group(0)
    return f"{prefix}{path_prefix}/{path}"


def proxy_rewrite_body(
    content: bytes, content_type: str, device_id: uuid.UUID
) -> bytes:
    if not any(
        kind in content_type.lower() for kind in ("text/html", "text/css", "javascript")
    ):
        return content
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return content
    path_prefix = proxy_path_prefix(device_id)
    text = re.sub(
        r'(?P<prefix>\b(?:href|src|action)=(["\']))/(?P<path>[^"\']*)',
        lambda match: proxy_rewrite_absolute_path(match, path_prefix),
        text,
    )
    text = re.sub(
        r'(?P<prefix>url\((["\']?))/(?P<path>[^)"\']*)',
        lambda match: proxy_rewrite_absolute_path(match, path_prefix),
        text,
    )
    text = re.sub(
        r'(?P<prefix>["\'])/(?P<path>(?!/|proxy/devices/)[^"\']*)',
        lambda match: proxy_rewrite_absolute_path(match, path_prefix),
        text,
    )
    return text.encode("utf-8")


@router.api_route(
    "/proxy/devices/{device_id}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
async def proxy_device(
    request: Request,
    device_id: uuid.UUID,
    path: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = db.get(Device, device_id)
    if (
        not device
        or device.revoked_at
        or not has_company_access(db, user, device.company_id)
    ):
        raise HTTPException(status_code=404)
    if request.method == "GET" and path == "":
        write_audit(
            db,
            request,
            "device.proxy.open",
            user=user,
            company_id=device.company_id,
            device_id=device.id,
        )
        db.commit()
    try:
        url = device_webgui_url(device) + path
        if request.url.query:
            url += "?" + request.url.query
    except ValueError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Stored WireGuard tunnel IP is invalid: {device.wg_tunnel_ip}",
        ) from exc
    try:
        async with httpx.AsyncClient(
            verify=settings.proxy_verify_tls, follow_redirects=False, timeout=30
        ) as client:
            proxied = await client.request(
                request.method,
                url,
                headers=proxy_request_headers(request, device_id),
                content=await request.body(),
            )
    except httpx.RequestError as exc:
        error_detail = str(exc) or repr(exc)
        raise HTTPException(
            status_code=502,
            detail=(
                f"Could not reach OPNsense UI at {url}: {exc.__class__.__name__}: {error_detail}. Verify WireGuard has a recent handshake, the firewall allows Hub tunnel traffic to the WebGUI port, and the WebGUI listens on the tunnel interface."
            ),
        ) from exc
    response_headers = {
        k: v
        for k, v in proxied.headers.items()
        if k.lower()
        not in {
            "content-encoding",
            "content-length",
            "connection",
            "location",
            "set-cookie",
            "transfer-encoding",
        }
    }
    if location := proxied.headers.get("location"):
        response_headers["location"] = proxy_rewrite_location(
            location, device_id, device_webgui_url(device)
        )
    response = Response(
        content=proxy_rewrite_body(
            proxied.content, proxied.headers.get("content-type", ""), device_id
        ),
        status_code=proxied.status_code,
        headers=response_headers,
    )
    for cookie in proxy_downstream_set_cookie_headers(
        proxied.headers.get_list("set-cookie"), device_id
    ):
        response.headers.append("set-cookie", cookie)
    return response
