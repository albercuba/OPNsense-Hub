from __future__ import annotations

import ipaddress
import re
import uuid
from http.cookies import SimpleCookie
from typing import Annotated
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from ..audit import log_security_warning, write_audit
from ..database import get_db
from ..deps import current_user, has_company_access
from ..models import Device, User
from ..services.firmware_scheduler import device_webgui_url, tunnel_proxy_host
from ..web import settings
from ..wireguard import get_validated_hub_wireguard_config

router = APIRouter()
PROXY_REQUEST_HEADER_BLOCKLIST = {
    "authorization",
    "connection",
    "content-length",
    "cookie",
    "forwarded",
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
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
    "x-original-url",
    "x-rewrite-url",
    "x-http-method-override",
    "x-method-override",
}
PROXY_RESPONSE_HEADER_BLOCKLIST = {
    "connection",
    "content-encoding",
    "content-length",
    "keep-alive",
    "location",
    "proxy-authenticate",
    "proxy-authorization",
    "set-cookie",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class ProxyResponseTooLarge(RuntimeError):
    pass


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
            morsel["httponly"] = True
            morsel["samesite"] = "Lax"
            if settings.session_secure:
                morsel["secure"] = True
            rewritten.append(morsel.OutputString())
    return rewritten


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


def proxy_rewrite_location(
    location: str, device_id: uuid.UUID, upstream_base: str
) -> str | None:
    path_prefix = proxy_path_prefix(device_id)
    if location.startswith("/") and not location.startswith(path_prefix + "/"):
        return path_prefix + location

    parsed_location = urlparse(location)
    if not parsed_location.scheme and not parsed_location.netloc:
        return location

    parsed_upstream = urlparse(upstream_base)
    upstream_port = parsed_upstream.port or (
        443 if parsed_upstream.scheme == "https" else 80
    )
    location_port = parsed_location.port or (
        443 if parsed_location.scheme == "https" else 80
    )
    same_origin = (
        parsed_location.scheme == parsed_upstream.scheme
        and parsed_location.hostname == parsed_upstream.hostname
        and location_port == upstream_port
    )
    if not same_origin:
        return None

    rewritten_path = parsed_location.path or "/"
    rewritten = path_prefix + rewritten_path
    if parsed_location.query:
        rewritten += f"?{parsed_location.query}"
    if parsed_location.fragment:
        rewritten += f"#{parsed_location.fragment}"
    return rewritten


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
        r'(?P<prefix>\b(?:href|src|action)=(?:["\']))/(?P<path>[^"\']*)',
        lambda match: proxy_rewrite_absolute_path(match, path_prefix),
        text,
    )
    text = re.sub(
        r'(?P<prefix>url\((?:["\']?))/(?P<path>[^)"\']*)',
        lambda match: proxy_rewrite_absolute_path(match, path_prefix),
        text,
    )
    text = re.sub(
        r'(?P<prefix>["\'])/(?P<path>(?!/|proxy/devices/)[^"\']*)',
        lambda match: proxy_rewrite_absolute_path(match, path_prefix),
        text,
    )
    return text.encode("utf-8")


async def read_limited_request_body(request: Request, limit_bytes: int) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > limit_bytes:
                raise HTTPException(
                    status_code=413,
                    detail="proxied request body exceeds the configured size limit",
                )
        except ValueError:
            pass
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit_bytes:
            raise HTTPException(
                status_code=413,
                detail="proxied request body exceeds the configured size limit",
            )
        chunks.append(chunk)
    return b"".join(chunks)


async def read_limited_proxy_response(
    proxied: httpx.Response, limit_bytes: int
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in proxied.aiter_bytes():
        total += len(chunk)
        if total > limit_bytes:
            raise ProxyResponseTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


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
        validate_proxy_device_target(device)
        url = device_webgui_url(device) + path
        if request.url.query:
            url += "?" + request.url.query
    except ValueError as exc:
        write_audit(
            db,
            request,
            "device.proxy.failed",
            user=user,
            company_id=device.company_id,
            device_id=device.id,
        )
        db.commit()
        raise HTTPException(
            status_code=500,
            detail=f"Stored WireGuard tunnel IP is invalid: {device.wg_tunnel_ip}",
        ) from exc
    body = await read_limited_request_body(request, settings.max_proxy_request_bytes)
    try:
        async with httpx.AsyncClient(
            verify=settings.proxy_verify_tls, follow_redirects=False, timeout=30
        ) as client:
            async with client.stream(
                request.method,
                url,
                headers=proxy_request_headers(request, device_id),
                content=body,
            ) as proxied:
                content = await read_limited_proxy_response(
                    proxied, settings.max_proxy_response_bytes
                )
                response_headers = {
                    k: v
                    for k, v in proxied.headers.items()
                    if k.lower() not in PROXY_RESPONSE_HEADER_BLOCKLIST
                }
                if location := proxied.headers.get("location"):
                    rewritten_location = proxy_rewrite_location(
                        location, device_id, device_webgui_url(device)
                    )
                    if rewritten_location is None:
                        raise HTTPException(
                            status_code=502,
                            detail="The proxied OPNsense UI returned a redirect to an unexpected origin",
                        )
                    response_headers["location"] = rewritten_location
                response = Response(
                    content=proxy_rewrite_body(
                        content, proxied.headers.get("content-type", ""), device_id
                    ),
                    status_code=proxied.status_code,
                    headers=response_headers,
                )
                for cookie in proxy_downstream_set_cookie_headers(
                    proxied.headers.get_list("set-cookie"), device_id
                ):
                    response.headers.append("set-cookie", cookie)
                return response
    except HTTPException as exc:
        write_audit(
            db,
            request,
            "device.proxy.failed",
            user=user,
            company_id=device.company_id,
            device_id=device.id,
        )
        db.commit()
        log_security_warning("device.proxy.failed", detail=str(exc.detail))
        raise exc
    except ProxyResponseTooLarge as exc:
        write_audit(
            db,
            request,
            "device.proxy.failed",
            user=user,
            company_id=device.company_id,
            device_id=device.id,
        )
        db.commit()
        log_security_warning(
            "device.proxy.failed",
            detail=f"upstream response exceeded {settings.max_proxy_response_bytes} bytes",
        )
        raise HTTPException(
            status_code=502,
            detail="The proxied OPNsense UI response exceeded the configured size limit",
        ) from exc
    except httpx.RequestError as exc:
        error_detail = str(exc) or repr(exc)
        write_audit(
            db,
            request,
            "device.proxy.failed",
            user=user,
            company_id=device.company_id,
            device_id=device.id,
        )
        db.commit()
        log_security_warning(
            "device.proxy.failed",
            detail=f"{exc.__class__.__name__}: {error_detail}",
        )
        raise HTTPException(
            status_code=502,
            detail=(
                f"Could not reach OPNsense UI at {url}: {exc.__class__.__name__}: {error_detail}. "
                "Verify WireGuard has a recent handshake, the firewall allows Hub tunnel traffic to the "
                "WebGUI port, and the WebGUI listens on the tunnel interface."
            ),
        ) from exc
