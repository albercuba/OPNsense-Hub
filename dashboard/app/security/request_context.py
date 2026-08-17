from __future__ import annotations

import ipaddress
from functools import lru_cache
from urllib.parse import urlparse

from fastapi import HTTPException, Request

from ..config import get_settings

settings = get_settings()


def _normalized_hostname(host: str | None) -> str:
    if not host:
        return ""
    try:
        parsed = urlparse(f"//{host.strip()}")
        _ = parsed.port
    except ValueError:
        return ""
    if parsed.path or parsed.params or parsed.query or parsed.fragment:
        return ""
    return (parsed.hostname or "").strip().lower()


@lru_cache
def proxy_hostname() -> str:
    try:
        return (urlparse(settings.proxy_public_url).hostname or "").strip().lower()
    except ValueError:
        return ""


@lru_cache
def allowed_hosts() -> tuple[str, ...]:
    configured = [item.strip().lower() for item in settings.allowed_hosts.split(",")]
    hosts = [item for item in configured if item]
    for configured_url in (settings.public_url, settings.proxy_public_url):
        try:
            configured_host = (urlparse(configured_url).hostname or "").strip().lower()
        except ValueError:
            configured_host = ""
        if configured_host and configured_host not in hosts:
            hosts.append(configured_host)
    return tuple(hosts)


@lru_cache
def trusted_proxy_networks() -> tuple[ipaddress._BaseNetwork, ...]:
    networks: list[ipaddress._BaseNetwork] = []
    for item in settings.trusted_proxy_cidrs.split(","):
        value = item.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return tuple(networks)


def host_is_allowed(host: str | None) -> bool:
    normalized = _normalized_hostname(host)
    if not normalized:
        return False
    hosts = allowed_hosts()
    if not hosts:
        return True
    if "*" in hosts:
        return True
    return normalized in hosts


def is_proxy_path(path: str) -> bool:
    return path == "/proxy" or path.startswith("/proxy/")


def ensure_host_path_boundary(request: Request) -> None:
    host = _normalized_hostname(request.headers.get("host") or request.url.hostname)
    if host == proxy_hostname() or is_proxy_path(request.url.path):
        raise HTTPException(status_code=404, detail="Not Found")


def ensure_allowed_host(request: Request) -> None:
    host = request.headers.get("host") or request.url.hostname
    if host_is_allowed(host):
        return
    raise HTTPException(status_code=400, detail="host header is not allowed")


def request_ip(request: Request) -> str | None:
    if request.client and request.client.host:
        return request.client.host
    return None


def is_trusted_proxy(host: str | None) -> bool:
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(address in network for network in trusted_proxy_networks())


def client_ip(request: Request) -> str:
    direct_ip = request_ip(request)
    if not direct_ip:
        return "unknown"
    if not is_trusted_proxy(direct_ip):
        return direct_ip

    forwarded = request.headers.get("x-forwarded-for", "")
    forwarded_hops: list[str] = []
    for item in forwarded.split(","):
        candidate = item.strip()
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        forwarded_hops.append(candidate)

    if not forwarded_hops:
        return direct_ip

    chain = forwarded_hops + [direct_ip]
    for candidate in reversed(chain[:-1]):
        if is_trusted_proxy(candidate):
            continue
        return candidate
    return direct_ip
