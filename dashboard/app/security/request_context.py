from __future__ import annotations

import ipaddress
from functools import lru_cache
from urllib.parse import urlparse

from fastapi import HTTPException, Request

from ..config import get_settings

settings = get_settings()


@lru_cache
def allowed_hosts() -> tuple[str, ...]:
    configured = [item.strip().lower() for item in settings.allowed_hosts.split(",")]
    hosts = [item for item in configured if item]
    public_host = (urlparse(settings.public_url).hostname or "").strip().lower()
    if public_host and public_host not in hosts:
        hosts.append(public_host)
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
    if not host:
        return False
    normalized = host.split(":", 1)[0].strip().lower()
    hosts = allowed_hosts()
    if not hosts:
        return True
    if "*" in hosts:
        return True
    return normalized in hosts


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
