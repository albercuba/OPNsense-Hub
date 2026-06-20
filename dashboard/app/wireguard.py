import ipaddress
import re
import subprocess

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import Device

WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")


class WireGuardError(RuntimeError):
    pass


def validate_public_key(public_key: str) -> None:
    if not WG_KEY_RE.match(public_key):
        raise WireGuardError("invalid WireGuard public key format")


def next_tunnel_ip(db: Session) -> str:
    settings = get_settings()
    network = ipaddress.ip_network(settings.hub_wg_cidr, strict=False)
    used = {str(row[0]) for row in db.execute(select(Device.wg_tunnel_ip)).all()}
    hub_ip = str(ipaddress.ip_interface(settings.hub_wg_address).ip)
    used.add(hub_ip)
    for ip in network.hosts():
        value = str(ip)
        if value not in used:
            return value
    raise WireGuardError("no available WireGuard tunnel IPs")


def add_peer(public_key: str, tunnel_ip: str) -> None:
    settings = get_settings()
    validate_public_key(public_key)
    ipaddress.ip_address(tunnel_ip)
    if settings.wg_dry_run:
        return
    cmd = [
        "wg",
        "set",
        settings.wg_interface,
        "peer",
        public_key,
        "allowed-ips",
        f"{tunnel_ip}/32",
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10)
    except subprocess.CalledProcessError as exc:
        raise WireGuardError("failed to add WireGuard peer") from exc


def remove_peer(public_key: str) -> None:
    settings = get_settings()
    validate_public_key(public_key)
    if settings.wg_dry_run:
        return
    cmd = ["wg", "set", settings.wg_interface, "peer", public_key, "remove"]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10)
    except subprocess.CalledProcessError as exc:
        raise WireGuardError("failed to remove WireGuard peer") from exc
