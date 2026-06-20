import ipaddress
import os
import re
import subprocess
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import Device

WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")


class WireGuardError(RuntimeError):
    pass


def _run(args: list[str], input_text: str | None = None, timeout: int = 15) -> str:
    try:
        result = subprocess.run(
            args,
            input=input_text,
            text=True,
            capture_output=True,
            check=True,
            timeout=timeout,
        )
        return result.stdout.strip()
    except FileNotFoundError as exc:
        raise WireGuardError(f"required command not found: {args[0]}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        message = stderr if stderr else f"command failed: {args[0]}"
        raise WireGuardError(message) from exc


def validate_public_key(public_key: str) -> None:
    if not WG_KEY_RE.match(public_key):
        raise WireGuardError("invalid WireGuard public key format")


def _paths() -> tuple[Path, Path]:
    settings = get_settings()
    config_path = Path(settings.wg_config_path)
    key_path = Path(settings.wg_server_private_key_path)
    return config_path, key_path


def ensure_server_keypair() -> str:
    """Create/persist the Hub WireGuard server key and return its public key."""
    settings = get_settings()
    if settings.wg_dry_run:
        return settings.wg_server_public_key

    config_path, key_path = _paths()
    key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if key_path.exists():
        private_key = key_path.read_text().strip()
    else:
        private_key = _run(["wg", "genkey"])
        key_path.write_text(private_key + "\n")
        os.chmod(key_path, 0o600)
    public_key = _run(["wg", "pubkey"], input_text=private_key + "\n")
    validate_public_key(public_key)
    config_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    return public_key


def get_server_public_key() -> str:
    settings = get_settings()
    if settings.wg_dry_run:
        return settings.wg_server_public_key
    return ensure_server_keypair()


def render_server_config() -> None:
    settings = get_settings()
    if settings.wg_dry_run:
        return
    config_path, key_path = _paths()
    ensure_server_keypair()
    text = f"""[Interface]
PrivateKey = {key_path.read_text().strip()}
Address = {settings.hub_wg_address}
ListenPort = {settings.hub_wg_listen_port}
SaveConfig = false
"""
    config_path.write_text(text)
    os.chmod(config_path, 0o600)


def interface_exists() -> bool:
    settings = get_settings()
    if settings.wg_dry_run:
        return True
    result = subprocess.run(
        ["wg", "show", settings.wg_interface],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return result.returncode == 0


def ensure_server_interface() -> None:
    """Ensure the Hub WireGuard interface exists and is listening."""
    settings = get_settings()
    if settings.wg_dry_run:
        return
    render_server_config()
    config_path, key_path = _paths()
    if not interface_exists():
        _run(["wg-quick", "up", str(config_path)], timeout=20)
    # Make runtime settings explicit in case the interface already existed.
    _run(
        [
            "wg",
            "set",
            settings.wg_interface,
            "private-key",
            str(key_path),
            "listen-port",
            str(settings.hub_wg_listen_port),
        ]
    )


def sync_existing_peers(db: Session) -> None:
    settings = get_settings()
    if settings.wg_dry_run:
        return
    ensure_server_interface()
    devices = db.scalars(select(Device).where(Device.revoked_at.is_(None))).all()
    for device in devices:
        add_peer(device.wg_public_key, str(device.wg_tunnel_ip))


def bootstrap_wireguard(db: Session) -> None:
    """Fully configure WireGuard and restore peers from the database on app startup."""
    settings = get_settings()
    if settings.wg_dry_run:
        return
    ensure_server_interface()
    sync_existing_peers(db)


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
    ensure_server_interface()
    cmd = [
        "wg",
        "set",
        settings.wg_interface,
        "peer",
        public_key,
        "allowed-ips",
        f"{tunnel_ip}/32",
    ]
    _run(cmd, timeout=10)


def remove_peer(public_key: str) -> None:
    settings = get_settings()
    validate_public_key(public_key)
    if settings.wg_dry_run:
        return
    ensure_server_interface()
    cmd = ["wg", "set", settings.wg_interface, "peer", public_key, "remove"]
    _run(cmd, timeout=10)
