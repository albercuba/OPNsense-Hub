import ipaddress
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import Device

WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")


class WireGuardError(RuntimeError):
    pass


@dataclass(frozen=True)
class ValidatedWireGuardConfig:
    network: ipaddress.IPv4Network
    hub_interface: ipaddress.IPv4Interface

    @property
    def hub_ip(self) -> ipaddress.IPv4Address:
        return self.hub_interface.ip


@dataclass(frozen=True)
class RuntimeWireGuardPeer:
    public_key: str
    preshared_key: str
    endpoint: str | None
    allowed_ips: list[str]
    last_handshake_at: datetime | None
    rx_bytes: int
    tx_bytes: int
    persistent_keepalive: int


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


def validate_hub_wireguard_config(
    hub_wg_cidr: str, hub_wg_address: str, allow_broad_wg_cidr: bool = False
) -> ValidatedWireGuardConfig:
    try:
        network = ipaddress.ip_network(hub_wg_cidr, strict=False)
    except ValueError as exc:
        raise WireGuardError(f"invalid HUB_WG_CIDR: {exc}") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise WireGuardError("HUB_WG_CIDR must be an IPv4 network")
    if network.prefixlen == 0:
        raise WireGuardError("HUB_WG_CIDR must not be 0.0.0.0/0")
    if network.prefixlen < 12 and not allow_broad_wg_cidr:
        raise WireGuardError(
            "HUB_WG_CIDR is too broad for a management overlay; use /12 or narrower or set ALLOW_BROAD_WG_CIDR=true"
        )

    try:
        hub_interface = ipaddress.ip_interface(hub_wg_address)
    except ValueError as exc:
        raise WireGuardError(f"invalid HUB_WG_ADDRESS: {exc}") from exc
    if not isinstance(hub_interface, ipaddress.IPv4Interface):
        raise WireGuardError("HUB_WG_ADDRESS must be an IPv4 interface")
    if hub_interface.ip not in network:
        raise WireGuardError("HUB_WG_ADDRESS must be inside HUB_WG_CIDR")
    if hub_interface.ip == network.network_address:
        raise WireGuardError("HUB_WG_ADDRESS must not be the network address")
    if hub_interface.ip == network.broadcast_address:
        raise WireGuardError("HUB_WG_ADDRESS must not be the broadcast address")
    return ValidatedWireGuardConfig(network=network, hub_interface=hub_interface)


def get_validated_hub_wireguard_config() -> ValidatedWireGuardConfig:
    settings = get_settings()
    return validate_hub_wireguard_config(
        settings.hub_wg_cidr,
        settings.hub_wg_address,
        allow_broad_wg_cidr=settings.allow_broad_wg_cidr,
    )


def _paths() -> tuple[Path, Path]:
    settings = get_settings()
    config_path = Path(settings.wg_config_path)
    key_path = Path(settings.wg_server_private_key_path)
    return config_path, key_path


def ensure_server_keypair() -> str:
    """Create/persist the Hub WireGuard server key and return its public key."""
    settings = get_settings()
    get_validated_hub_wireguard_config()
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
    validated = get_validated_hub_wireguard_config()
    if settings.wg_dry_run:
        return
    config_path, key_path = _paths()
    ensure_server_keypair()
    text = f"""[Interface]
PrivateKey = {key_path.read_text().strip()}
Address = {validated.hub_interface}
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
    get_validated_hub_wireguard_config()
    if settings.wg_dry_run:
        return
    ensure_server_interface()
    sync_existing_peers(db)


def peer_allowed_ips(tunnel_ip: str) -> str:
    """Return the only route the Hub installs for a firewall: its tunnel /32.

    Customer LAN subnets are intentionally never included. OPNsense Hub is only
    for reaching the firewall web UI over its unique tunnel IP, not for routing
    into customer networks where overlapping LANs are common.
    """
    ip = ipaddress.ip_address(tunnel_ip)
    return f"{ip}/32"


def client_allowed_ips() -> str:
    """Return the only route the firewall installs for the Hub: Hub tunnel /32."""
    validated = get_validated_hub_wireguard_config()
    return f"{validated.hub_ip}/32"


def next_tunnel_ip(db: Session) -> str:
    validated = get_validated_hub_wireguard_config()
    used = {str(validated.hub_ip)}
    for row in db.execute(select(Device.wg_tunnel_ip)).all():
        value = str(row[0])
        try:
            ip = ipaddress.ip_address(value)
        except ValueError as exc:
            raise WireGuardError(
                f"stored device tunnel IP is invalid: {value}"
            ) from exc
        if not isinstance(ip, ipaddress.IPv4Address):
            raise WireGuardError(
                f"stored device tunnel IP is not IPv4 and cannot be allocated safely: {value}"
            )
        if ip not in validated.network:
            raise WireGuardError(
                f"stored device tunnel IP {value} is outside HUB_WG_CIDR {validated.network}"
            )
        if ip in {
            validated.network.network_address,
            validated.network.broadcast_address,
        }:
            raise WireGuardError(
                f"stored device tunnel IP {value} is not a usable host address inside HUB_WG_CIDR"
            )
        used.add(str(ip))
    for ip in validated.network.hosts():
        value = str(ip)
        if value not in used:
            return value
    raise WireGuardError("no available WireGuard tunnel IPs")


def add_peer(public_key: str, tunnel_ip: str) -> None:
    settings = get_settings()
    validated = get_validated_hub_wireguard_config()
    validate_public_key(public_key)
    ip = ipaddress.ip_address(tunnel_ip)
    if not isinstance(ip, ipaddress.IPv4Address):
        raise WireGuardError("tunnel_ip must be IPv4")
    if ip not in validated.network:
        raise WireGuardError(
            f"tunnel_ip {ip} is outside HUB_WG_CIDR {validated.network}"
        )
    if ip == validated.hub_ip:
        raise WireGuardError("tunnel_ip must not equal HUB_WG_ADDRESS")
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
        peer_allowed_ips(str(ip)),
    ]
    _run(cmd, timeout=10)


def _parse_unix_timestamp(value: str) -> datetime | None:
    if not value or value in {"0", "off"}:
        return None
    try:
        timestamp = int(value)
    except ValueError as exc:
        raise WireGuardError(
            f"invalid handshake timestamp in wg output: {value}"
        ) from exc
    if timestamp <= 0:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def _parse_wg_integer(value: str, *, field_name: str) -> int:
    normalized = value.strip().lower()
    if not normalized or normalized == "off":
        return 0
    try:
        return int(normalized)
    except ValueError as exc:
        raise WireGuardError(
            f"invalid {field_name} value in wg output: {value}"
        ) from exc


def parse_wg_show_dump(output: str) -> list[RuntimeWireGuardPeer]:
    peers: list[RuntimeWireGuardPeer] = []
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            raise WireGuardError("unexpected wg show dump output")
        allowed_ips = [item.strip() for item in fields[3].split(",") if item.strip()]
        endpoint = fields[2].strip() or None
        peers.append(
            RuntimeWireGuardPeer(
                public_key=fields[0].strip(),
                preshared_key=fields[1].strip(),
                endpoint=endpoint,
                allowed_ips=allowed_ips,
                last_handshake_at=_parse_unix_timestamp(fields[4].strip()),
                rx_bytes=_parse_wg_integer(fields[5], field_name="rx bytes"),
                tx_bytes=_parse_wg_integer(fields[6], field_name="tx bytes"),
                persistent_keepalive=_parse_wg_integer(
                    fields[7], field_name="persistent keepalive"
                ),
            )
        )
    return peers


def get_runtime_peers() -> list[RuntimeWireGuardPeer]:
    settings = get_settings()
    if settings.wg_dry_run:
        return []
    output = _run(["wg", "show", settings.wg_interface, "dump"], timeout=10)
    return parse_wg_show_dump(output)


def remove_peer(public_key: str) -> None:
    settings = get_settings()
    validate_public_key(public_key)
    if settings.wg_dry_run:
        return
    ensure_server_interface()
    cmd = ["wg", "set", settings.wg_interface, "peer", public_key, "remove"]
    _run(cmd, timeout=10)
