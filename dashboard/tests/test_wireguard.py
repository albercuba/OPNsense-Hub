import importlib.util
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from app.wireguard import (
    WireGuardError,
    next_tunnel_ip,
    peer_allowed_ips,
    validate_hub_wireguard_config,
    validate_public_key,
)
from sqlalchemy.orm import Session


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class FakeDb:
    def __init__(self, tunnel_ips):
        self.tunnel_ips = tunnel_ips

    def execute(self, _statement):
        return FakeResult([(value,) for value in self.tunnel_ips])


def load_connect_module():
    root = Path(__file__).resolve().parents[2]
    connect_path = (
        root
        / "net-mgmt"
        / "os-opnsensehub"
        / "src"
        / "opnsense"
        / "scripts"
        / "OPNsense"
        / "OPNsenseHub"
        / "connect.py"
    )
    spec = importlib.util.spec_from_file_location("opnsensehub_connect", connect_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_validate_public_key_accepts_wireguard_shape():
    validate_public_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")


def test_validate_public_key_rejects_shell_input():
    with pytest.raises(WireGuardError):
        validate_public_key("bad; rm -rf /")


def test_peer_allowed_ips_is_tunnel_ip_only():
    assert peer_allowed_ips("100.96.0.10") == "100.96.0.10/32"


def test_peer_allowed_ips_rejects_network_routes():
    with pytest.raises(ValueError):
        peer_allowed_ips("192.168.1.0/24")


def test_validate_hub_wireguard_config_accepts_valid_overlay():
    validated = validate_hub_wireguard_config("100.96.0.0/16", "100.96.0.1/16")
    assert str(validated.network) == "100.96.0.0/16"
    assert str(validated.hub_interface) == "100.96.0.1/16"


def test_validate_hub_wireguard_config_rejects_broad_or_invalid_values():
    with pytest.raises(WireGuardError):
        validate_hub_wireguard_config("0.0.0.0/0", "100.96.0.1/16")
    with pytest.raises(WireGuardError):
        validate_hub_wireguard_config("10.0.0.0/8", "10.0.0.1/8")
    with pytest.raises(WireGuardError):
        validate_hub_wireguard_config("100.96.0.0/16", "100.97.0.1/16")


def test_next_tunnel_ip_rejects_stored_ip_outside_configured_cidr(monkeypatch):
    monkeypatch.setattr(
        "app.wireguard.get_validated_hub_wireguard_config",
        lambda: SimpleNamespace(
            network=__import__("ipaddress").ip_network("100.96.0.0/30"),
            hub_ip=__import__("ipaddress").ip_address("100.96.0.1"),
        ),
    )
    with pytest.raises(WireGuardError):
        next_tunnel_ip(cast(Session, FakeDb(["192.168.1.10"])))


def test_plugin_validate_wireguard_payload_accepts_only_hub_tunnel_32():
    connect = load_connect_module()
    wg = connect.validate_wireguard_payload(
        {
            "interface_address": "100.96.0.10/32",
            "allowed_ips": "100.96.0.1/32",
            "server_public_key": "key",
            "endpoint": "hub.example.com:51820",
            "persistent_keepalive": "25",
        }
    )
    assert wg["interface_address"] == "100.96.0.10/32"
    assert wg["allowed_ips"] == "100.96.0.1/32"


def test_plugin_validate_wireguard_payload_rejects_broad_allowed_ips():
    connect = load_connect_module()
    with pytest.raises(SystemExit):
        connect.validate_wireguard_payload(
            {
                "interface_address": "100.96.0.10/32",
                "allowed_ips": "100.96.0.0/16",
            }
        )
