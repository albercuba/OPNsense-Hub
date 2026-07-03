import importlib.util
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from app.wireguard import (
    WireGuardError,
    client_allowed_ips,
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


def load_plugin_module(filename, module_name):
    root = Path(__file__).resolve().parents[2]
    module_path = (
        root
        / "net-mgmt"
        / "os-opnsensehub"
        / "src"
        / "opnsense"
        / "scripts"
        / "OPNsense"
        / "OPNsenseHub"
        / filename
    )
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_connect_module():
    return load_plugin_module("connect.py", "opnsensehub_connect")


def load_firmware_status_module():
    return load_plugin_module("firmware_status.py", "opnsensehub_firmware_status")


def test_validate_public_key_accepts_wireguard_shape():
    validate_public_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")


def test_validate_public_key_rejects_shell_input():
    with pytest.raises(WireGuardError):
        validate_public_key("bad; rm -rf /")


def test_peer_allowed_ips_is_tunnel_ip_only():
    assert peer_allowed_ips("100.96.0.10") == "100.96.0.10/32"
    assert "/24" not in peer_allowed_ips("100.96.0.10")
    assert "/16" not in peer_allowed_ips("100.96.0.10")


def test_client_allowed_ips_is_hub_tunnel_only(monkeypatch):
    monkeypatch.setattr(
        "app.wireguard.get_validated_hub_wireguard_config",
        lambda: SimpleNamespace(
            hub_ip=__import__("ipaddress").ip_address("100.96.0.1")
        ),
    )
    assert client_allowed_ips() == "100.96.0.1/32"
    assert "/24" not in client_allowed_ips()
    assert "/16" not in client_allowed_ips()


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


def test_plugin_license_metadata_marks_business_when_license_present(monkeypatch):
    connect = load_connect_module()
    monkeypatch.setattr(
        connect,
        "firmware_product",
        lambda: {"product_license": {"valid_to": "2026-12-31"}},
    )

    metadata = connect.license_metadata()

    assert metadata == {
        "license_type": "Business",
        "license_expires_at": "2026-12-31",
    }


def test_plugin_license_metadata_defaults_to_community_without_license(monkeypatch):
    connect = load_connect_module()
    monkeypatch.setattr(connect, "firmware_product", lambda: {})

    metadata = connect.license_metadata()

    assert metadata == {
        "license_type": "Community",
        "license_expires_at": None,
    }


def test_plugin_firmware_parser_maps_up_to_date_payload():
    firmware_status = load_firmware_status_module()

    parsed = firmware_status.parse_firmware_product(
        {
            "product_version": "25.7.11",
            "product_latest": "25.7.11",
            "all_packages": [],
            "status_msg": "System is up to date",
        },
        now=__import__("datetime").datetime(
            2026, 6, 25, 23, 3, tzinfo=__import__("datetime").timezone.utc
        ),
    )

    assert parsed["status"] == "none"
    assert parsed["update_available"] is False
    assert parsed["current_version"] == "25.7.11"
    assert parsed["available_version"] == "25.7.11"


def test_plugin_firmware_parser_maps_update_payload():
    firmware_status = load_firmware_status_module()

    parsed = firmware_status.parse_firmware_product(
        {
            "product_version": "25.7.10",
            "product_latest": "25.7.11",
            "all_packages": [
                {"name": "opnsense", "new_version": "25.7.11"},
                {"name": "php", "new_version": "8.3.20"},
            ],
            "status_msg": "There are 2 updates available.",
        }
    )

    assert parsed["status"] == "update"
    assert parsed["update_available"] is True
    assert parsed["update_type"] == "update"
    assert parsed["update_count"] == 2


def test_plugin_firmware_parser_maps_upgrade_payload():
    firmware_status = load_firmware_status_module()

    parsed = firmware_status.parse_firmware_product(
        {
            "product_version": "25.7.11",
            "upgrade_major_version": "26.1",
            "upgrade_sets": [{"name": "26.1", "new_version": "26.1"}],
            "status_msg": "A major upgrade is available.",
        }
    )

    assert parsed["status"] == "upgrade"
    assert parsed["update_available"] is True
    assert parsed["update_type"] == "upgrade"
    assert parsed["available_version"] == "26.1"


def test_plugin_firmware_parser_maps_error_payload():
    firmware_status = load_firmware_status_module()

    parsed = firmware_status.parse_firmware_product(
        {
            "status": "error",
            "message": "firmware probe failed",
            "product_version": "25.7.11",
        }
    )

    assert parsed["status"] == "error"
    assert parsed["update_available"] is False
    assert parsed["message"] == "firmware probe failed"
