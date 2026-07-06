import importlib.util
import json
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from app.wireguard import (
    WireGuardError,
    client_allowed_ips,
    next_tunnel_ip,
    parse_wg_show_dump,
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


def load_heartbeat_module():
    return load_plugin_module("heartbeat.py", "opnsensehub_heartbeat")


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


def test_parse_wg_show_dump_reads_runtime_peer_data():
    output = (
        "private\tpublic\t51820\tmark\n"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t(off)\t198.51.100.10:51820\t100.96.0.10/32\t1751712000\t1234\t5678\t25\n"
    )

    peers = parse_wg_show_dump(output)

    assert len(peers) == 1
    assert peers[0].public_key == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    assert peers[0].endpoint == "198.51.100.10:51820"
    assert peers[0].allowed_ips == ["100.96.0.10/32"]
    assert peers[0].rx_bytes == 1234
    assert peers[0].tx_bytes == 5678
    assert peers[0].persistent_keepalive == 25
    assert peers[0].last_handshake_at is not None


def test_parse_wg_show_dump_rejects_short_rows():
    with pytest.raises(WireGuardError):
        parse_wg_show_dump("private\tpublic\t51820\tmark\nshort\trow\n")


def test_parse_wg_show_dump_accepts_off_keepalive():
    output = (
        "private\tpublic\t51820\tmark\n"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t(off)\t198.51.100.10:51820\t100.96.0.10/32\t1751712000\t1234\t5678\toff\n"
    )

    peers = parse_wg_show_dump(output)

    assert len(peers) == 1
    assert peers[0].persistent_keepalive == 0


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


def test_plugin_heartbeat_does_not_remove_local_state_on_unauthorized(
    monkeypatch, tmp_path, capsys
):
    heartbeat = load_heartbeat_module()
    state_file = tmp_path / "state.json"
    state_file.write_text("{}")
    state = {
        "device_id": "device-1",
        "device_token": "token",
        "hub_url": "https://hub.example.com",
    }
    saved_states = []
    cleanup_called = False

    def fake_send_heartbeat(_state, _payload):
        raise urllib.error.HTTPError(
            url="https://hub.example.com/api/v1/devices/device-1/heartbeat",
            code=401,
            msg="Unauthorized",
            hdrs=None,
            fp=None,
        )

    def fake_remove_local_artifacts(reason=None):
        nonlocal cleanup_called
        cleanup_called = True
        return {"reason": reason}

    monkeypatch.setattr(heartbeat, "STATE_FILE", state_file)
    monkeypatch.setattr(heartbeat, "load_state", lambda: state.copy())
    monkeypatch.setattr(
        heartbeat, "save_state", lambda value: saved_states.append(value.copy())
    )
    monkeypatch.setattr(heartbeat, "send_heartbeat", fake_send_heartbeat)
    monkeypatch.setattr(
        heartbeat, "remove_local_artifacts", fake_remove_local_artifacts
    )

    with pytest.raises(SystemExit) as exc_info:
        heartbeat.main()

    assert exc_info.value.code == 1
    assert cleanup_called is False
    assert saved_states[-1]["last_error"] == "heartbeat failed with HTTP 401"
    output = json.loads(capsys.readouterr().out.strip())
    assert output == {
        "status": "error",
        "message": "heartbeat failed with HTTP 401",
    }


def test_plugin_heartbeat_removes_local_state_only_on_revocation(
    monkeypatch, tmp_path, capsys
):
    heartbeat = load_heartbeat_module()
    state_file = tmp_path / "state.json"
    state_file.write_text("{}")
    state = {
        "device_id": "device-1",
        "device_token": "token",
        "hub_url": "https://hub.example.com",
    }
    saved_states = []
    cleanup_reasons = []

    def fake_send_heartbeat(_state, _payload):
        raise urllib.error.HTTPError(
            url="https://hub.example.com/api/v1/devices/device-1/heartbeat",
            code=410,
            msg="Gone",
            hdrs=None,
            fp=None,
        )

    def fake_remove_local_artifacts(reason=None):
        cleanup_reasons.append(reason)
        return {"status": "removed", "reason": reason, "device_id": "device-1"}

    monkeypatch.setattr(heartbeat, "STATE_FILE", state_file)
    monkeypatch.setattr(heartbeat, "load_state", lambda: state.copy())
    monkeypatch.setattr(
        heartbeat, "save_state", lambda value: saved_states.append(value.copy())
    )
    monkeypatch.setattr(heartbeat, "send_heartbeat", fake_send_heartbeat)
    monkeypatch.setattr(
        heartbeat, "remove_local_artifacts", fake_remove_local_artifacts
    )

    with pytest.raises(SystemExit) as exc_info:
        heartbeat.main()

    assert exc_info.value.code == 1
    assert cleanup_reasons == ["heartbeat failed with HTTP 410"]
    assert saved_states[-1]["last_error"] == "heartbeat failed with HTTP 410"
    output = json.loads(capsys.readouterr().out.strip())
    assert output["status"] == "revoked"
    assert output["reason"] == "heartbeat failed with HTTP 410"
    assert output["message"] == (
        "Hub revoked this device; removed local OPNsense Hub tunnel and state"
    )
