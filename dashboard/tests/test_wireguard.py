import pytest
from app.wireguard import WireGuardError, peer_allowed_ips, validate_public_key


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
