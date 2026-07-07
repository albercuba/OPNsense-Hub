from uuid import uuid4

from app.models import Device
from app.routers.proxy import proxy_rewrite_location, validate_proxy_device_target
from app.security import (
    generate_totp_secret,
    hash_secret,
    hash_session_token,
    password_is_strong_enough,
    random_otp,
    totp_code,
    totp_provisioning_uri,
    verify_secret,
    verify_totp_code,
)
from app.security.csrf import should_enforce_csrf
from app.security.request_context import (
    allowed_hosts,
    client_ip,
    host_is_allowed,
    trusted_proxy_networks,
)
from app.web import settings
from starlette.requests import Request


def test_hash_secret_roundtrip():
    encoded = hash_secret("secret-value")
    assert encoded != "secret-value"
    assert verify_secret("secret-value", encoded)
    assert not verify_secret("wrong", encoded)


def test_random_otp_shape():
    otp = random_otp()
    assert len(otp) == 9
    assert otp[4] == "-"


def test_hash_session_token_is_deterministic_for_same_secret():
    token_hash = hash_session_token("secret-key", "session-token")
    assert token_hash == hash_session_token("secret-key", "session-token")
    assert token_hash != hash_session_token("different-secret", "session-token")


def test_password_strength_check_requires_length_letters_and_numbers():
    assert password_is_strong_enough("StrongPassword123")
    assert not password_is_strong_enough("short")
    assert not password_is_strong_enough("allletterslong")


def test_totp_secret_and_uri_are_generated_in_expected_format():
    secret = generate_totp_secret()
    assert len(secret) >= 32
    assert secret.isalnum()
    assert totp_provisioning_uri(secret, "user@example.com").startswith(
        "otpauth://totp/"
    )


def test_totp_code_verifies_with_current_and_adjacent_window():
    secret = "JBSWY3DPEHPK3PXP"
    code = totp_code(secret, for_time=1700000000)
    assert verify_totp_code(secret, code, for_time=1700000000)
    assert verify_totp_code(secret, code, for_time=1700000029)
    assert not verify_totp_code(secret, code, for_time=1700000065)


def test_host_allowlist_blocks_unknown_hosts():
    assert host_is_allowed("localhost:8083")
    assert host_is_allowed("testserver")
    assert not host_is_allowed("evil.example.com")


def test_client_ip_only_trusts_forwarded_header_from_trusted_proxy(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", "127.0.0.1/32")
    trusted_proxy_networks.cache_clear()
    allowed_hosts.cache_clear()
    proxied_request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-forwarded-for", b"203.0.113.10")],
            "client": ("127.0.0.1", 12345),
        }
    )
    direct_request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-forwarded-for", b"203.0.113.10")],
            "client": ("198.51.100.4", 12345),
        }
    )

    assert client_ip(proxied_request) == "203.0.113.10"
    assert client_ip(direct_request) == "198.51.100.4"
    trusted_proxy_networks.cache_clear()
    allowed_hosts.cache_clear()


def test_client_ip_uses_last_untrusted_hop_before_trusted_proxy_chain(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", "127.0.0.1/32,10.0.0.0/8")
    trusted_proxy_networks.cache_clear()
    allowed_hosts.cache_clear()
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-forwarded-for", b"198.51.100.99, 203.0.113.10, 10.0.0.2")],
            "client": ("127.0.0.1", 12345),
        }
    )

    assert client_ip(request) == "203.0.113.10"
    trusted_proxy_networks.cache_clear()
    allowed_hosts.cache_clear()


def test_auth_microsoft_post_is_now_subject_to_csrf():
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/auth/microsoft",
            "headers": [],
            "client": ("127.0.0.1", 12345),
        }
    )

    assert should_enforce_csrf(request) is True


def test_proxy_rewrite_location_rejects_off_origin_redirects():
    assert (
        proxy_rewrite_location(
            "https://evil.example.com/admin",
            uuid4(),
            "https://100.96.0.10:443/",
        )
        is None
    )


def test_validate_proxy_device_target_rejects_ips_outside_wireguard_overlay():
    device = Device(
        company_id=None,
        hostname="fw-1",
        wg_public_key="A" * 43 + "=",
        wg_tunnel_ip="127.0.0.1",
        device_token_hash="hash",
    )

    try:
        validate_proxy_device_target(device)
    except ValueError as exc:
        assert "outside HUB_WG_CIDR" in str(exc)
    else:
        raise AssertionError("expected invalid proxy target to be rejected")
