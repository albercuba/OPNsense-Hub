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
