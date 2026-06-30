from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets as py_secrets
import struct
from datetime import datetime, timezone
from urllib.parse import quote, urlencode


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def random_token(bytes_len: int = 32) -> str:
    return py_secrets.token_urlsafe(bytes_len)


def random_otp() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "-".join(
        "".join(py_secrets.choice(alphabet) for _ in range(4)) for _ in range(2)
    )


def hash_secret(secret: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 210_000)
    return (
        "pbkdf2_sha256$210000$"
        + base64.b64encode(salt).decode()
        + "$"
        + base64.b64encode(digest).decode()
    )


def verify_secret(secret: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt_b64, digest_b64 = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac(
            "sha256", secret.encode("utf-8"), salt, int(rounds)
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def hash_session_token(secret_key: str, token: str) -> str:
    return hmac.new(
        secret_key.encode("utf-8"), token.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def generate_totp_secret(byte_length: int = 20) -> str:
    return base64.b32encode(os.urandom(byte_length)).decode("ascii").rstrip("=")


def normalize_totp_secret(secret: str) -> str:
    return "".join(ch for ch in secret.upper() if ch.isalnum())


def normalize_totp_code(code: str) -> str:
    return "".join(ch for ch in code if ch.isdigit())


def _totp_secret_bytes(secret: str) -> bytes:
    normalized = normalize_totp_secret(secret)
    if not normalized:
        raise ValueError("TOTP secret is required")
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    return base64.b32decode(normalized + padding, casefold=True)


def _totp_code_for_counter(secret: str, counter: int, digits: int = 6) -> str:
    digest = hmac.new(
        _totp_secret_bytes(secret), struct.pack(">Q", counter), hashlib.sha1
    ).digest()
    offset = digest[-1] & 0x0F
    binary = (
        ((digest[offset] & 0x7F) << 24)
        | (digest[offset + 1] << 16)
        | (digest[offset + 2] << 8)
        | digest[offset + 3]
    )
    return str(binary % (10**digits)).zfill(digits)


def totp_code(secret: str, for_time: int | None = None, period: int = 30) -> str:
    timestamp = utc_now().timestamp() if for_time is None else for_time
    counter = int(timestamp // period)
    return _totp_code_for_counter(secret, counter)


def verify_totp_code(
    secret: str,
    code: str,
    *,
    for_time: int | None = None,
    period: int = 30,
    window: int = 1,
) -> bool:
    normalized = normalize_totp_code(code)
    if len(normalized) != 6:
        return False
    timestamp = utc_now().timestamp() if for_time is None else for_time
    counter = int(timestamp // period)
    try:
        return any(
            hmac.compare_digest(
                _totp_code_for_counter(secret, counter + offset), normalized
            )
            for offset in range(-window, window + 1)
        )
    except ValueError:
        return False


def totp_provisioning_uri(
    secret: str, account_name: str, issuer: str = "OPNsense Hub"
) -> str:
    label = quote(f"{issuer}:{account_name}")
    query = urlencode(
        {
            "secret": normalize_totp_secret(secret),
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
        }
    )
    return f"otpauth://totp/{label}?{query}"


def password_is_strong_enough(password: str, min_length: int = 12) -> bool:
    if len(password) < min_length:
        return False
    has_alpha = any(ch.isalpha() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    return has_alpha and has_digit
