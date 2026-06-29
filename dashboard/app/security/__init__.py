from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets as py_secrets
from datetime import datetime, timezone


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


def password_is_strong_enough(password: str, min_length: int = 12) -> bool:
    if len(password) < min_length:
        return False
    has_alpha = any(ch.isalpha() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    return has_alpha and has_digit
