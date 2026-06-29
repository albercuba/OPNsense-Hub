from __future__ import annotations

import base64
import hashlib
from typing import Final

from cryptography.fernet import Fernet, InvalidToken

from ..config import get_settings

settings = get_settings()
ENCRYPTED_PREFIX: Final = "enc:v1:"


def _normalized_master_key() -> bytes:
    source = settings.secret_encryption_key or settings.secret_key
    digest = hashlib.sha256(source.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def secret_fernet() -> Fernet:
    return Fernet(_normalized_master_key())


def is_encrypted_secret(value: str | None) -> bool:
    return bool(value and value.startswith(ENCRYPTED_PREFIX))


def encrypt_secret(value: str | None) -> str | None:
    if value is None:
        return None
    if is_encrypted_secret(value):
        return value
    token = secret_fernet().encrypt(value.encode("utf-8")).decode("utf-8")
    return ENCRYPTED_PREFIX + token


def decrypt_secret(value: str | None) -> str | None:
    if value is None:
        return None
    if not is_encrypted_secret(value):
        return value
    token = value[len(ENCRYPTED_PREFIX) :]
    try:
        return secret_fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError("stored secret could not be decrypted") from exc


def store_secret(existing_value: str | None, new_value: str | None) -> str | None:
    if new_value is None:
        return existing_value
    stripped = new_value.strip()
    if not stripped:
        return existing_value
    return encrypt_secret(stripped)
