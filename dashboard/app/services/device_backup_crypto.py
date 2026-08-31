from __future__ import annotations

import base64
import binascii
import json
import re
import uuid
from datetime import datetime
from typing import Final

from fastapi import HTTPException

ENCRYPTED_DEVICE_BACKUP_FORMAT: Final = "opnsense-config-encrypted-v1"
PLAINTEXT_DEVICE_BACKUP_FORMAT: Final = "opnsense-config-plaintext-v1"
ENCRYPTED_DEVICE_BACKUP_VERSION: Final = 1
PLAINTEXT_DEVICE_BACKUP_VERSION: Final = 1
ENCRYPTED_DEVICE_BACKUP_CIPHER: Final = "AES-256-CBC+HMAC-SHA256"
ENCRYPTED_DEVICE_BACKUP_KDF: Final = "PBKDF2-HMAC-SHA256"
ENCRYPTED_DEVICE_BACKUP_ITERATIONS: Final = 200_000
ENCRYPTED_DEVICE_BACKUP_MAX_CIPHERTEXT_BYTES: Final = 2_100_000
ENCRYPTED_DEVICE_BACKUP_MAX_ENCODED_CIPHERTEXT_CHARS: Final = 2_800_000
ENCRYPTED_DEVICE_BACKUP_MAX_ENVELOPE_CHARS: Final = 2_900_000
ENCRYPTED_DEVICE_BACKUP_MAX_REQUEST_BYTES: Final = 2_910_000
_ENCRYPTED_ENVELOPE_FIELDS: Final = {
    "format",
    "version",
    "cipher",
    "kdf",
    "iterations",
    "key_id",
    "device_id",
    "source_hostname",
    "captured_at",
    "ciphertext",
    "mac",
}
_PLAINTEXT_ENVELOPE_FIELDS: Final = {
    "format",
    "version",
    "device_id",
    "source_hostname",
    "captured_at",
    "content",
}
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^[0-9a-f]{24}$")


def _invalid_device_backup(detail: str) -> HTTPException:
    return HTTPException(status_code=400, detail=detail)


def validate_encrypted_device_backup(
    value: object, *, expected_device_id: uuid.UUID
) -> str:
    if not isinstance(value, dict) or set(value) != _ENCRYPTED_ENVELOPE_FIELDS:
        raise _invalid_device_backup("encrypted backup envelope fields are invalid")
    if value.get("format") != ENCRYPTED_DEVICE_BACKUP_FORMAT:
        raise _invalid_device_backup("encrypted backup format is not supported")
    version = value.get("version")
    iterations = value.get("iterations")
    if not isinstance(version, int) or isinstance(version, bool):
        raise _invalid_device_backup("encrypted backup version is invalid")
    if not isinstance(iterations, int) or isinstance(iterations, bool):
        raise _invalid_device_backup("encrypted backup KDF parameters are invalid")
    if (
        version != ENCRYPTED_DEVICE_BACKUP_VERSION
        or value.get("cipher") != ENCRYPTED_DEVICE_BACKUP_CIPHER
        or value.get("kdf") != ENCRYPTED_DEVICE_BACKUP_KDF
        or iterations != ENCRYPTED_DEVICE_BACKUP_ITERATIONS
    ):
        raise _invalid_device_backup("encrypted backup algorithms are not supported")

    try:
        source_device_id = uuid.UUID(str(value.get("device_id")))
    except (ValueError, AttributeError, TypeError) as exc:
        raise _invalid_device_backup("encrypted backup device ID is invalid") from exc
    if source_device_id != expected_device_id:
        raise _invalid_device_backup("encrypted backup is for another firewall")

    key_id = value.get("key_id")
    mac = value.get("mac")
    if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
        raise _invalid_device_backup("encrypted backup key fingerprint is invalid")
    if not isinstance(mac, str) or not _HEX_64_RE.fullmatch(mac):
        raise _invalid_device_backup("encrypted backup authentication code is invalid")

    source_hostname = value.get("source_hostname")
    if (
        not isinstance(source_hostname, str)
        or not source_hostname.strip()
        or len(source_hostname) > 255
        or any(ord(character) < 32 for character in source_hostname)
    ):
        raise _invalid_device_backup("encrypted backup hostname is invalid")
    captured_at = value.get("captured_at")
    if not isinstance(captured_at, str) or len(captured_at) > 64:
        raise _invalid_device_backup("encrypted backup timestamp is invalid")
    try:
        parsed_timestamp = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _invalid_device_backup("encrypted backup timestamp is invalid") from exc
    if parsed_timestamp.tzinfo is None:
        raise _invalid_device_backup("encrypted backup timestamp must include a timezone")

    encoded_ciphertext = value.get("ciphertext")
    if not isinstance(encoded_ciphertext, str) or not encoded_ciphertext:
        raise _invalid_device_backup("encrypted backup ciphertext is invalid")
    if len(encoded_ciphertext) > ENCRYPTED_DEVICE_BACKUP_MAX_ENCODED_CIPHERTEXT_CHARS:
        raise _invalid_device_backup("encrypted backup ciphertext is too large")
    try:
        ciphertext = base64.b64decode(encoded_ciphertext, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise _invalid_device_backup("encrypted backup ciphertext is invalid") from exc
    if not ciphertext.startswith(b"Salted__"):
        raise _invalid_device_backup("encrypted backup salt header is invalid")
    encrypted_body = ciphertext[16:]
    if not encrypted_body or len(encrypted_body) % 16 != 0:
        raise _invalid_device_backup("encrypted backup ciphertext length is invalid")
    if len(ciphertext) > ENCRYPTED_DEVICE_BACKUP_MAX_CIPHERTEXT_BYTES:
        raise _invalid_device_backup("encrypted backup ciphertext is too large")

    canonical_payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    if len(canonical_payload) > ENCRYPTED_DEVICE_BACKUP_MAX_ENVELOPE_CHARS:
        raise _invalid_device_backup("encrypted backup envelope is too large")
    return canonical_payload


def validate_plaintext_device_backup(
    value: object, *, expected_device_id: uuid.UUID
) -> str:
    if not isinstance(value, dict) or set(value) != _PLAINTEXT_ENVELOPE_FIELDS:
        raise _invalid_device_backup("plaintext backup envelope fields are invalid")
    if value.get("format") != PLAINTEXT_DEVICE_BACKUP_FORMAT:
        raise _invalid_device_backup("plaintext backup format is not supported")
    if value.get("version") != PLAINTEXT_DEVICE_BACKUP_VERSION:
        raise _invalid_device_backup("plaintext backup version is invalid")
    try:
        source_device_id = uuid.UUID(str(value.get("device_id")))
    except (ValueError, AttributeError, TypeError) as exc:
        raise _invalid_device_backup("plaintext backup device ID is invalid") from exc
    if source_device_id != expected_device_id:
        raise _invalid_device_backup("plaintext backup is for another firewall")

    source_hostname = value.get("source_hostname")
    if (
        not isinstance(source_hostname, str)
        or not source_hostname.strip()
        or len(source_hostname) > 255
        or any(ord(character) < 32 for character in source_hostname)
    ):
        raise _invalid_device_backup("plaintext backup hostname is invalid")
    captured_at = value.get("captured_at")
    if not isinstance(captured_at, str) or len(captured_at) > 64:
        raise _invalid_device_backup("plaintext backup timestamp is invalid")
    try:
        parsed_timestamp = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _invalid_device_backup("plaintext backup timestamp is invalid") from exc
    if parsed_timestamp.tzinfo is None:
        raise _invalid_device_backup("plaintext backup timestamp must include a timezone")

    content = value.get("content")
    if not isinstance(content, str) or not content.strip():
        raise _invalid_device_backup("plaintext backup content is invalid")
    if len(content.encode("utf-8")) > ENCRYPTED_DEVICE_BACKUP_MAX_CIPHERTEXT_BYTES:
        raise _invalid_device_backup("plaintext backup content is too large")
    content_prefix = content.lower()[:512]
    if "<" not in content or (
        "<opnsense" not in content_prefix and "<config" not in content_prefix
    ):
        raise _invalid_device_backup(
            "plaintext backup content is not an OPNsense XML config"
        )

    canonical_payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    if len(canonical_payload) > ENCRYPTED_DEVICE_BACKUP_MAX_ENVELOPE_CHARS:
        raise _invalid_device_backup("plaintext backup envelope is too large")
    return canonical_payload


def device_backup_filename(hostname: str, received_at: datetime, backup_format: str) -> str:
    safe_hostname = re.sub(r"[^A-Za-z0-9._-]+", "-", hostname).strip("-")
    extension = ".xml" if backup_format == PLAINTEXT_DEVICE_BACKUP_FORMAT else ".opnenc"
    timestamp = received_at.strftime("%Y%m%d%H%M%S")
    return f"{safe_hostname or 'firewall'}-backup-{timestamp}{extension}"


def encrypted_device_backup_filename(hostname: str, received_at: datetime) -> str:
    return device_backup_filename(hostname, received_at, ENCRYPTED_DEVICE_BACKUP_FORMAT)
