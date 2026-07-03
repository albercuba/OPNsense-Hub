from __future__ import annotations

import base64
import contextlib
import io
import ipaddress
import json
import os
import stat
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import HTTPException
from sqlalchemy import Boolean, DateTime, Integer, delete, select
from sqlalchemy.orm import Session

from ..branding import (
    clear_uploaded_logo,
    detect_image_extension,
    save_uploaded_logo,
    uploaded_logo_path,
)
from ..models import (
    AuditLog,
    Company,
    CompanyUser,
    Device,
    DeviceBackup,
    DeviceEvent,
    EnrollmentCode,
    IntegrationSettings,
    SessionToken,
    User,
)
from ..security import utc_now
from ..web import settings
from ..wireguard import WireGuardError, bootstrap_wireguard, remove_peer

BACKUP_FORMAT_VERSION: Final = 1
ENCRYPTED_BACKUP_FORMAT: Final = "opnhub-encrypted-backup-v1"
REQUIRED_BACKUP_MEMBERS: Final = {"manifest.json", "data.json"}
BACKUP_TABLE_MODELS = (
    ("users", User),
    ("integration_settings", IntegrationSettings),
    ("companies", Company),
    ("company_users", CompanyUser),
    ("enrollment_codes", EnrollmentCode),
    ("devices", Device),
    ("device_backups", DeviceBackup),
    ("device_events", DeviceEvent),
    ("audit_logs", AuditLog),
)
BACKUP_RESTORE_DELETE_ORDER = (
    SessionToken,
    AuditLog,
    DeviceEvent,
    DeviceBackup,
    Device,
    EnrollmentCode,
    CompanyUser,
    Company,
    IntegrationSettings,
    User,
)


def backup_json_value(value: object) -> object:
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(
        value,
        (
            ipaddress.IPv4Address,
            ipaddress.IPv6Address,
            ipaddress.IPv4Network,
            ipaddress.IPv6Network,
            ipaddress.IPv4Interface,
            ipaddress.IPv6Interface,
        ),
    ):
        return str(value)
    return value


def serialize_model_row(row: object) -> dict[str, object]:
    table = getattr(row, "__table__")
    return {
        column.name: backup_json_value(getattr(row, column.name))
        for column in table.columns
    }


def parse_backup_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def deserialize_model_row(model: type, payload: dict[str, object]):
    values = {}
    for column in model.__table__.columns:
        raw_value = payload.get(column.name)
        if raw_value is None:
            values[column.name] = None
            continue
        if isinstance(column.type, DateTime):
            values[column.name] = parse_backup_datetime(str(raw_value))
        elif isinstance(column.type, Integer):
            values[column.name] = int(str(raw_value))
        elif isinstance(column.type, Boolean):
            values[column.name] = bool(raw_value)
        elif getattr(column.type, "as_uuid", False):
            values[column.name] = uuid.UUID(str(raw_value))
        else:
            values[column.name] = raw_value
    return model(**values)


def build_backup_manifest(
    data: dict[str, list[dict[str, object]]],
) -> dict[str, object]:
    logo_path = uploaded_logo_path(settings.branding_upload_dir)
    wg_key_path = Path(settings.wg_server_private_key_path)
    return {
        "format_version": BACKUP_FORMAT_VERSION,
        "created_at": utc_now().isoformat(),
        "app_name": settings.app_name,
        "tables": {name: len(rows) for name, rows in data.items()},
        "includes": {
            "branding_logo": logo_path.name if logo_path else None,
            "wireguard_private_key": wg_key_path.name if wg_key_path.exists() else None,
        },
    }


def _derive_backup_key(passphrase: str, salt: bytes, iterations: int = 390000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def encrypt_backup_payload(content: bytes, passphrase: str) -> bytes:
    salt = os.urandom(16)
    iterations = 390000
    token = Fernet(_derive_backup_key(passphrase, salt, iterations)).encrypt(content)
    envelope = {
        "format": ENCRYPTED_BACKUP_FORMAT,
        "salt": base64.b64encode(salt).decode("utf-8"),
        "iterations": iterations,
        "ciphertext": token.decode("utf-8"),
    }
    return json.dumps(envelope, indent=2, sort_keys=True).encode("utf-8")


def validate_backup_archive_members(archive: zipfile.ZipFile) -> None:
    infos = archive.infolist()
    if len(infos) > settings.max_backup_restore_entries:
        raise HTTPException(
            status_code=400, detail="backup archive contains too many files"
        )
    total_uncompressed = 0
    names = {info.filename for info in infos}
    if not REQUIRED_BACKUP_MEMBERS.issubset(names):
        raise HTTPException(
            status_code=400, detail="backup archive is missing required files"
        )
    for info in infos:
        if info.is_dir():
            continue
        if info.file_size > settings.max_backup_restore_file_bytes:
            raise HTTPException(
                status_code=400,
                detail=f"backup archive member '{info.filename}' exceeds the allowed size",
            )
        total_uncompressed += info.file_size
        if total_uncompressed > settings.max_backup_restore_total_uncompressed_bytes:
            raise HTTPException(
                status_code=400,
                detail="backup archive is too large after decompression",
            )


def decrypt_backup_payload(content: bytes, passphrase: str | None) -> bytes:
    try:
        envelope = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return content
    if (
        not isinstance(envelope, dict)
        or envelope.get("format") != ENCRYPTED_BACKUP_FORMAT
    ):
        return content
    if not passphrase:
        raise HTTPException(
            status_code=400, detail="backup archive requires a passphrase"
        )
    try:
        salt = base64.b64decode(str(envelope["salt"]))
        iterations = int(envelope["iterations"])
        token = str(envelope["ciphertext"]).encode("utf-8")
        return Fernet(_derive_backup_key(passphrase, salt, iterations)).decrypt(token)
    except (KeyError, ValueError, TypeError, InvalidToken) as exc:
        raise HTTPException(
            status_code=400,
            detail="backup passphrase is invalid or the archive is corrupted",
        ) from exc


def export_backup_bundle(
    db: Session, passphrase: str | None = None
) -> tuple[bytes, str, str]:
    exported = {
        table_name: [
            serialize_model_row(row) for row in db.scalars(select(model)).all()
        ]
        for table_name, model in BACKUP_TABLE_MODELS
    }
    manifest = build_backup_manifest(exported)
    base_filename = f"opnsense-hub-backup-{utc_now().strftime('%Y%m%d-%H%M%S')}"
    bundle = io.BytesIO()
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "manifest.json", json.dumps(manifest, indent=2, sort_keys=True)
        )
        archive.writestr("data.json", json.dumps(exported, indent=2, sort_keys=True))
        logo_path = uploaded_logo_path(settings.branding_upload_dir)
        if logo_path:
            archive.writestr(f"branding/{logo_path.name}", logo_path.read_bytes())
        wg_key_path = Path(settings.wg_server_private_key_path)
        if wg_key_path.exists():
            archive.writestr("wireguard/server.key", wg_key_path.read_text())
    raw_bundle = bundle.getvalue()
    if passphrase and passphrase.strip():
        return (
            encrypt_backup_payload(raw_bundle, passphrase.strip()),
            base_filename + ".opnhub",
            "application/octet-stream",
        )
    return raw_bundle, base_filename + ".zip", "application/zip"


def parse_backup_bundle(
    content: bytes, passphrase: str | None = None
) -> tuple[
    dict[str, object],
    dict[str, list[dict[str, object]]],
    tuple[str, bytes] | None,
    str | None,
]:
    if len(content) > settings.max_backup_restore_bytes:
        raise HTTPException(
            status_code=400, detail="backup file exceeds the maximum allowed size"
        )
    decrypted = decrypt_backup_payload(content, passphrase)
    try:
        archive = zipfile.ZipFile(io.BytesIO(decrypted))
    except zipfile.BadZipFile as exc:
        raise HTTPException(
            status_code=400, detail="backup file must be a valid zip archive"
        ) from exc
    with archive:
        validate_backup_archive_members(archive)
        try:
            manifest = json.loads(archive.read("manifest.json"))
            data = json.loads(archive.read("data.json"))
        except KeyError as exc:
            raise HTTPException(
                status_code=400, detail="backup archive is missing required files"
            ) from exc
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=400, detail="backup archive contains invalid JSON"
            ) from exc
        if not isinstance(manifest, dict) or not isinstance(data, dict):
            raise HTTPException(
                status_code=400, detail="backup archive has an invalid structure"
            )
        if manifest.get("format_version") != BACKUP_FORMAT_VERSION:
            raise HTTPException(
                status_code=400, detail="backup archive format version is not supported"
            )
        for table_name, _model in BACKUP_TABLE_MODELS:
            rows = data.get(table_name, [])
            if not isinstance(rows, list):
                raise HTTPException(
                    status_code=400, detail=f"backup table '{table_name}' is invalid"
                )
        logo_entry = next(
            (
                name
                for name in archive.namelist()
                if name.startswith("branding/logo.") and not name.endswith("/")
            ),
            None,
        )
        logo_file = (
            (logo_entry.rsplit("/", 1)[-1], archive.read(logo_entry))
            if logo_entry
            else None
        )
        wireguard_key = None
        if "wireguard/server.key" in archive.namelist():
            wireguard_key = archive.read("wireguard/server.key").decode("utf-8")
    return manifest, data, logo_file, wireguard_key


def restore_backup_bundle(
    db: Session,
    data: dict[str, list[dict[str, object]]],
    logo_file: tuple[str, bytes] | None,
    wireguard_private_key: str | None,
) -> None:
    existing_device_keys = [
        device.wg_public_key
        for device in db.scalars(
            select(Device).where(Device.revoked_at.is_(None))
        ).all()
    ]
    for public_key in existing_device_keys:
        with contextlib.suppress(WireGuardError):
            remove_peer(public_key)
    for model in BACKUP_RESTORE_DELETE_ORDER:
        db.execute(delete(model))
    for table_name, model in BACKUP_TABLE_MODELS:
        for row in data.get(table_name, []):
            if not isinstance(row, dict):
                raise HTTPException(
                    status_code=400,
                    detail=f"backup table '{table_name}' contains an invalid row",
                )
            db.add(deserialize_model_row(model, row))
    db.flush()
    if logo_file:
        logo_name, logo_content = logo_file
        extension = detect_image_extension(logo_content)
        if logo_name != f"logo{extension}":
            raise HTTPException(
                status_code=400,
                detail="backup archive branding logo filename is invalid",
            )
        save_uploaded_logo(settings.branding_upload_dir, extension, logo_content)
    else:
        clear_uploaded_logo(settings.branding_upload_dir)
    if wireguard_private_key is not None:
        key_path = Path(settings.wg_server_private_key_path)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(wireguard_private_key.strip() + "\n")
        with contextlib.suppress(OSError):
            os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
    bootstrap_wireguard(db)
