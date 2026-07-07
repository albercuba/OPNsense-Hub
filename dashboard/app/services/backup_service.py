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

from ..backups import (
    DEVICE_BACKUP_INTERVAL_HOURS_MAX,
    DEVICE_BACKUP_INTERVAL_UNITS,
    DEVICE_BACKUP_INTERVAL_VALUE_MAX,
    DEVICE_BACKUP_RETENTION_MAX,
)
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
from ..wireguard import (
    WG_KEY_RE,
    WireGuardError,
    add_peer,
    bootstrap_wireguard,
    get_validated_hub_wireguard_config,
    remove_peer,
    validate_public_key,
)

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
ALLOWED_BACKUP_ARCHIVE_MEMBERS: Final = {
    "manifest.json",
    "data.json",
    "wireguard/server.key",
    "branding/logo.png",
    "branding/logo.jpg",
    "branding/logo.webp",
}
ALLOWED_USER_ROLES: Final = {"user", "administrator"}
ALLOWED_COMPANY_USER_ROLES: Final = {"viewer", "admin", "owner"}
ALLOWED_DEVICE_STATUSES: Final = {
    "pending",
    "online",
    "offline",
    "warning",
    "critical",
    "revoked",
    "unknown",
}
ALLOWED_FIRMWARE_STATUSES: Final = {"unknown", "none", "update", "upgrade", "error"}
ALLOWED_FIRMWARE_UPDATE_TYPES: Final = {None, "update", "upgrade"}
ALLOWED_FIRMWARE_REQUEST_REASONS: Final = {None, "manual", "scheduled"}
ALLOWED_LICENSE_TYPES: Final = {None, "community", "business"}
ALLOWED_AUTH_PROVIDERS: Final = {None, "microsoft", "local_ad"}


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


def parse_backup_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    raise HTTPException(
        status_code=400, detail="backup archive contains an invalid boolean value"
    )


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
            values[column.name] = parse_backup_bool(raw_value)
        elif getattr(column.type, "as_uuid", False):
            values[column.name] = uuid.UUID(str(raw_value))
        else:
            values[column.name] = raw_value
    return model(**values)


def _ensure_string_max_length(value: object, *, field_name: str, maximum: int) -> None:
    if value is None:
        return
    if len(str(value)) > maximum:
        raise HTTPException(
            status_code=400,
            detail=f"{field_name} exceeds the maximum length of {maximum}",
        )


def _validate_private_key(value: str) -> None:
    if not WG_KEY_RE.match(value.strip()):
        raise HTTPException(
            status_code=400,
            detail="backup archive contains an invalid WireGuard private key",
        )


def _validate_restore_tunnel_ip(value: object, *, seen: set[str]) -> str:
    try:
        parsed = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="backup archive contains an invalid device tunnel IP",
        ) from exc
    validated = get_validated_hub_wireguard_config()
    if not isinstance(parsed, ipaddress.IPv4Address):
        raise HTTPException(status_code=400, detail="device tunnel IP must be IPv4")
    if parsed not in validated.network:
        raise HTTPException(
            status_code=400, detail="device tunnel IP must be inside HUB_WG_CIDR"
        )
    if parsed in {
        validated.hub_ip,
        validated.network.network_address,
        validated.network.broadcast_address,
    }:
        raise HTTPException(
            status_code=400, detail="device tunnel IP is not a usable host address"
        )
    normalized = str(parsed)
    if normalized in seen:
        raise HTTPException(
            status_code=400,
            detail="backup archive contains duplicate device tunnel IPs",
        )
    seen.add(normalized)
    return normalized


def validate_backup_data(
    data: dict[str, list[dict[str, object]]],
    logo_file: tuple[str, bytes] | None,
    wireguard_private_key: str | None,
) -> None:
    for table_name, model in BACKUP_TABLE_MODELS:
        rows = data.get(table_name, [])
        if not isinstance(rows, list):
            raise HTTPException(
                status_code=400, detail=f"backup table '{table_name}' is invalid"
            )
        for row in rows:
            if not isinstance(row, dict):
                raise HTTPException(
                    status_code=400,
                    detail=f"backup table '{table_name}' contains an invalid row",
                )
            deserialize_model_row(model, row)

    settings_rows = data.get("integration_settings", [])
    if len(settings_rows) != 1 or str(settings_rows[0].get("id")) != "1":
        raise HTTPException(
            status_code=400,
            detail="backup archive must contain exactly one integration settings row with id=1",
        )

    user_ids = {uuid.UUID(str(row["id"])) for row in data.get("users", [])}
    company_ids = {uuid.UUID(str(row["id"])) for row in data.get("companies", [])}
    device_ids = {uuid.UUID(str(row["id"])) for row in data.get("devices", [])}
    tunnel_ips_seen: set[str] = set()

    for row in data.get("users", []):
        role = str(row.get("role") or "").strip().lower()
        if role not in ALLOWED_USER_ROLES:
            raise HTTPException(
                status_code=400, detail="backup archive contains an invalid user role"
            )
        provider = row.get("auth_provider")
        if provider is not None and str(provider).strip().lower() not in {
            item for item in ALLOWED_AUTH_PROVIDERS if item is not None
        }:
            raise HTTPException(
                status_code=400,
                detail="backup archive contains an invalid auth provider",
            )
        _ensure_string_max_length(
            row.get("email"), field_name="user email", maximum=320
        )
        _ensure_string_max_length(
            row.get("first_name"), field_name="user first name", maximum=120
        )
        _ensure_string_max_length(
            row.get("last_name"), field_name="user last name", maximum=120
        )

    for row in data.get("companies", []):
        _ensure_string_max_length(
            row.get("name"), field_name="company name", maximum=200
        )

    for row in data.get("company_users", []):
        if (
            uuid.UUID(str(row.get("company_id"))) not in company_ids
            or uuid.UUID(str(row.get("user_id"))) not in user_ids
        ):
            raise HTTPException(
                status_code=400,
                detail="backup archive contains a company membership with a missing user or company",
            )
        role = str(row.get("role") or "").strip().lower()
        if role not in ALLOWED_COMPANY_USER_ROLES:
            raise HTTPException(
                status_code=400,
                detail="backup archive contains an invalid company role",
            )

    for row in data.get("devices", []):
        if uuid.UUID(str(row.get("company_id"))) not in company_ids:
            raise HTTPException(
                status_code=400,
                detail="backup archive contains a device with a missing company",
            )
        validate_public_key(str(row.get("wg_public_key") or "").strip())
        _validate_restore_tunnel_ip(row.get("wg_tunnel_ip"), seen=tunnel_ips_seen)
        status = str(row.get("status") or "").strip().lower()
        if status not in ALLOWED_DEVICE_STATUSES:
            raise HTTPException(
                status_code=400,
                detail="backup archive contains an invalid device status",
            )
        firmware_status = str(row.get("firmware_status") or "unknown").strip().lower()
        if firmware_status not in ALLOWED_FIRMWARE_STATUSES:
            raise HTTPException(
                status_code=400,
                detail="backup archive contains an invalid firmware status",
            )
        update_type = row.get("firmware_update_type")
        if (
            str(update_type).strip().lower() if update_type is not None else None
        ) not in ALLOWED_FIRMWARE_UPDATE_TYPES:
            raise HTTPException(
                status_code=400,
                detail="backup archive contains an invalid firmware update type",
            )
        request_reason = row.get("firmware_check_request_reason")
        if (
            str(request_reason).strip().lower() if request_reason is not None else None
        ) not in ALLOWED_FIRMWARE_REQUEST_REASONS:
            raise HTTPException(
                status_code=400,
                detail="backup archive contains an invalid firmware request reason",
            )
        license_type = row.get("license_type")
        if (
            str(license_type).strip().lower() if license_type is not None else None
        ) not in ALLOWED_LICENSE_TYPES:
            raise HTTPException(
                status_code=400,
                detail="backup archive contains an invalid license type",
            )
        backup_retention_count = int(str(row.get("backup_retention_count") or 3))
        if (
            backup_retention_count < 1
            or backup_retention_count > DEVICE_BACKUP_RETENTION_MAX
        ):
            raise HTTPException(
                status_code=400, detail="backup retention count is out of range"
            )
        backup_interval_value = int(str(row.get("backup_interval_value") or 24))
        if (
            backup_interval_value < 1
            or backup_interval_value > DEVICE_BACKUP_INTERVAL_VALUE_MAX
        ):
            raise HTTPException(
                status_code=400, detail="backup interval value is out of range"
            )
        backup_interval_unit = (
            str(row.get("backup_interval_unit") or "hours").strip().lower()
        )
        if backup_interval_unit not in DEVICE_BACKUP_INTERVAL_UNITS:
            raise HTTPException(
                status_code=400,
                detail="backup interval unit must be hours, days, or months",
            )
        backup_interval_hours = int(str(row.get("backup_interval_hours") or 24))
        if (
            backup_interval_hours < 1
            or backup_interval_hours > DEVICE_BACKUP_INTERVAL_HOURS_MAX
        ):
            raise HTTPException(
                status_code=400, detail="backup interval hours is out of range"
            )
        _ensure_string_max_length(
            row.get("hostname"), field_name="device hostname", maximum=255
        )
        _ensure_string_max_length(
            row.get("name"), field_name="device name", maximum=200
        )
        _ensure_string_max_length(
            row.get("email_notification_recipient"),
            field_name="device email notification recipient",
            maximum=320,
        )
        _ensure_string_max_length(
            row.get("runbook_owner"), field_name="runbook owner", maximum=200
        )
        _ensure_string_max_length(
            row.get("runbook_contact"), field_name="runbook contact", maximum=320
        )
        _ensure_string_max_length(
            row.get("runbook_site"), field_name="runbook site", maximum=200
        )
        _ensure_string_max_length(
            row.get("firmware_current_version"),
            field_name="firmware current version",
            maximum=80,
        )
        _ensure_string_max_length(
            row.get("firmware_available_version"),
            field_name="firmware available version",
            maximum=80,
        )
        _ensure_string_max_length(
            row.get("firmware_status_message"),
            field_name="firmware status message",
            maximum=500,
        )

    for row in data.get("device_backups", []):
        if uuid.UUID(str(row.get("device_id"))) not in device_ids:
            raise HTTPException(
                status_code=400,
                detail="backup archive contains a stored backup with a missing device",
            )
        _ensure_string_max_length(
            row.get("filename"), field_name="backup filename", maximum=255
        )
        _ensure_string_max_length(
            row.get("content"), field_name="backup content", maximum=2_000_000
        )

    for row in data.get("device_events", []):
        if uuid.UUID(str(row.get("device_id"))) not in device_ids:
            raise HTTPException(
                status_code=400,
                detail="backup archive contains a device event with a missing device",
            )
        _ensure_string_max_length(
            row.get("event_type"), field_name="device event type", maximum=80
        )
        _ensure_string_max_length(
            row.get("message"), field_name="device event message", maximum=1000
        )

    for row in data.get("audit_logs", []):
        user_id = row.get("user_id")
        company_id = row.get("company_id")
        device_id = row.get("device_id")
        if user_id is not None and uuid.UUID(str(user_id)) not in user_ids:
            raise HTTPException(
                status_code=400,
                detail="backup archive contains an audit log with a missing user",
            )
        if company_id is not None and uuid.UUID(str(company_id)) not in company_ids:
            raise HTTPException(
                status_code=400,
                detail="backup archive contains an audit log with a missing company",
            )
        if device_id is not None and uuid.UUID(str(device_id)) not in device_ids:
            raise HTTPException(
                status_code=400,
                detail="backup archive contains an audit log with a missing device",
            )
        _ensure_string_max_length(
            row.get("action"), field_name="audit action", maximum=120
        )
        _ensure_string_max_length(
            row.get("user_agent"), field_name="audit user agent", maximum=500
        )

    for row in data.get("enrollment_codes", []):
        if uuid.UUID(str(row.get("company_id"))) not in company_ids:
            raise HTTPException(
                status_code=400,
                detail="backup archive contains an enrollment code with a missing company",
            )
        created_by = row.get("created_by")
        if created_by is not None and uuid.UUID(str(created_by)) not in user_ids:
            raise HTTPException(
                status_code=400,
                detail="backup archive contains an enrollment code with a missing creator",
            )

    if logo_file:
        logo_name, logo_content = logo_file
        extension = detect_image_extension(logo_content)
        if logo_name != f"logo{extension}":
            raise HTTPException(
                status_code=400,
                detail="backup archive branding logo filename is invalid",
            )
        if len(logo_content) > settings.branding_logo_max_bytes:
            raise HTTPException(
                status_code=400,
                detail="backup archive branding logo exceeds the allowed size",
            )

    if wireguard_private_key is not None:
        _validate_private_key(wireguard_private_key)


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
    unexpected = names.difference(ALLOWED_BACKUP_ARCHIVE_MEMBERS)
    if unexpected:
        raise HTTPException(
            status_code=400,
            detail=f"backup archive contains unexpected files: {', '.join(sorted(unexpected))}",
        )
    for info in infos:
        if info.is_dir():
            continue
        if info.filename.startswith(("/", "\\")) or ".." in Path(info.filename).parts:
            raise HTTPException(
                status_code=400, detail="backup archive contains an invalid member path"
            )
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
    validate_backup_data(data, logo_file, wireguard_key)
    return manifest, data, logo_file, wireguard_key


def restore_backup_bundle(
    db: Session,
    data: dict[str, list[dict[str, object]]],
    logo_file: tuple[str, bytes] | None,
    wireguard_private_key: str | None,
) -> None:
    validate_backup_data(data, logo_file, wireguard_private_key)
    existing_devices = db.scalars(
        select(Device).where(Device.revoked_at.is_(None))
    ).all()
    existing_peers = [
        (device.wg_public_key, str(device.wg_tunnel_ip)) for device in existing_devices
    ]
    previous_logo = uploaded_logo_path(settings.branding_upload_dir)
    previous_logo_name = previous_logo.name if previous_logo else None
    previous_logo_content = previous_logo.read_bytes() if previous_logo else None
    key_path = Path(settings.wg_server_private_key_path)
    previous_key_content = key_path.read_text() if key_path.exists() else None

    for model in BACKUP_RESTORE_DELETE_ORDER:
        db.execute(delete(model))
    for table_name, model in BACKUP_TABLE_MODELS:
        for row in data.get(table_name, []):
            db.add(deserialize_model_row(model, row))
        db.flush()

    try:
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
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_text(wireguard_private_key.strip() + "\n")
            with contextlib.suppress(OSError):
                os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
        for public_key, _tunnel_ip in existing_peers:
            with contextlib.suppress(WireGuardError):
                remove_peer(public_key)
        bootstrap_wireguard(db)
    except Exception as exc:
        if previous_logo_content is not None and previous_logo_name is not None:
            save_uploaded_logo(
                settings.branding_upload_dir,
                Path(previous_logo_name).suffix,
                previous_logo_content,
            )
        else:
            clear_uploaded_logo(settings.branding_upload_dir)
        if previous_key_content is not None:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_text(previous_key_content)
            with contextlib.suppress(OSError):
                os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
        else:
            with contextlib.suppress(OSError):
                key_path.unlink(missing_ok=True)
        for public_key, tunnel_ip in existing_peers:
            with contextlib.suppress(WireGuardError):
                add_peer(public_key, tunnel_ip)
        raise HTTPException(
            status_code=400,
            detail=f"restore failed safely before commit: WireGuard could not be reinitialized: {exc}",
        ) from exc
