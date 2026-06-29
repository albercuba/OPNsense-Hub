import asyncio
import contextlib
import io
import ipaddress
import json
import logging
import re
import smtplib
import uuid
import zipfile
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Annotated
from urllib.parse import quote
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import Boolean, DateTime, Integer, delete, inspect, select, text
from sqlalchemy.orm import Session

from .audit import write_audit
from .backups import (
    DEVICE_BACKUP_INTERVAL_HOURS_MAX,
    DEVICE_BACKUP_INTERVAL_UNITS,
    DEVICE_BACKUP_INTERVAL_VALUE_MAX,
    DEVICE_BACKUP_RETENTION_MAX,
    backup_due,
    backup_interval_delta,
    backup_request_pending,
    mark_device_backup_requested,
)
from .branding import (
    BrandingError,
    clear_uploaded_logo,
    detect_image_extension,
    save_uploaded_logo,
    uploaded_logo_path,
    validate_branding_upload,
)
from .config import get_settings
from .dashboard import accessible_companies_for_user, build_dashboard_context
from .database import Base, SessionLocal, engine, get_db
from .hardening import apply_startup_hardening
from .health import HealthState, HealthThresholds, next_health_state
from .integration import (
    email_settings_configured,
    graph_email_configured,
    smtp_email_configured,
)
from .models import (
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
from .rbac import has_company_role
from .security import (
    hash_secret,
    hash_session_token,
    random_otp,
    random_token,
    utc_now,
    verify_secret,
)
from .wireguard import (
    WireGuardError,
    add_peer,
    bootstrap_wireguard,
    client_allowed_ips,
    get_server_public_key,
    next_tunnel_ip,
    remove_peer,
)

settings = get_settings()
logger = logging.getLogger(__name__)
app = FastAPI(title=settings.app_name)
APP_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

FIRMWARE_STATUSES = {"unknown", "none", "update", "upgrade", "error"}
FIRMWARE_SUCCESS_STATUSES = {"none", "update", "upgrade"}
FIRMWARE_VERSION_MAX_LENGTH = 80
FIRMWARE_MESSAGE_MAX_LENGTH = 500
DEVICE_BACKUP_CONTENT_MAX_LENGTH = 2_000_000


def app_timezone_info() -> ZoneInfo:
    try:
        return ZoneInfo(settings.app_timezone)
    except ZoneInfoNotFoundError:
        logger.warning("Unknown app timezone %s; falling back to UTC", settings.app_timezone)
        return ZoneInfo("UTC")


def to_app_timezone(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(app_timezone_info())


def app_now() -> datetime:
    return utc_now().astimezone(app_timezone_info())


def format_datetime(value: datetime | None, include_tz: bool = False) -> str:
    if value is None:
        return ""
    fmt = "%Y-%m-%d %H:%M %Z" if include_tz else "%Y-%m-%d %H:%M"
    return to_app_timezone(value).strftime(fmt)


def tunnel_proxy_host(value: object) -> str:
    """Return a plain IP host for proxy URLs from an INET/CIDR value."""
    text_value = str(value)
    if "/" in text_value:
        return str(ipaddress.ip_interface(text_value).ip)
    return str(ipaddress.ip_address(text_value))


def device_webgui_url(device: Device) -> str:
    proxy_host = tunnel_proxy_host(device.wg_tunnel_ip)
    return f"https://{proxy_host}:{settings.opnsense_gui_port}/"


PROXY_REQUEST_HEADER_BLOCKLIST = {
    "connection",
    "content-length",
    "cookie",
    "host",
    "keep-alive",
    "origin",
    "proxy-authenticate",
    "proxy-authorization",
    "referer",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def proxy_request_headers(request: Request, device_id: uuid.UUID) -> dict[str, str]:
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in PROXY_REQUEST_HEADER_BLOCKLIST
    }
    cookie_header = proxy_upstream_cookie_header(request, device_id)
    if cookie_header:
        headers["cookie"] = cookie_header
    return headers


def proxy_cookie_prefix(device_id: uuid.UUID) -> str:
    return f"opnhub_{device_id.hex}_"


def proxy_path_prefix(device_id: uuid.UUID) -> str:
    return f"/proxy/devices/{device_id}"


def proxy_upstream_cookie_header(request: Request, device_id: uuid.UUID) -> str:
    prefix = proxy_cookie_prefix(device_id)
    upstream_cookies = []
    for name, value in request.cookies.items():
        if name.startswith(prefix):
            upstream_cookies.append(f"{name[len(prefix) :]}={value}")
    return "; ".join(upstream_cookies)


def proxy_downstream_set_cookie_headers(
    set_cookie_headers: list[str], device_id: uuid.UUID
) -> list[str]:
    rewritten = []
    prefix = proxy_cookie_prefix(device_id)
    path_prefix = proxy_path_prefix(device_id)
    for header in set_cookie_headers:
        cookies = SimpleCookie()
        cookies.load(header)
        for name, morsel in cookies.items():
            morsel.set(prefix + name, morsel.value, morsel.coded_value)
            morsel["path"] = path_prefix
            morsel["domain"] = ""
            rewritten.append(morsel.OutputString())
    return rewritten


def proxy_rewrite_location(
    location: str, device_id: uuid.UUID, upstream_base: str
) -> str:
    path_prefix = proxy_path_prefix(device_id)
    if location.startswith(upstream_base):
        return path_prefix + "/" + location.removeprefix(upstream_base).lstrip("/")
    if location.startswith("/") and not location.startswith(path_prefix + "/"):
        return path_prefix + location
    return location


def proxy_rewrite_absolute_path(match: re.Match[str], path_prefix: str) -> str:
    prefix = match.group("prefix")
    path = match.group("path")
    if path.startswith(("/", "proxy/devices/")):
        return match.group(0)
    return f"{prefix}{path_prefix}/{path}"


def proxy_rewrite_body(
    content: bytes, content_type: str, device_id: uuid.UUID
) -> bytes:
    if not any(
        kind in content_type.lower() for kind in ("text/html", "text/css", "javascript")
    ):
        return content
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return content
    path_prefix = proxy_path_prefix(device_id)
    text = re.sub(
        r'(?P<prefix>\b(?:href|src|action)=(["\']))/(?P<path>[^"\']*)',
        lambda match: proxy_rewrite_absolute_path(match, path_prefix),
        text,
    )
    text = re.sub(
        r'(?P<prefix>url\((["\']?))/(?P<path>[^)"\']*)',
        lambda match: proxy_rewrite_absolute_path(match, path_prefix),
        text,
    )
    text = re.sub(
        r'(?P<prefix>["\'])/(?P<path>(?!/|proxy/devices/)[^"\']*)',
        lambda match: proxy_rewrite_absolute_path(match, path_prefix),
        text,
    )
    return text.encode("utf-8")


async def probe_device_webgui(
    client: httpx.AsyncClient, device: Device
) -> tuple[bool, str]:
    try:
        url = device_webgui_url(device)
    except ValueError as exc:
        return (
            False,
            f"Stored WireGuard tunnel IP is invalid: {device.wg_tunnel_ip}: {exc}",
        )

    try:
        await client.get(url)
    except httpx.RequestError as exc:
        error_detail = str(exc) or repr(exc)
        return (
            False,
            f"WebGUI unreachable at {url}: {exc.__class__.__name__}: {error_detail}",
        )
    return True, f"WebGUI reachable at {url}"


def device_health_status(device: Device, healthy: bool) -> str:
    new_state = next_health_state(
        HealthState(
            status=device.status,
            missed_checks=device.health_missed_checks,
            success_checks=device.health_success_checks,
        ),
        healthy,
        HealthThresholds(
            warning_misses=settings.firewall_health_warning_misses,
            critical_misses=settings.firewall_health_critical_misses,
            warning_recovery_successes=settings.firewall_health_warning_recovery_successes,
            critical_recovery_successes=settings.firewall_health_critical_recovery_successes,
        ),
    )
    device.health_missed_checks = new_state.missed_checks
    device.health_success_checks = new_state.success_checks
    return new_state.status


async def run_device_health_checks_once() -> None:
    with SessionLocal() as db:
        devices = db.scalars(
            select(Device).where(Device.revoked_at.is_(None)).order_by(Device.hostname)
        ).all()
        if not devices:
            return

        now = utc_now()
        async with httpx.AsyncClient(
            verify=settings.proxy_verify_tls,
            follow_redirects=False,
            timeout=settings.firewall_health_check_timeout_seconds,
        ) as client:
            for device in devices:
                healthy, message = await probe_device_webgui(client, device)
                previous_status = device.status
                new_status = device_health_status(device, healthy)
                if previous_status != new_status:
                    device.status = new_status
                    db.add(
                        DeviceEvent(
                            device_id=device.id,
                            event_type="health_check",
                            message=(
                                f"{message}; missed={device.health_missed_checks}; "
                                f"successes={device.health_success_checks}"
                            )[:1000],
                        )
                    )
                    maybe_send_health_notification(
                        db, device, previous_status, new_status, now
                    )
                if healthy:
                    device.last_seen_at = now
        db.commit()


async def device_health_check_loop() -> None:
    interval = max(1, settings.firewall_health_check_interval_seconds)
    while True:
        try:
            await run_device_health_checks_once()
        except Exception:
            logger.exception("Firewall health check failed")
        await asyncio.sleep(interval)


async def run_firmware_schedule_once(now: datetime | None = None) -> int:
    current_time = now or app_now()
    if current_time.hour != 23:
        return 0
    with SessionLocal() as db:
        marked = mark_devices_for_firmware_check(
            db, reason="scheduled", now=current_time
        )
        if marked:
            db.commit()
            logger.info("Marked %s firewalls for scheduled firmware check", marked)
        return marked


async def firmware_check_schedule_loop() -> None:
    while True:
        try:
            await run_firmware_schedule_once()
        except Exception:
            logger.exception("Firmware check scheduler failed")
        await asyncio.sleep(60)


def ensure_schema_compat() -> None:
    with engine.begin() as conn:
        conn.execute(
            text("ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name text NULL")
        )
        conn.execute(
            text("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name text NULL")
        )
        conn.execute(
            text(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'user'"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS health_missed_checks integer NOT NULL DEFAULT 0"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS health_success_checks integer NOT NULL DEFAULT 0"
            )
        )
        conn.execute(
            text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS license_type text NULL")
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS license_expires_at timestamptz NULL"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS microsoft_admin_group_name text NULL"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS microsoft_admin_group_id text NULL"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS microsoft_user_group_name text NULL"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS microsoft_user_group_id text NULL"
            )
        )
        integration_columns = {
            column["name"] for column in inspect(conn).get_columns("integration_settings")
        }
        if "microsoft_admin_group" in integration_columns:
            conn.execute(
                text(
                    """
                    UPDATE integration_settings
                    SET microsoft_admin_group_name = COALESCE(microsoft_admin_group_name, microsoft_admin_group)
                    WHERE microsoft_admin_group IS NOT NULL
                    """
                )
            )
        if "microsoft_user_group" in integration_columns:
            conn.execute(
                text(
                    """
                    UPDATE integration_settings
                    SET microsoft_user_group_name = COALESCE(microsoft_user_group_name, microsoft_user_group)
                    WHERE microsoft_user_group IS NOT NULL
                    """
                )
            )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_status text NOT NULL DEFAULT 'unknown'"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_update_available boolean NOT NULL DEFAULT false"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_update_type text NULL"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_current_version text NULL"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_available_version text NULL"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_update_count integer NOT NULL DEFAULT 0"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_reboot_required boolean NOT NULL DEFAULT false"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_status_message text NULL"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_checked_at timestamptz NULL"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_check_requested_at timestamptz NULL"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_check_request_reason text NULL"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS backup_enabled boolean NOT NULL DEFAULT false"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS backup_retention_count integer NOT NULL DEFAULT 3"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS backup_interval_value integer NOT NULL DEFAULT 24"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS backup_interval_unit text NOT NULL DEFAULT 'hours'"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS backup_interval_hours integer NOT NULL DEFAULT 24"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS backup_last_requested_at timestamptz NULL"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS backup_last_uploaded_at timestamptz NULL"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS email_notifications_enabled boolean NOT NULL DEFAULT false"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS email_notification_recipient text NULL"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS email_notify_on_warning boolean NOT NULL DEFAULT true"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS email_notify_on_critical boolean NOT NULL DEFAULT true"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS email_last_notified_status text NULL"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS email_last_notified_at timestamptz NULL"
            )
        )
        conn.execute(
            text(
                """
                UPDATE devices
                SET backup_interval_value = backup_interval_hours,
                    backup_interval_unit = 'hours'
                WHERE backup_interval_hours IS NOT NULL
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                  id uuid PRIMARY KEY,
                  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                  token_hash text NOT NULL UNIQUE,
                  created_at timestamptz NOT NULL DEFAULT now(),
                  expires_at timestamptz NOT NULL,
                  revoked_at timestamptz NULL
                )
                """
            )
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)"
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS integration_settings (
                  id integer PRIMARY KEY DEFAULT 1,
                  smtp_enabled boolean NOT NULL DEFAULT false,
                  smtp_host text NULL,
                  smtp_port integer NULL,
                  smtp_username text NULL,
                  smtp_password text NULL,
                  smtp_from text NULL,
                  graph_enabled boolean NOT NULL DEFAULT false,
                  graph_tenant_id text NULL,
                  graph_client_id text NULL,
                  graph_client_secret text NULL,
                  graph_sender text NULL,
                  microsoft_enabled boolean NOT NULL DEFAULT false,
                  microsoft_tenant_id text NULL,
                  microsoft_client_id text NULL,
                  microsoft_audience text NULL,
                  microsoft_authority text NULL,
                  microsoft_admin_group_name text NULL,
                  microsoft_admin_group_id text NULL,
                  microsoft_user_group_name text NULL,
                  microsoft_user_group_id text NULL,
                  ad_enabled boolean NOT NULL DEFAULT false,
                  ad_host text NULL,
                  ad_base_dn text NULL,
                  ad_bind_dn text NULL,
                  branding_logo_url text NULL,
                  updated_at timestamptz NOT NULL DEFAULT now()
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS device_backups (
                  id uuid PRIMARY KEY,
                  device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                  filename text NOT NULL,
                  content text NOT NULL,
                  created_at timestamptz NOT NULL DEFAULT now()
                )
                """
            )
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS idx_device_backups_device_id ON device_backups(device_id)"
            )
        )


def bootstrap() -> None:
    Base.metadata.create_all(bind=engine)
    ensure_schema_compat()
    with SessionLocal() as db:
        admin = db.scalar(
            select(User).where(User.email == settings.initial_admin_email.lower())
        )
        if not admin:
            db.add(
                User(
                    email=settings.initial_admin_email.lower(),
                    password_hash=hash_secret(settings.initial_admin_password),
                    role="administrator",
                )
            )
            db.commit()
        elif admin.role != "administrator":
            admin.role = "administrator"
            db.commit()
        bootstrap_wireguard(db)


@app.on_event("startup")
async def on_startup() -> None:
    apply_startup_hardening(settings)
    bootstrap()
    app.state.health_check_task = asyncio.create_task(device_health_check_loop())
    app.state.firmware_schedule_task = asyncio.create_task(
        firmware_check_schedule_loop()
    )


@app.on_event("shutdown")
async def on_shutdown() -> None:
    for task_name in ("health_check_task", "firmware_schedule_task"):
        task = getattr(app.state, task_name, None)
        if task is None:
            continue
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401 and not request.url.path.startswith("/api/"):
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(settings.session_cookie_name)
        return response
    detail = exc.detail if exc.detail is not None else "Unauthorized"
    return JSONResponse(status_code=exc.status_code, content={"detail": detail})


def current_user(request: Request, db: Annotated[Session, Depends(get_db)]) -> User:
    session = session_from_request(request, db)
    user = db.get(User, session.user_id)
    if not user:
        raise HTTPException(status_code=401)
    return user


def ui_user(request: Request, db: Session) -> User | None:
    try:
        return current_user(request, db)
    except HTTPException:
        return None


def require_company(
    db: Session, user: User, company_id: uuid.UUID, minimum: str = "viewer"
) -> Company:
    company = db.get(Company, company_id)
    if not company or not has_company_access(db, user, company_id, minimum):
        raise HTTPException(status_code=404, detail="company not found")
    return company


def has_company_access(
    db: Session, user: User, company_id: uuid.UUID, minimum: str = "viewer"
) -> bool:
    return user.role == "administrator" or has_company_role(
        db, user, company_id, minimum
    )


def require_admin(user: User) -> None:
    if user.role != "administrator":
        raise HTTPException(status_code=403, detail="administrator access required")


def get_or_create_integration_settings(db: Session) -> IntegrationSettings:
    integration_settings = db.get(IntegrationSettings, 1)
    if not integration_settings:
        integration_settings = IntegrationSettings(id=1)
        db.add(integration_settings)
        db.commit()
        db.refresh(integration_settings)
    return integration_settings


def clean_optional(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


BACKUP_FORMAT_VERSION = 1
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
            ipaddress.IPv4Interface,
            ipaddress.IPv6Interface,
            ipaddress.IPv4Network,
            ipaddress.IPv6Network,
        ),
    ):
        return str(value)
    return value


def serialize_model_row(row: object) -> dict[str, object]:
    table = getattr(row, "__table__")
    return {
        column.name: backup_json_value(getattr(row, column.name)) for column in table.columns
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


def build_backup_manifest(data: dict[str, list[dict[str, object]]]) -> dict[str, object]:
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


def export_backup_bundle(db: Session) -> tuple[bytes, str]:
    exported = {
        table_name: [serialize_model_row(row) for row in db.scalars(select(model)).all()]
        for table_name, model in BACKUP_TABLE_MODELS
    }
    manifest = build_backup_manifest(exported)
    filename = f"opnsense-hub-backup-{utc_now().strftime('%Y%m%d-%H%M%S')}.zip"
    bundle = io.BytesIO()
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
        archive.writestr("data.json", json.dumps(exported, indent=2, sort_keys=True))
        logo_path = uploaded_logo_path(settings.branding_upload_dir)
        if logo_path:
            archive.writestr(f"branding/{logo_path.name}", logo_path.read_bytes())
        wg_key_path = Path(settings.wg_server_private_key_path)
        if wg_key_path.exists():
            archive.writestr("wireguard/server.key", wg_key_path.read_text())
    return bundle.getvalue(), filename


def parse_backup_bundle(content: bytes) -> tuple[dict[str, object], dict[str, list[dict[str, object]]], tuple[str, bytes] | None, str | None]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=400, detail="backup file must be a valid zip archive") from exc
    with archive:
        try:
            manifest = json.loads(archive.read("manifest.json"))
            data = json.loads(archive.read("data.json"))
        except KeyError as exc:
            raise HTTPException(status_code=400, detail="backup archive is missing required files") from exc
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="backup archive contains invalid JSON") from exc
        if not isinstance(manifest, dict) or not isinstance(data, dict):
            raise HTTPException(status_code=400, detail="backup archive has an invalid structure")
        if manifest.get("format_version") != BACKUP_FORMAT_VERSION:
            raise HTTPException(status_code=400, detail="backup archive format version is not supported")
        for table_name, _model in BACKUP_TABLE_MODELS:
            rows = data.get(table_name, [])
            if not isinstance(rows, list):
                raise HTTPException(status_code=400, detail=f"backup table '{table_name}' is invalid")
        logo_entry = next(
            (
                name
                for name in archive.namelist()
                if name.startswith("branding/logo.") and not name.endswith("/")
            ),
            None,
        )
        logo_file = (logo_entry.rsplit("/", 1)[-1], archive.read(logo_entry)) if logo_entry else None
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
        for device in db.scalars(select(Device).where(Device.revoked_at.is_(None))).all()
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
                    status_code=400, detail=f"backup table '{table_name}' contains an invalid row"
                )
            db.add(deserialize_model_row(model, row))

    db.flush()

    if logo_file:
        logo_name, logo_content = logo_file
        extension = detect_image_extension(logo_content)
        if logo_name != f"logo{extension}":
            raise HTTPException(status_code=400, detail="backup archive branding logo filename is invalid")
        save_uploaded_logo(settings.branding_upload_dir, extension, logo_content)
    else:
        clear_uploaded_logo(settings.branding_upload_dir)

    if wireguard_private_key is not None:
        key_path = Path(settings.wg_server_private_key_path)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(wireguard_private_key.strip() + "\n")

    bootstrap_wireguard(db)


def is_valid_email_address(value: str | None) -> bool:
    if not value:
        return False
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value))


def send_smtp_email(
    integration_settings: IntegrationSettings, to_email: str, subject: str, body: str
) -> None:
    message = EmailMessage()
    message["From"] = integration_settings.smtp_from
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)
    with smtplib.SMTP(
        integration_settings.smtp_host, integration_settings.smtp_port, timeout=20
    ) as smtp:
        if integration_settings.smtp_username and integration_settings.smtp_password:
            smtp.login(
                integration_settings.smtp_username, integration_settings.smtp_password
            )
        smtp.send_message(message)


def send_graph_email(
    integration_settings: IntegrationSettings, to_email: str, subject: str, body: str
) -> None:
    token_url = (
        "https://login.microsoftonline.com/"
        f"{integration_settings.graph_tenant_id}/oauth2/v2.0/token"
    )
    with httpx.Client(timeout=20) as client:
        token_response = client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": integration_settings.graph_client_id,
                "client_secret": integration_settings.graph_client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        token_response.raise_for_status()
        access_token = token_response.json()["access_token"]
        send_response = client.post(
            "https://graph.microsoft.com/v1.0/users/"
            f"{quote(str(integration_settings.graph_sender), safe='')}/sendMail",
            headers={"Authorization": f"Bearer {access_token}"},
            json={
                "message": {
                    "subject": subject,
                    "body": {"contentType": "Text", "content": body},
                    "toRecipients": [{"emailAddress": {"address": to_email}}],
                }
            },
        )
        send_response.raise_for_status()


def send_notification_email(
    db: Session, to_email: str, subject: str, body: str
) -> None:
    integration_settings = get_or_create_integration_settings(db)
    if smtp_email_configured(integration_settings):
        send_smtp_email(integration_settings, to_email, subject, body)
        return
    if graph_email_configured(integration_settings):
        send_graph_email(integration_settings, to_email, subject, body)
        return
    raise RuntimeError("email settings are not configured")


def parse_bounded_int(
    value: object,
    *,
    field_name: str,
    minimum: int,
    maximum: int,
) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"{field_name} must be a number") from exc
    if parsed < minimum or parsed > maximum:
        raise HTTPException(
            status_code=400,
            detail=f"{field_name} must be between {minimum} and {maximum}",
        )
    return parsed


def parse_backup_interval_unit(value: object) -> str:
    normalized = str(value).strip().lower()
    if normalized not in DEVICE_BACKUP_INTERVAL_UNITS:
        raise HTTPException(
            status_code=400,
            detail="backup interval unit must be hours, days, or months",
        )
    return normalized


def normalize_backup_filename(device: Device, created_at: datetime) -> str:
    safe_hostname = re.sub(r"[^A-Za-z0-9._-]+", "-", device.hostname).strip("-") or "firewall"
    return f"{safe_hostname}-backup-{created_at.strftime('%Y%m%d%H%M%S')}.xml"


def health_notification_status_label(status: str) -> str:
    return "critical" if status == "offline" else status


def should_notify_for_health_status(device: Device, new_status: str) -> bool:
    if new_status == "warning":
        return device.email_notify_on_warning
    if new_status == "offline":
        return device.email_notify_on_critical
    return False


def build_health_notification_email(
    device: Device,
    company: Company | None,
    previous_status: str,
    new_status: str,
    current_time: datetime,
) -> tuple[str, str]:
    display_status = health_notification_status_label(new_status)
    subject = f"[OPNsense Hub] Firewall status {display_status}: {device.hostname}"
    body = "\n".join(
        [
            f"Firewall: {device.hostname}",
            f"Company: {company.name if company else 'Unknown'}",
            f"Status: {display_status}",
            f"Previous status: {previous_status}",
            f"Tunnel IP: {device.wg_tunnel_ip}",
            "Last seen: "
            + (format_datetime(device.last_seen_at, include_tz=True) if device.last_seen_at else "Never"),
            f"Time: {format_datetime(current_time, include_tz=True)}",
            "",
            "This alert was sent because email notifications are enabled for this firewall in OPNsense Hub.",
        ]
    )
    return subject, body


def maybe_send_health_notification(
    db: Session,
    device: Device,
    previous_status: str,
    new_status: str,
    current_time: datetime,
    email_sender=None,
) -> bool:
    if device.revoked_at or previous_status == new_status:
        return False
    if not device.email_notifications_enabled:
        return False
    if not should_notify_for_health_status(device, new_status):
        return False
    recipient = clean_optional(device.email_notification_recipient)
    if not recipient:
        return False
    integration_settings = get_or_create_integration_settings(db)
    if not email_settings_configured(integration_settings):
        return False
    company = db.get(Company, device.company_id)
    subject, body = build_health_notification_email(
        device, company, previous_status, new_status, current_time
    )
    sender = email_sender or send_notification_email
    try:
        sender(db, recipient, subject, body)
    except Exception as exc:
        db.add(
            DeviceEvent(
                device_id=device.id,
                event_type="email_notification_failed",
                message=(
                    "Could not send health status email notification: "
                    f"{exc.__class__.__name__}"
                )[:1000],
            )
        )
        logger.warning(
            "Health status notification failed for device %s: %s",
            device.id,
            exc.__class__.__name__,
        )
        return False
    device.email_last_notified_status = new_status
    device.email_last_notified_at = current_time
    db.add(
        DeviceEvent(
            device_id=device.id,
            event_type="email_notification_sent",
            message=(
                f"Health status notification sent for {health_notification_status_label(new_status)}"
            )[:1000],
        )
    )
    return True


def parse_license_expires_at(value: object) -> datetime | None:
    if value is None:
        return None
    text_value = str(value).strip()
    if not text_value:
        return None
    try:
        parsed = datetime.fromisoformat(text_value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def parse_uploaded_backup_created_at(value: object) -> datetime:
    parsed = parse_license_expires_at(value)
    return parsed or utc_now()


def normalize_device_license_payload(
    payload: dict[str, object],
) -> tuple[str | None, datetime | None]:
    raw_license_type = clean_optional(
        str(payload.get("license_type", ""))
        if payload.get("license_type") is not None
        else None
    )
    if not raw_license_type:
        return None, None
    normalized_type = raw_license_type.lower()
    if normalized_type not in {"business", "community"}:
        return None, None
    if normalized_type == "community":
        return "community", None
    return "business", parse_license_expires_at(payload.get("license_expires_at"))


def apply_device_license_payload(device: Device, payload: dict[str, object]) -> None:
    license_type, license_expires_at = normalize_device_license_payload(payload)
    if license_type is None:
        return
    device.license_type = license_type
    device.license_expires_at = license_expires_at


def device_license_label(device: Device) -> str:
    return "Business" if device.license_type == "business" else "Community"


def device_license_expiration(device: Device, now: datetime | None = None) -> str:
    if device.license_type != "business":
        return "-"
    if not device.license_expires_at:
        return "-"
    current_time = now or utc_now()
    expiration_date = device.license_expires_at.astimezone(timezone.utc).date()
    if expiration_date < current_time.date():
        return "Expired"
    return expiration_date.strftime("%m-%d-%Y")


def parse_firmware_checked_at(value: object) -> datetime | None:
    return parse_license_expires_at(value)


def truncate_optional_text(value: object, max_length: int) -> str | None:
    if value is None:
        return None
    text_value = str(value).strip()
    if not text_value:
        return None
    return text_value[:max_length]


def normalize_device_firmware_payload(
    payload: dict[str, object], now: datetime | None = None
) -> dict[str, object] | None:
    raw_firmware = payload.get("firmware")
    if raw_firmware is None:
        return None
    current_time = now or utc_now()
    if not isinstance(raw_firmware, dict):
        return {
            "status": "error",
            "update_available": False,
            "update_type": None,
            "current_version": None,
            "available_version": None,
            "update_count": 0,
            "reboot_required": False,
            "message": "Invalid firmware status payload reported by firewall",
            "checked_at": current_time,
        }

    raw_status = truncate_optional_text(raw_firmware.get("status"), 30)
    normalized_status = (raw_status or "error").lower()
    message = truncate_optional_text(
        raw_firmware.get("message"), FIRMWARE_MESSAGE_MAX_LENGTH
    )
    if normalized_status not in {"none", "update", "upgrade", "error"}:
        normalized_status = "error"
        if not message:
            message = "Invalid firmware status reported by firewall"

    raw_update_type = truncate_optional_text(raw_firmware.get("update_type"), 30)
    normalized_update_type = raw_update_type.lower() if raw_update_type else None
    if normalized_update_type not in {None, "none", "update", "upgrade", "error"}:
        normalized_update_type = None

    try:
        update_count = max(0, int(raw_firmware.get("update_count", 0) or 0))
    except (TypeError, ValueError):
        update_count = 0

    checked_at = (
        parse_firmware_checked_at(raw_firmware.get("checked_at")) or current_time
    )
    update_available = bool(raw_firmware.get("update_available"))
    if normalized_status in {"update", "upgrade"}:
        update_available = True
    elif normalized_status == "none":
        update_available = False

    return {
        "status": normalized_status,
        "update_available": update_available,
        "update_type": normalized_update_type,
        "current_version": truncate_optional_text(
            raw_firmware.get("current_version"), FIRMWARE_VERSION_MAX_LENGTH
        ),
        "available_version": truncate_optional_text(
            raw_firmware.get("available_version"), FIRMWARE_VERSION_MAX_LENGTH
        ),
        "update_count": update_count,
        "reboot_required": bool(raw_firmware.get("reboot_required")),
        "message": message,
        "checked_at": checked_at,
    }


def apply_device_firmware_payload(
    device: Device, payload: dict[str, object], now: datetime | None = None
) -> bool:
    firmware = normalize_device_firmware_payload(payload, now=now)
    if firmware is None:
        return False
    device.firmware_status = str(firmware["status"])
    device.firmware_update_available = bool(firmware["update_available"])
    device.firmware_update_type = firmware["update_type"]
    device.firmware_current_version = firmware["current_version"]
    device.firmware_available_version = firmware["available_version"]
    device.firmware_update_count = int(firmware["update_count"])
    device.firmware_reboot_required = bool(firmware["reboot_required"])
    device.firmware_status_message = firmware["message"]
    device.firmware_checked_at = firmware["checked_at"]
    device.firmware_check_requested_at = None
    device.firmware_check_request_reason = None
    return True


def firmware_status_local_date(value: datetime | None) -> date | None:
    if value is None:
        return None
    return to_app_timezone(value).date()


def device_has_firmware_check_for_day(device: Device, scheduled_day) -> bool:
    return firmware_status_local_date(device.firmware_checked_at) == scheduled_day


def device_has_pending_firmware_request_for_day(device: Device, scheduled_day) -> bool:
    return (
        device.firmware_check_request_reason == "scheduled"
        and firmware_status_local_date(device.firmware_check_requested_at)
        == scheduled_day
    )


def mark_devices_for_firmware_check(
    db: Session, reason: str = "scheduled", now: datetime | None = None
) -> int:
    scheduled_time = now or app_now()
    requested_at = scheduled_time.astimezone(timezone.utc)
    scheduled_day = scheduled_time.date()
    devices = db.scalars(
        select(Device).where(Device.revoked_at.is_(None)).order_by(Device.hostname)
    ).all()
    marked = 0
    for device in devices:
        if device.revoked_at is not None:
            continue
        if device_has_firmware_check_for_day(device, scheduled_day):
            continue
        if device_has_pending_firmware_request_for_day(device, scheduled_day):
            continue
        device.firmware_check_requested_at = requested_at
        device.firmware_check_request_reason = reason[:30]
        marked += 1
    return marked


def firmware_status_ui(device: Device) -> dict[str, str]:
    status = (device.firmware_status or "unknown").lower()
    if status not in FIRMWARE_STATUSES:
        status = "unknown"
    checked_at_text = None
    if device.firmware_checked_at:
        checked_at_text = format_datetime(device.firmware_checked_at)

    mapping = {
        "unknown": {
            "label": "Unknown",
            "class": "text-muted",
            "icon": "fa-solid fa-circle-question",
            "tooltip": "Firmware status unknown",
        },
        "none": {
            "label": "Up to date",
            "class": "text-success",
            "icon": "fa-solid fa-circle-check",
            "tooltip": f"Up to date: {device.firmware_current_version or device.opnsense_version or 'Unknown'}",
        },
        "update": {
            "label": "Updates available",
            "class": "text-info",
            "icon": "fa-solid fa-circle-exclamation",
            "tooltip": f"Updates available: {device.firmware_available_version or device.firmware_current_version or 'Unknown'}",
        },
        "upgrade": {
            "label": "Upgrade available",
            "class": "text-warning",
            "icon": "fa-solid fa-triangle-exclamation",
            "tooltip": f"Upgrade available: {device.firmware_available_version or 'Unknown'}",
        },
        "error": {
            "label": "Check failed",
            "class": "text-danger",
            "icon": "fa-solid fa-circle-xmark",
            "tooltip": f"Update check failed: {device.firmware_status_message or 'Unknown error'}",
        },
    }
    result = dict(mapping[status])
    if checked_at_text:
        result["tooltip"] = f"{result['tooltip']}\nLast checked: {checked_at_text}"
    return result


def current_brand_logo_url(db: Session | None = None) -> str | None:
    if uploaded_logo_path(settings.branding_upload_dir):
        return "/branding/logo"
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True
    try:
        integration_settings = db.get(IntegrationSettings, 1)
        return integration_settings.branding_logo_url if integration_settings else None
    finally:
        if close_db:
            db.close()


def render_template(
    db: Session | None, template_name: str, context: dict, status_code: int = 200
):
    payload = dict(context)
    payload.setdefault("brand_logo_url", current_brand_logo_url(db))
    payload.setdefault("device_license_label", device_license_label)
    payload.setdefault("device_license_expiration", device_license_expiration)
    payload.setdefault("firmware_status_ui", firmware_status_ui)
    payload.setdefault("format_datetime", format_datetime)
    payload.setdefault("app_timezone_name", app_timezone_info().key)
    return templates.TemplateResponse(
        template_name,
        payload,
        status_code=status_code,
    )


def create_user_session(db: Session, user: User) -> str:
    token = random_token(48)
    now = utc_now()
    db.add(
        SessionToken(
            user_id=user.id,
            token_hash=hash_session_token(settings.secret_key, token),
            created_at=now,
            expires_at=now + timedelta(hours=settings.session_ttl_hours),
        )
    )
    return token


def session_from_request(request: Request, db: Session) -> SessionToken:
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise HTTPException(status_code=401)
    token_hash = hash_session_token(settings.secret_key, token)
    session = db.scalar(
        select(SessionToken).where(SessionToken.token_hash == token_hash)
    )
    if not session or session.revoked_at or session.expires_at <= utc_now():
        raise HTTPException(status_code=401)
    return session


@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Annotated[Session, Depends(get_db)]):
    user = ui_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render_template(None, "login.html", {"request": request, "error": None})


@app.post("/api/v1/auth/login")
def login(
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    email: str = Form(...),
    password: str = Form(...),
):
    user = db.scalar(select(User).where(User.email == email.lower().strip()))
    if not user or not verify_secret(password, user.password_hash):
        return render_template(
            db,
            "login.html",
            {"request": request, "error": "Invalid email or password"},
            status_code=401,
        )
    token = create_user_session(db, user)
    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        secure=settings.session_secure,
        samesite="lax",
        max_age=settings.session_ttl_hours * 3600,
    )
    write_audit(db, request, "auth.login", user=user)
    db.commit()
    return response


@app.post("/api/v1/auth/logout")
def logout(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    session = session_from_request(request, db)
    session.revoked_at = utc_now()
    write_audit(db, request, "auth.logout", user=user)
    db.commit()
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(settings.session_cookie_name)
    return response


@app.get("/api/v1/auth/me")
def me(user: Annotated[User, Depends(current_user)]):
    return {"id": str(user.id), "email": user.email, "mfa_enabled": user.mfa_enabled}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    company_id: str | None = None,
    status: str | None = None,
    include_revoked: str | None = None,
):
    context = build_dashboard_context(
        db,
        user,
        {
            "company_id": company_id,
            "status": status,
            "include_revoked": include_revoked,
        },
    )
    context.update(
        {
            "request": request,
            "user": user,
            "active_page": "dashboard",
        }
    )
    return render_template(db, "dashboard.html", context)


@app.get("/companies", response_class=HTMLResponse)
def companies_page(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    companies = accessible_companies_for_user(db, user)
    company_ids = [company.id for company in companies]
    devices = (
        db.scalars(
            select(Device).where(Device.company_id.in_(company_ids)).order_by(Device.hostname)
        ).all()
        if company_ids
        else []
    )
    devices_by_company: dict[uuid.UUID, list[Device]] = {company.id: [] for company in companies}
    for device in devices:
        devices_by_company.setdefault(device.company_id, []).append(device)
    for company in companies:
        company.devices = devices_by_company.get(company.id, [])
    return render_template(
        db,
        "companies.html",
        {
            "request": request,
            "user": user,
            "companies": companies,
            "active_page": "companies",
        },
    )


@app.get("/settings", response_class=HTMLResponse)
def settings_redirect(user: Annotated[User, Depends(current_user)]):
    require_admin(user)
    return RedirectResponse("/settings/manage-companies", status_code=303)


@app.get("/settings/{section}", response_class=HTMLResponse)
def settings_page(
    request: Request,
    section: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    require_admin(user)
    allowed_sections = {
        "manage-companies",
        "manage-users",
        "email-settings",
        "microsoft-365",
        "local-ad",
        "branding",
        "backup",
    }
    if section not in allowed_sections:
        raise HTTPException(status_code=404)
    companies = db.scalars(select(Company).order_by(Company.name)).all()
    users = db.scalars(select(User).order_by(User.email)).all()
    integration_settings = get_or_create_integration_settings(db)
    return render_template(
        db,
        "settings.html",
        {
            "request": request,
            "user": user,
            "companies": companies,
            "users": users,
            "settings": integration_settings,
            "protected_admin_email": settings.initial_admin_email.lower(),
            "active_page": "settings",
            "active_settings": section,
            "status": request.query_params.get("status"),
        },
    )


@app.post("/settings/users")
def create_user(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    email: str = Form(...),
    password: str = Form(...),
    first_name: str = Form(""),
    last_name: str = Form(""),
    role: str = Form("user"),
):
    require_admin(user)
    role = role if role in {"user", "administrator"} else "user"
    normalized_email = email.lower().strip()
    if not normalized_email or not password:
        raise HTTPException(status_code=400, detail="email and password are required")
    if db.scalar(select(User).where(User.email == normalized_email)):
        raise HTTPException(status_code=400, detail="email already exists")
    db.add(
        User(
            email=normalized_email,
            password_hash=hash_secret(password),
            first_name=clean_optional(first_name),
            last_name=clean_optional(last_name),
            role=role,
        )
    )
    write_audit(db, request, "settings.user.create", user=user)
    db.commit()
    return RedirectResponse(
        "/settings/manage-users?status=user-created", status_code=303
    )


@app.post("/settings/users/{target_user_id}")
def update_user(
    request: Request,
    target_user_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    email: str = Form(...),
    password: str = Form(""),
    first_name: str = Form(""),
    last_name: str = Form(""),
    role: str = Form("user"),
):
    require_admin(user)
    target = db.get(User, target_user_id)
    if not target:
        raise HTTPException(status_code=404)
    role = role if role in {"user", "administrator"} else "user"
    normalized_email = email.lower().strip()
    duplicate = db.scalar(
        select(User).where(User.email == normalized_email, User.id != target.id)
    )
    if duplicate:
        raise HTTPException(status_code=400, detail="email already exists")
    target.email = normalized_email
    target.first_name = clean_optional(first_name)
    target.last_name = clean_optional(last_name)
    target.role = role
    if password.strip():
        target.password_hash = hash_secret(password)
    write_audit(db, request, "settings.user.update", user=user)
    db.commit()
    return RedirectResponse(
        "/settings/manage-users?status=user-updated", status_code=303
    )


@app.post("/settings/users/{target_user_id}/delete")
def delete_user(
    request: Request,
    target_user_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    require_admin(user)
    if target_user_id == user.id:
        raise HTTPException(status_code=400, detail="you cannot delete your own user")
    target = db.get(User, target_user_id)
    if not target:
        raise HTTPException(status_code=404)
    if target.email == settings.initial_admin_email.lower():
        raise HTTPException(
            status_code=400, detail="the default administrator user cannot be deleted"
        )
    db.execute(delete(CompanyUser).where(CompanyUser.user_id == target.id))
    db.delete(target)
    write_audit(db, request, "settings.user.delete", user=user)
    db.commit()
    return RedirectResponse(
        "/settings/manage-users?status=user-deleted", status_code=303
    )


@app.post("/settings/email")
def update_email_settings(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    smtp_enabled: str | None = Form(None),
    smtp_host: str = Form(""),
    smtp_port: str = Form(""),
    smtp_username: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from: str = Form(""),
    graph_enabled: str | None = Form(None),
    graph_tenant_id: str = Form(""),
    graph_client_id: str = Form(""),
    graph_client_secret: str = Form(""),
    graph_sender: str = Form(""),
):
    require_admin(user)
    integration_settings = get_or_create_integration_settings(db)
    use_smtp = smtp_enabled == "on"
    use_graph = graph_enabled == "on" and not use_smtp
    integration_settings.smtp_enabled = use_smtp
    integration_settings.graph_enabled = use_graph
    integration_settings.smtp_host = clean_optional(smtp_host)
    integration_settings.smtp_port = int(smtp_port) if smtp_port.strip() else None
    integration_settings.smtp_username = clean_optional(smtp_username)
    integration_settings.smtp_from = clean_optional(smtp_from)
    integration_settings.graph_tenant_id = clean_optional(graph_tenant_id)
    integration_settings.graph_client_id = clean_optional(graph_client_id)
    integration_settings.graph_sender = clean_optional(graph_sender)
    if smtp_password.strip():
        integration_settings.smtp_password = smtp_password
    if graph_client_secret.strip():
        integration_settings.graph_client_secret = graph_client_secret
    integration_settings.updated_at = utc_now()
    write_audit(db, request, "settings.email.update", user=user)
    db.commit()
    return RedirectResponse(
        "/settings/email-settings?status=email-saved", status_code=303
    )


@app.post("/settings/microsoft")
def update_microsoft_settings(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    microsoft_enabled: str | None = Form(None),
    microsoft_tenant_id: str = Form(""),
    microsoft_client_id: str = Form(""),
    microsoft_audience: str = Form(""),
    microsoft_authority: str = Form(""),
    microsoft_admin_group_name: str = Form(""),
    microsoft_admin_group_id: str = Form(""),
    microsoft_user_group_name: str = Form(""),
    microsoft_user_group_id: str = Form(""),
):
    require_admin(user)
    integration_settings = get_or_create_integration_settings(db)
    integration_settings.microsoft_enabled = microsoft_enabled == "on"
    integration_settings.microsoft_tenant_id = clean_optional(microsoft_tenant_id)
    integration_settings.microsoft_client_id = clean_optional(microsoft_client_id)
    integration_settings.microsoft_audience = clean_optional(microsoft_audience)
    integration_settings.microsoft_authority = clean_optional(microsoft_authority)
    integration_settings.microsoft_admin_group_name = clean_optional(
        microsoft_admin_group_name
    )
    integration_settings.microsoft_admin_group_id = clean_optional(
        microsoft_admin_group_id
    )
    integration_settings.microsoft_user_group_name = clean_optional(
        microsoft_user_group_name
    )
    integration_settings.microsoft_user_group_id = clean_optional(
        microsoft_user_group_id
    )
    integration_settings.updated_at = utc_now()
    write_audit(db, request, "settings.microsoft.update", user=user)
    db.commit()
    return RedirectResponse(
        "/settings/microsoft-365?status=microsoft-saved", status_code=303
    )


@app.post("/settings/local-ad")
def update_local_ad_settings(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    ad_enabled: str | None = Form(None),
    ad_host: str = Form(""),
    ad_base_dn: str = Form(""),
    ad_bind_dn: str = Form(""),
):
    require_admin(user)
    integration_settings = get_or_create_integration_settings(db)
    integration_settings.ad_enabled = ad_enabled == "on"
    integration_settings.ad_host = clean_optional(ad_host)
    integration_settings.ad_base_dn = clean_optional(ad_base_dn)
    integration_settings.ad_bind_dn = clean_optional(ad_bind_dn)
    integration_settings.updated_at = utc_now()
    write_audit(db, request, "settings.local_ad.update", user=user)
    db.commit()
    return RedirectResponse("/settings/local-ad?status=local-ad-saved", status_code=303)


@app.get("/branding/logo")
def branding_logo():
    logo_path = uploaded_logo_path(settings.branding_upload_dir)
    if not logo_path:
        raise HTTPException(status_code=404)
    media_type = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".webp": "image/webp",
    }[logo_path.suffix]
    return FileResponse(logo_path, media_type=media_type)


@app.post("/settings/branding")
async def update_branding_settings(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    branding_logo_url: str = Form(""),
    remove_logo: str | None = Form(None),
    branding_logo_file: UploadFile | None = File(None),
):
    require_admin(user)
    integration_settings = get_or_create_integration_settings(db)
    integration_settings.branding_logo_url = clean_optional(branding_logo_url)
    if remove_logo == "on":
        clear_uploaded_logo(settings.branding_upload_dir)
        integration_settings.branding_logo_url = None
    elif branding_logo_file and branding_logo_file.filename:
        content = await branding_logo_file.read()
        try:
            extension, _content_type = validate_branding_upload(
                branding_logo_file,
                content,
                settings.branding_logo_max_bytes,
            )
        except BrandingError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        save_uploaded_logo(settings.branding_upload_dir, extension, content)
    integration_settings.updated_at = utc_now()
    write_audit(db, request, "settings.branding.update", user=user)
    db.commit()
    return RedirectResponse("/settings/branding?status=branding-saved", status_code=303)


@app.post("/settings/backup/export")
def export_settings_backup(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    require_admin(user)
    bundle, filename = export_backup_bundle(db)
    write_audit(db, request, "settings.backup.export", user=user)
    db.commit()
    return Response(
        content=bundle,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/settings/backup/restore")
async def restore_settings_backup(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    backup_file: UploadFile = File(...),
):
    require_admin(user)
    content = await backup_file.read()
    if not content:
        raise HTTPException(status_code=400, detail="backup file is required")
    _manifest, data, logo_file, wireguard_private_key = parse_backup_bundle(content)
    restore_backup_bundle(db, data, logo_file, wireguard_private_key)
    db.execute(delete(SessionToken))
    db.commit()
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(settings.session_cookie_name)
    return response


@app.get("/api/v1/companies")
def list_companies(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    companies = db.scalars(
        select(Company)
        .join(CompanyUser)
        .where(CompanyUser.user_id == user.id)
        .order_by(Company.name)
    ).all()
    return [
        {"id": str(c.id), "name": c.name, "created_at": c.created_at.isoformat()}
        for c in companies
    ]


@app.post("/api/v1/companies")
def create_company(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    name: str = Form(...),
):
    company = Company(name=name.strip())
    db.add(company)
    db.flush()
    db.add(CompanyUser(company_id=company.id, user_id=user.id, role="owner"))
    write_audit(db, request, "company.create", user=user, company_id=company.id)
    db.commit()
    return RedirectResponse(f"/companies/{company.id}", status_code=303)


@app.post("/settings/companies")
def create_settings_company(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    name: str = Form(...),
):
    require_admin(user)
    normalized_name = name.strip()
    if not normalized_name:
        raise HTTPException(status_code=400, detail="company name is required")
    company = Company(name=normalized_name)
    db.add(company)
    db.flush()
    db.add(CompanyUser(company_id=company.id, user_id=user.id, role="owner"))
    write_audit(
        db, request, "settings.company.create", user=user, company_id=company.id
    )
    db.commit()
    return RedirectResponse(
        "/settings/manage-companies?status=company-created", status_code=303
    )


@app.post("/settings/companies/{company_id}")
def update_company(
    request: Request,
    company_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    name: str = Form(...),
):
    require_admin(user)
    company = db.get(Company, company_id)
    if not company:
        raise HTTPException(status_code=404)
    normalized_name = name.strip()
    if not normalized_name:
        raise HTTPException(status_code=400, detail="company name is required")
    company.name = normalized_name
    write_audit(
        db, request, "settings.company.update", user=user, company_id=company.id
    )
    db.commit()
    return RedirectResponse(
        "/settings/manage-companies?status=company-updated", status_code=303
    )


@app.post("/settings/companies/{company_id}/delete")
def delete_company(
    request: Request,
    company_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    require_admin(user)
    company = db.get(Company, company_id)
    if not company:
        raise HTTPException(status_code=404)
    devices = db.scalars(select(Device).where(Device.company_id == company.id)).all()
    for device in devices:
        if not device.revoked_at:
            remove_peer(device.wg_public_key)
    device_ids = [device.id for device in devices]
    if device_ids:
        db.execute(delete(DeviceEvent).where(DeviceEvent.device_id.in_(device_ids)))
    db.execute(delete(Device).where(Device.company_id == company.id))
    db.execute(delete(EnrollmentCode).where(EnrollmentCode.company_id == company.id))
    db.execute(delete(CompanyUser).where(CompanyUser.company_id == company.id))
    write_audit(
        db, request, "settings.company.delete", user=user, company_id=company.id
    )
    db.delete(company)
    db.commit()
    return RedirectResponse(
        "/settings/manage-companies?status=company-deleted", status_code=303
    )


@app.get("/companies/{company_id}", response_class=HTMLResponse)
def company_detail(
    request: Request,
    company_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    company = require_company(db, user, company_id)
    devices = db.scalars(
        select(Device).where(Device.company_id == company.id).order_by(Device.hostname)
    ).all()
    codes = db.scalars(
        select(EnrollmentCode)
        .where(EnrollmentCode.company_id == company.id)
        .order_by(EnrollmentCode.created_at.desc())
        .limit(5)
    ).all()
    return render_template(
        db,
        "company_detail.html",
        {
            "request": request,
            "user": user,
            "company": company,
            "devices": devices,
            "codes": codes,
            "now": utc_now(),
            "active_page": "companies",
        },
    )


@app.get("/api/v1/companies/{company_id}")
def get_company(
    company_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    company = require_company(db, user, company_id)
    return {"id": str(company.id), "name": company.name}


@app.post("/api/v1/companies/{company_id}/enrollment-codes")
def create_enrollment_code(
    request: Request,
    company_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    company = require_company(db, user, company_id, "admin")
    code = random_otp()
    expires_at = utc_now() + timedelta(minutes=settings.otp_ttl_minutes)
    db.add(
        EnrollmentCode(
            company_id=company.id,
            code_hash=hash_secret(code),
            expires_at=expires_at,
            created_by=user.id,
        )
    )
    write_audit(db, request, "enrollment_code.create", user=user, company_id=company.id)
    db.commit()
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse(
            {
                "code": code,
                "company": company.name,
                "expires_at": expires_at.isoformat(),
                "expires_at_display": format_datetime(expires_at, include_tz=True),
            }
        )
    return render_template(
        db,
        "otp.html",
        {
            "request": request,
            "company": company,
            "code": code,
            "expires_at": expires_at,
        },
    )


@app.post("/api/v1/enroll")
def enroll(
    payload: dict[str, object],
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    otp = str(payload.get("otp", "")).strip().upper()
    wg_public_key = str(payload.get("wg_public_key", "")).strip()
    hostname = str(payload.get("hostname", "")).strip()[:255]
    if not otp or not hostname or not wg_public_key:
        raise HTTPException(
            status_code=400, detail="otp, hostname and wg_public_key are required"
        )
    now = utc_now()
    codes = db.scalars(
        select(EnrollmentCode).where(
            EnrollmentCode.used_at.is_(None), EnrollmentCode.expires_at > now
        )
    ).all()
    matched = next((code for code in codes if verify_secret(otp, code.code_hash)), None)
    if not matched:
        raise HTTPException(
            status_code=401, detail="invalid or expired enrollment code"
        )
    tunnel_ip = next_tunnel_ip(db)
    token = random_token(48)
    device = Device(
        company_id=matched.company_id,
        hostname=hostname,
        opnsense_version=payload.get("opnsense_version"),
        plugin_version=payload.get("plugin_version"),
        wg_public_key=wg_public_key,
        wg_tunnel_ip=tunnel_ip,
        device_token_hash=hash_secret(token),
        status="online",
        last_seen_at=now,
    )
    apply_device_license_payload(device, payload)
    try:
        add_peer(wg_public_key, tunnel_ip)
    except WireGuardError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    matched.used_at = now
    db.add(device)
    db.flush()
    db.add(
        DeviceEvent(
            device_id=device.id, event_type="enrolled", message="Device enrolled"
        )
    )
    write_audit(
        db, request, "device.enroll", company_id=device.company_id, device_id=device.id
    )
    db.commit()
    return {
        "device_id": str(device.id),
        "device_token": token,
        "wireguard": {
            "interface_address": f"{tunnel_ip}/32",
            "server_public_key": get_server_public_key(),
            "endpoint": settings.hub_wg_endpoint,
            "allowed_ips": client_allowed_ips(),
            "persistent_keepalive": 25,
        },
    }


def device_from_token(
    db: Session, device_id: uuid.UUID, authorization: str | None
) -> Device:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401)
    token = authorization.removeprefix("Bearer ").strip()
    device = db.get(Device, device_id)
    if (
        not device
        or device.revoked_at
        or not verify_secret(token, device.device_token_hash)
    ):
        raise HTTPException(status_code=401)
    return device


@app.post("/api/v1/devices/{device_id}/heartbeat")
def heartbeat(
    device_id: uuid.UUID,
    payload: dict[str, object],
    db: Annotated[Session, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
):
    device = device_from_token(db, device_id, authorization)
    device.status = str(payload.get("status", "online"))[:30]
    device.health_missed_checks = 0
    device.health_success_checks += 1
    device.hostname = str(payload.get("hostname", device.hostname))[:255]
    opnsense_version = payload.get("opnsense_version")
    if opnsense_version is not None:
        device.opnsense_version = str(opnsense_version)[:80]
    plugin_version = payload.get("plugin_version")
    if plugin_version is not None:
        device.plugin_version = str(plugin_version)[:80]
    apply_device_license_payload(device, payload)
    firmware_applied = apply_device_firmware_payload(device, payload)
    device.last_seen_at = utc_now()
    if firmware_applied or device.status != "online":
        event_message = device.status
        if firmware_applied:
            event_message = (
                f"{device.status}; firmware={device.firmware_status}; "
                f"updates={device.firmware_update_count}"
            )[:1000]
        db.add(
            DeviceEvent(device_id=device.id, event_type="heartbeat", message=event_message)
        )
    pending_firmware_check = device.firmware_check_requested_at is not None
    pending_firmware_check_at = device.firmware_check_requested_at
    pending_firmware_check_reason = device.firmware_check_request_reason
    pending_backup = mark_device_backup_requested(device)
    pending_backup_at = device.backup_last_requested_at
    db.commit()
    return {
        "ok": True,
        "firmware_check_requested": pending_firmware_check,
        "firmware_check_requested_at": pending_firmware_check_at.isoformat()
        if pending_firmware_check_at
        else None,
        "firmware_check_request_reason": pending_firmware_check_reason,
        "backup_requested": pending_backup,
        "backup_requested_at": pending_backup_at.isoformat()
        if pending_backup_at
        else None,
        "backup_retention_count": device.backup_retention_count
        if (device.backup_enabled or pending_backup)
        else None,
        "backup_interval_hours": device.backup_interval_hours
        if (device.backup_enabled or pending_backup)
        else None,
    }


@app.post("/api/v1/devices/{device_id}/backups")
def upload_device_backup(
    device_id: uuid.UUID,
    payload: dict[str, object],
    db: Annotated[Session, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
):
    device = device_from_token(db, device_id, authorization)
    if not device.backup_enabled and not backup_request_pending(device):
        raise HTTPException(status_code=400, detail="backups are disabled for this firewall")
    content = str(payload.get("content", ""))
    if not content.strip():
        raise HTTPException(status_code=400, detail="backup content is required")
    if len(content) > DEVICE_BACKUP_CONTENT_MAX_LENGTH:
        raise HTTPException(status_code=400, detail="backup content is too large")
    created_at = parse_uploaded_backup_created_at(payload.get("created_at"))
    filename = clean_optional(str(payload.get("filename", ""))) or normalize_backup_filename(
        device, created_at
    )
    backup = DeviceBackup(
        device_id=device.id,
        filename=filename[:255],
        content=content,
        created_at=created_at,
    )
    device.backup_last_uploaded_at = utc_now()
    device.backup_last_requested_at = None
    db.add(backup)
    db.flush()
    backups = db.scalars(
        select(DeviceBackup)
        .where(DeviceBackup.device_id == device.id)
        .order_by(DeviceBackup.created_at.desc(), DeviceBackup.id.desc())
    ).all()
    for stale_backup in backups[device.backup_retention_count :]:
        db.delete(stale_backup)
    db.add(
        DeviceEvent(
            device_id=device.id,
            event_type="backup_uploaded",
            message=f"Configuration backup uploaded: {backup.filename}"[:1000],
        )
    )
    db.commit()
    return {
        "ok": True,
        "backup_id": str(backup.id),
        "filename": backup.filename,
        "created_at": backup.created_at.isoformat(),
        "retained_count": min(len(backups), device.backup_retention_count),
    }


@app.get("/api/v1/companies/{company_id}/devices")
def list_devices(
    company_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    company = require_company(db, user, company_id)
    devices = db.scalars(
        select(Device).where(Device.company_id == company.id).order_by(Device.hostname)
    ).all()
    return [
        {
            "id": str(d.id),
            "hostname": d.hostname,
            "status": d.status,
            "tunnel_ip": str(d.wg_tunnel_ip),
            "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
            "license": device_license_label(d),
            "license_expires_at": d.license_expires_at.isoformat()
            if d.license_expires_at
            else None,
            "firmware_status": d.firmware_status,
            "firmware_update_available": d.firmware_update_available,
            "firmware_available_version": d.firmware_available_version,
            "firmware_checked_at": d.firmware_checked_at.isoformat()
            if d.firmware_checked_at
            else None,
        }
        for d in devices
    ]


@app.get("/devices/{device_id}", response_class=HTMLResponse)
def device_page(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id):
        raise HTTPException(status_code=404)
    can_edit_notification_settings = has_company_access(
        db, user, device.company_id, "admin"
    )
    integration_settings = get_or_create_integration_settings(db)
    company = db.get(Company, device.company_id)
    backups = db.scalars(
        select(DeviceBackup)
        .where(DeviceBackup.device_id == device.id)
        .order_by(DeviceBackup.created_at.desc())
    ).all()
    events = db.scalars(
        select(DeviceEvent)
        .where(DeviceEvent.device_id == device.id)
        .order_by(DeviceEvent.created_at.desc())
        .limit(10)
    ).all()
    return render_template(
        db,
        "device.html",
        {
            "request": request,
            "user": user,
            "company": company,
            "device": device,
            "backups": backups,
            "can_edit_notification_settings": can_edit_notification_settings,
            "email_settings_configured": email_settings_configured(
                integration_settings
            ),
            "events": events,
            "active_page": "companies",
            "status": request.query_params.get("status"),
        },
    )


@app.get("/api/v1/devices/{device_id}")
def get_device(
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id):
        raise HTTPException(status_code=404)
    return {
        "id": str(device.id),
        "hostname": device.hostname,
        "opnsense_version": device.opnsense_version,
        "plugin_version": device.plugin_version,
        "license": device_license_label(device),
        "license_expires_at": device.license_expires_at.isoformat()
        if device.license_expires_at
        else None,
        "tunnel_ip": str(device.wg_tunnel_ip),
        "status": device.status,
        "firmware_status": device.firmware_status,
        "firmware_update_available": device.firmware_update_available,
        "firmware_update_type": device.firmware_update_type,
        "firmware_current_version": device.firmware_current_version,
        "firmware_available_version": device.firmware_available_version,
        "firmware_update_count": device.firmware_update_count,
        "firmware_reboot_required": device.firmware_reboot_required,
        "firmware_status_message": device.firmware_status_message,
        "firmware_checked_at": device.firmware_checked_at.isoformat()
        if device.firmware_checked_at
        else None,
        "backup_enabled": device.backup_enabled,
        "backup_retention_count": device.backup_retention_count,
        "backup_interval_value": device.backup_interval_value,
        "backup_interval_unit": device.backup_interval_unit,
        "backup_interval_hours": device.backup_interval_hours,
        "backup_last_requested_at": device.backup_last_requested_at.isoformat()
        if device.backup_last_requested_at
        else None,
        "backup_last_uploaded_at": device.backup_last_uploaded_at.isoformat()
        if device.backup_last_uploaded_at
        else None,
        "email_notifications_enabled": device.email_notifications_enabled,
        "email_notification_recipient": device.email_notification_recipient,
        "email_notify_on_warning": device.email_notify_on_warning,
        "email_notify_on_critical": device.email_notify_on_critical,
        "email_last_notified_status": device.email_last_notified_status,
        "email_last_notified_at": device.email_last_notified_at.isoformat()
        if device.email_last_notified_at
        else None,
        "revoked_at": device.revoked_at.isoformat() if device.revoked_at else None,
    }


@app.post("/devices/{device_id}/backup-settings")
def update_device_backup_settings(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    backup_enabled: str | None = Form(None),
    backup_retention_count: str = Form("3"),
    backup_interval_value: str = Form("24"),
    backup_interval_unit: str = Form("hours"),
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id, "admin"):
        raise HTTPException(status_code=404)
    device.backup_enabled = backup_enabled == "on"
    device.backup_retention_count = parse_bounded_int(
        backup_retention_count,
        field_name="backup retention count",
        minimum=1,
        maximum=DEVICE_BACKUP_RETENTION_MAX,
    )
    device.backup_interval_value = parse_bounded_int(
        backup_interval_value,
        field_name="backup interval value",
        minimum=1,
        maximum=DEVICE_BACKUP_INTERVAL_VALUE_MAX,
    )
    device.backup_interval_unit = parse_backup_interval_unit(backup_interval_unit)
    device.backup_interval_hours = max(
        1, int(backup_interval_delta(device).total_seconds() // 3600)
    )
    if device.backup_enabled:
        mark_device_backup_requested(device)
    else:
        device.backup_last_requested_at = None
    write_audit(
        db,
        request,
        "device.backup_settings.update",
        user=user,
        company_id=device.company_id,
        device_id=device.id,
    )
    db.commit()
    return RedirectResponse(
        f"/devices/{device.id}?status=backup-settings-saved", status_code=303
    )


@app.post("/devices/{device_id}/email-notification-settings")
def update_device_email_notification_settings(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    email_notifications_enabled: str | None = Form(None),
    email_notification_recipient: str = Form(""),
    email_notify_on_warning: str | None = Form(None),
    email_notify_on_critical: str | None = Form(None),
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id, "admin"):
        raise HTTPException(status_code=404)
    integration_settings = get_or_create_integration_settings(db)
    enabled = email_notifications_enabled == "on"
    recipient = clean_optional(email_notification_recipient)
    if enabled and not email_settings_configured(integration_settings):
        raise HTTPException(status_code=400, detail="email settings are not configured")
    if enabled and not is_valid_email_address(recipient):
        raise HTTPException(
            status_code=400, detail="a valid recipient email address is required"
        )
    device.email_notifications_enabled = enabled
    # Clear the stored recipient and notification state when notifications are disabled
    # so a stale address is not reused by accident if the firewall is later re-enabled.
    device.email_notification_recipient = recipient if enabled else None
    device.email_notify_on_warning = email_notify_on_warning == "on"
    device.email_notify_on_critical = email_notify_on_critical == "on"
    if not enabled:
        device.email_last_notified_status = None
        device.email_last_notified_at = None
    write_audit(
        db,
        request,
        "device.email_notification_settings.update",
        user=user,
        company_id=device.company_id,
        device_id=device.id,
    )
    db.commit()
    return RedirectResponse(
        f"/devices/{device.id}?status=email-notification-settings-saved",
        status_code=303,
    )


@app.post("/devices/{device_id}/backup-now")
def request_device_backup_now(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id, "admin"):
        raise HTTPException(status_code=404)
    device.backup_last_requested_at = utc_now()
    write_audit(
        db,
        request,
        "device.backup.request_now",
        user=user,
        company_id=device.company_id,
        device_id=device.id,
    )
    db.commit()
    return RedirectResponse(
        f"/devices/{device.id}?status=backup-requested", status_code=303
    )


@app.get("/devices/{device_id}/backups/{backup_id}/download")
def download_device_backup(
    device_id: uuid.UUID,
    backup_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id):
        raise HTTPException(status_code=404)
    backup = db.get(DeviceBackup, backup_id)
    if not backup or backup.device_id != device.id:
        raise HTTPException(status_code=404)
    headers = {"Content-Disposition": f'attachment; filename="{backup.filename}"'}
    return Response(
        content=backup.content.encode("utf-8"),
        media_type="application/xml",
        headers=headers,
    )


@app.post("/api/v1/devices/{device_id}/revoke")
def revoke_device(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id, "admin"):
        raise HTTPException(status_code=404)
    if not device.revoked_at:
        remove_peer(device.wg_public_key)
        device.revoked_at = utc_now()
        device.status = "revoked"
        device.device_token_hash = hash_secret(random_token(48))
        db.add(
            DeviceEvent(
                device_id=device.id, event_type="revoked", message="Device revoked"
            )
        )
        write_audit(
            db,
            request,
            "device.revoke",
            user=user,
            company_id=device.company_id,
            device_id=device.id,
        )
        db.commit()
    return RedirectResponse(f"/companies/{device.company_id}", status_code=303)


@app.post("/api/v1/devices/{device_id}/delete")
def delete_revoked_device(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    redirect_to: str = Form("/companies"),
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id, "admin"):
        raise HTTPException(status_code=404)
    if not device.revoked_at:
        raise HTTPException(
            status_code=400, detail="only revoked firewalls can be removed"
        )
    company_id = device.company_id
    db.execute(delete(DeviceEvent).where(DeviceEvent.device_id == device.id))
    write_audit(
        db,
        request,
        "device.delete_revoked",
        user=user,
        company_id=company_id,
    )
    db.delete(device)
    db.commit()
    if not redirect_to.startswith("/") or redirect_to.startswith("//"):
        redirect_to = "/companies"
    return RedirectResponse(redirect_to, status_code=303)


@app.api_route(
    "/proxy/devices/{device_id}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
async def proxy_device(
    request: Request,
    device_id: uuid.UUID,
    path: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = db.get(Device, device_id)
    if (
        not device
        or device.revoked_at
        or not has_company_access(db, user, device.company_id)
    ):
        raise HTTPException(status_code=404)
    write_audit(
        db,
        request,
        "device.proxy.open",
        user=user,
        company_id=device.company_id,
        device_id=device.id,
    )
    db.commit()
    try:
        url = device_webgui_url(device) + path
        if request.url.query:
            url += "?" + request.url.query
    except ValueError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Stored WireGuard tunnel IP is invalid: {device.wg_tunnel_ip}",
        ) from exc
    try:
        async with httpx.AsyncClient(
            verify=settings.proxy_verify_tls, follow_redirects=False, timeout=30
        ) as client:
            proxied = await client.request(
                request.method,
                url,
                headers=proxy_request_headers(request, device_id),
                content=await request.body(),
            )
    except httpx.RequestError as exc:
        error_detail = str(exc) or repr(exc)
        raise HTTPException(
            status_code=502,
            detail=(
                f"Could not reach OPNsense UI at {url}: "
                f"{exc.__class__.__name__}: {error_detail}. "
                "Verify WireGuard has a recent handshake, the firewall allows "
                "Hub tunnel traffic to the WebGUI port, and the WebGUI listens "
                "on the tunnel interface."
            ),
        ) from exc
    response_headers = {
        k: v
        for k, v in proxied.headers.items()
        if k.lower()
        not in {
            "content-encoding",
            "content-length",
            "connection",
            "location",
            "set-cookie",
            "transfer-encoding",
        }
    }
    if location := proxied.headers.get("location"):
        response_headers["location"] = proxy_rewrite_location(
            location, device_id, device_webgui_url(device)
        )
    response = Response(
        content=proxy_rewrite_body(
            proxied.content, proxied.headers.get("content-type", ""), device_id
        ),
        status_code=proxied.status_code,
        headers=response_headers,
    )
    for cookie in proxy_downstream_set_cookie_headers(
        proxied.headers.get_list("set-cookie"), device_id
    ):
        response.headers.append("set-cookie", cookie)
    return response
