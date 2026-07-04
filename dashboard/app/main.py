from __future__ import annotations

import asyncio
import contextlib
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .backups import backup_due, backup_interval_delta, backup_request_pending
from .database import SessionLocal, get_db
from .deps import current_user
from .hardening import apply_startup_hardening
from .rbac import has_company_role
from .routers import auth as auth_router
from .routers import companies as companies_router
from .routers import dashboard as dashboard_router
from .routers import devices as devices_router
from .routers import enrollment as enrollment_router
from .routers import proxy as proxy_router
from .routers import settings as settings_router
from .security.csrf import (
    csrf_cookie_value_for_request,
    should_enforce_csrf,
    validate_csrf_request,
)
from .security.rate_limit import rate_limiter
from .security.request_context import ensure_allowed_host
from .services import firmware_scheduler as firmware_scheduler_service
from .services import notification_service as notification_service_module
from .services.auth_service import session_from_request
from .services.backup_service import export_backup_bundle
from .services.db_migrations import bootstrap
from .services.firmware_scheduler import (
    device_health_check_loop,
    device_license_expiration,
    device_license_label,
    firmware_check_schedule_loop,
    firmware_status_local_date,
    firmware_status_ui,
    mark_devices_for_firmware_check,
    normalize_device_firmware_payload,
    normalize_device_license_payload,
    parse_license_expires_at,
    probe_device_webgui,
)
from .services.log_retention import log_retention_loop
from .services.notification_service import (
    maybe_send_health_notification,
    send_notification_email,
)
from .web import APP_DIR, current_brand_logo_url, format_datetime, settings, templates


@asynccontextmanager
async def lifespan(app: FastAPI):
    apply_startup_hardening(settings)
    bootstrap()
    app.state.health_check_task = asyncio.create_task(device_health_check_loop())
    app.state.firmware_schedule_task = asyncio.create_task(
        firmware_check_schedule_loop()
    )
    app.state.log_retention_task = (
        asyncio.create_task(log_retention_loop())
        if settings.log_retention_enabled
        else None
    )
    try:
        yield
    finally:
        for task_name in (
            "health_check_task",
            "firmware_schedule_task",
            "log_retention_task",
        ):
            task = getattr(app.state, task_name, None)
            if task is None:
                continue
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        rate_limiter.clear()


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    try:
        ensure_allowed_host(request)
    except HTTPException as exc:
        detail = exc.detail if exc.detail is not None else "Bad Request"
        return JSONResponse(status_code=exc.status_code, content={"detail": detail})
    if should_enforce_csrf(request):
        try:
            await validate_csrf_request(request)
        except HTTPException as exc:
            detail = exc.detail if exc.detail is not None else "Forbidden"
            return JSONResponse(status_code=exc.status_code, content={"detail": detail})
    response = await call_next(request)
    if getattr(request.state, "csrf_cookie_needs_set", False):
        response.set_cookie(
            settings.csrf_cookie_name,
            csrf_cookie_value_for_request(request),
            httponly=True,
            secure=settings.session_secure,
            samesite="lax",
        )
    if settings.security_headers_enabled:
        response.headers.setdefault(
            "Content-Security-Policy", settings.content_security_policy
        )
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", settings.referrer_policy)
        response.headers.setdefault("Permissions-Policy", settings.permissions_policy)
        if settings.session_secure:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401 and not request.url.path.startswith("/api/"):
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(settings.session_cookie_name)
        return response
    detail = exc.detail if exc.detail is not None else "Unauthorized"
    return JSONResponse(status_code=exc.status_code, content={"detail": detail})


app.include_router(auth_router.router)
app.include_router(dashboard_router.router)
app.include_router(settings_router.router)
app.include_router(companies_router.router)
app.include_router(enrollment_router.router)
app.include_router(devices_router.router)
app.include_router(proxy_router.router)


def _compat_post_request(path: str = "/") -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": [],
            "client": ("127.0.0.1", 0),
        }
    )


def _sync_scheduler_compat_exports() -> None:
    firmware_scheduler_service.SessionLocal = SessionLocal
    firmware_scheduler_service.httpx = httpx
    firmware_scheduler_service.probe_device_webgui = probe_device_webgui
    notification_service_module.send_notification_email = send_notification_email


# Re-export commonly used symbols for tests and compatibility.
login = auth_router.login
logout = auth_router.logout


def heartbeat(device_id, payload, db, authorization=None):
    return devices_router.heartbeat(
        device_id,
        payload,
        _compat_post_request(f"/api/v1/devices/{device_id}/heartbeat"),
        db,
        authorization,
    )


request_device_backup_now = devices_router.request_device_backup_now
update_device_email_notification_settings = (
    devices_router.update_device_email_notification_settings
)


async def run_device_health_checks_once():
    _sync_scheduler_compat_exports()
    await firmware_scheduler_service.run_device_health_checks_once()


async def run_firmware_schedule_once(now=None):
    _sync_scheduler_compat_exports()
    return await firmware_scheduler_service.run_firmware_schedule_once(now=now)


def upload_device_backup(device_id, payload, db, authorization=None):
    return devices_router.upload_device_backup(
        device_id,
        payload,
        _compat_post_request(f"/api/v1/devices/{device_id}/backups"),
        db,
        authorization,
    )


# Additional compatibility re-exports used by tests and existing imports.
current_brand_logo_url = current_brand_logo_url
format_datetime = format_datetime
templates = templates
backup_due = backup_due
backup_interval_delta = backup_interval_delta
backup_request_pending = backup_request_pending
device_license_expiration = device_license_expiration
device_license_label = device_license_label
firmware_status_local_date = firmware_status_local_date
firmware_status_ui = firmware_status_ui
mark_devices_for_firmware_check = mark_devices_for_firmware_check
normalize_device_firmware_payload = normalize_device_firmware_payload
normalize_device_license_payload = normalize_device_license_payload
parse_license_expires_at = parse_license_expires_at
run_device_health_checks_once = run_device_health_checks_once
run_firmware_schedule_once = run_firmware_schedule_once
maybe_send_health_notification = maybe_send_health_notification
has_company_role = has_company_role
get_db = get_db
SessionLocal = SessionLocal
current_user = current_user
session_from_request = session_from_request
export_backup_bundle = export_backup_bundle
