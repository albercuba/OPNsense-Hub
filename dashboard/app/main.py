from __future__ import annotations

import asyncio
import contextlib

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .backups import backup_due, backup_interval_delta, backup_request_pending
from .config import get_settings
from .database import get_db
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
    run_device_health_checks_once,
    run_firmware_schedule_once,
)
from .services.notification_service import maybe_send_health_notification
from .web import APP_DIR, current_brand_logo_url, format_datetime, settings, templates

app = FastAPI(title=settings.app_name)
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")


@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    if should_enforce_csrf(request):
        await validate_csrf_request(request)
    response = await call_next(request)
    if getattr(request.state, "csrf_cookie_needs_set", False):
        response.set_cookie(
            settings.csrf_cookie_name,
            csrf_cookie_value_for_request(request),
            httponly=True,
            secure=settings.session_secure,
            samesite="lax",
        )
    return response


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
    rate_limiter.clear()


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

# Re-export commonly used symbols for tests and compatibility.
login = auth_router.login
logout = auth_router.logout
heartbeat = devices_router.heartbeat
request_device_backup_now = devices_router.request_device_backup_now
update_device_email_notification_settings = (
    devices_router.update_device_email_notification_settings
)
upload_device_backup = devices_router.upload_device_backup
