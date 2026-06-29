from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .branding import uploaded_logo_path
from .config import get_settings
from .database import SessionLocal
from .models import IntegrationSettings
from .security.csrf import get_or_create_csrf_token
from .services.common import clean_optional

settings = get_settings()
logger = logging.getLogger(__name__)
APP_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))


def app_timezone_info() -> ZoneInfo:
    try:
        return ZoneInfo(settings.app_timezone)
    except ZoneInfoNotFoundError:
        logger.warning(
            "Unknown app timezone %s; falling back to UTC", settings.app_timezone
        )
        return ZoneInfo("UTC")


def to_app_timezone(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(app_timezone_info())


def app_now() -> datetime:
    from .security import utc_now

    return utc_now().astimezone(app_timezone_info())


def format_datetime(value: datetime | None, include_tz: bool = False) -> str:
    if value is None:
        return ""
    fmt = "%Y-%m-%d %H:%M %Z" if include_tz else "%Y-%m-%d %H:%M"
    return to_app_timezone(value).strftime(fmt)


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
    from .services.firmware_scheduler import (
        device_license_expiration,
        device_license_label,
        firmware_status_ui,
    )

    payload = dict(context)
    request = payload.get("request")
    if request is not None:
        payload.setdefault("csrf_token", get_or_create_csrf_token(request))
    payload.setdefault("brand_logo_url", current_brand_logo_url(db))
    payload.setdefault("device_license_label", device_license_label)
    payload.setdefault("device_license_expiration", device_license_expiration)
    payload.setdefault("firmware_status_ui", firmware_status_ui)
    payload.setdefault("format_datetime", format_datetime)
    payload.setdefault("app_timezone_name", app_timezone_info().key)
    return templates.TemplateResponse(
        request, template_name, payload, status_code=status_code
    )
