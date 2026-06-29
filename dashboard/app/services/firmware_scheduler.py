from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from datetime import date, datetime, timezone
from typing import cast

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..backups import (
    DEVICE_BACKUP_INTERVAL_UNITS,
    backup_interval_delta,
    backup_request_pending,
    mark_device_backup_requested,
)
from ..database import SessionLocal
from ..health import HealthState, HealthThresholds, next_health_state
from ..models import Company, Device, DeviceEvent
from ..security import utc_now
from ..web import app_now, format_datetime, settings, to_app_timezone
from .notification_service import maybe_send_health_notification

logger = logging.getLogger(__name__)
FIRMWARE_STATUSES = {"unknown", "none", "update", "upgrade", "error"}
FIRMWARE_VERSION_MAX_LENGTH = 80
FIRMWARE_MESSAGE_MAX_LENGTH = 500
DEVICE_BACKUP_CONTENT_MAX_LENGTH = 2_000_000


def tunnel_proxy_host(value: object) -> str:
    text_value = str(value)
    if "/" in text_value:
        return str(ipaddress.ip_interface(text_value).ip)
    return str(ipaddress.ip_address(text_value))


def device_webgui_url(device: Device) -> str:
    proxy_host = tunnel_proxy_host(device.wg_tunnel_ip)
    return f"https://{proxy_host}:{settings.opnsense_gui_port}/"


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
                                f"{message}; missed={device.health_missed_checks}; successes={device.health_success_checks}"
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


def parse_bounded_int(
    value: object, *, field_name: str, minimum: int, maximum: int
) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=400, detail=f"{field_name} must be a number"
        ) from exc
    if parsed < minimum or parsed > maximum:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=400,
            detail=f"{field_name} must be between {minimum} and {maximum}",
        )
    return parsed


def parse_backup_interval_unit(value: object) -> str:
    normalized = str(value).strip().lower()
    if normalized not in DEVICE_BACKUP_INTERVAL_UNITS:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=400,
            detail="backup interval unit must be hours, days, or months",
        )
    return normalized


def normalize_backup_filename(device: Device, created_at: datetime) -> str:
    safe_hostname = (
        re.sub(r"[^A-Za-z0-9._-]+", "-", device.hostname).strip("-") or "firewall"
    )
    return f"{safe_hostname}-backup-{created_at.strftime('%Y%m%d%H%M%S')}.xml"


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
    from .common import clean_optional

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
    device.firmware_update_type = cast(str | None, firmware["update_type"])
    device.firmware_current_version = cast(str | None, firmware["current_version"])
    device.firmware_available_version = cast(str | None, firmware["available_version"])
    device.firmware_update_count = int(cast(int, firmware["update_count"]))
    device.firmware_reboot_required = bool(firmware["reboot_required"])
    device.firmware_status_message = cast(str | None, firmware["message"])
    device.firmware_checked_at = cast(datetime, firmware["checked_at"])
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
    checked_at_text = (
        format_datetime(device.firmware_checked_at)
        if device.firmware_checked_at
        else None
    )
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
