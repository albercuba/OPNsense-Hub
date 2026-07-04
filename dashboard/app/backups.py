from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .models import Device
from .security import utc_now

DEVICE_BACKUP_RETENTION_MAX = 10
DEVICE_BACKUP_INTERVAL_HOURS_MAX = 24 * 30
DEVICE_BACKUP_INTERVAL_UNITS = {"hours", "days", "months"}
DEVICE_BACKUP_INTERVAL_VALUE_MAX = 999


def _utc_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def backup_interval_delta(device: Device) -> timedelta:
    unit = (device.backup_interval_unit or "hours").lower()
    value = max(1, int(device.backup_interval_value or 1))
    if unit == "days":
        return timedelta(days=value)
    if unit == "months":
        return timedelta(days=value * 30)
    return timedelta(hours=value)


def backup_request_pending(device: Device) -> bool:
    requested_at = _utc_datetime(device.backup_last_requested_at)
    uploaded_at = _utc_datetime(device.backup_last_uploaded_at)
    return bool(requested_at and (uploaded_at is None or uploaded_at < requested_at))


def backup_due(device: Device, now: datetime | None = None) -> bool:
    if not device.backup_enabled:
        return False
    current_time = _utc_datetime(now or utc_now())
    if backup_request_pending(device):
        return True
    uploaded_at = _utc_datetime(device.backup_last_uploaded_at)
    if uploaded_at is None:
        return True
    assert current_time is not None
    return uploaded_at + backup_interval_delta(device) <= current_time


def mark_device_backup_requested(device: Device, now: datetime | None = None) -> bool:
    current_time = _utc_datetime(now or utc_now())
    if backup_request_pending(device):
        return True
    if not backup_due(device, now=current_time):
        return False
    device.backup_last_requested_at = current_time
    return True
