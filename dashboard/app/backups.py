from __future__ import annotations

from datetime import datetime, timedelta

from .models import Device
from .security import utc_now

DEVICE_BACKUP_RETENTION_MAX = 10
DEVICE_BACKUP_INTERVAL_HOURS_MAX = 24 * 30
DEVICE_BACKUP_INTERVAL_UNITS = {"hours", "days", "months"}
DEVICE_BACKUP_INTERVAL_VALUE_MAX = 999


def backup_interval_delta(device: Device) -> timedelta:
    unit = (device.backup_interval_unit or "hours").lower()
    value = max(1, int(device.backup_interval_value or 1))
    if unit == "days":
        return timedelta(days=value)
    if unit == "months":
        return timedelta(days=value * 30)
    return timedelta(hours=value)


def backup_request_pending(device: Device) -> bool:
    return bool(
        device.backup_last_requested_at
        and (
            device.backup_last_uploaded_at is None
            or device.backup_last_uploaded_at < device.backup_last_requested_at
        )
    )


def backup_due(device: Device, now: datetime | None = None) -> bool:
    if not device.backup_enabled:
        return False
    current_time = now or utc_now()
    if backup_request_pending(device):
        return True
    if device.backup_last_uploaded_at is None:
        return True
    return device.backup_last_uploaded_at + backup_interval_delta(device) <= current_time


def mark_device_backup_requested(device: Device, now: datetime | None = None) -> bool:
    current_time = now or utc_now()
    if backup_request_pending(device):
        return True
    if not backup_due(device, now=current_time):
        return False
    device.backup_last_requested_at = current_time
    return True
