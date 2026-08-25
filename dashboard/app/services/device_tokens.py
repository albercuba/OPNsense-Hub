from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..models import Device
from ..security import hash_secret, random_token, utc_now
from ..web import settings


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def device_token_expiry(now: datetime | None = None) -> datetime:
    issued_at = _aware_utc(now or utc_now())
    return issued_at + timedelta(days=settings.device_token_ttl_days)


def issue_device_token(device: Device, now: datetime | None = None) -> str:
    issued_at = _aware_utc(now or utc_now())
    token = random_token(48)
    device.device_token_hash = hash_secret(token)
    device.device_token_issued_at = issued_at
    device.device_token_expires_at = device_token_expiry(issued_at)
    return token


def device_token_is_expired(device: Device, now: datetime | None = None) -> bool:
    expires_at = device.device_token_expires_at
    if expires_at is None:
        return True
    return _aware_utc(expires_at) <= _aware_utc(now or utc_now())


def device_token_rotation_due(device: Device, now: datetime | None = None) -> bool:
    expires_at = device.device_token_expires_at
    if expires_at is None:
        return True
    threshold = _aware_utc(now or utc_now()) + timedelta(
        days=settings.device_token_rotation_window_days
    )
    return _aware_utc(expires_at) <= threshold
