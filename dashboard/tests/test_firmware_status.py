import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from app.main import (
    firmware_status_ui,
    heartbeat,
    mark_devices_for_firmware_check,
    normalize_device_firmware_payload,
    run_firmware_schedule_once,
)
from app.models import Device, DeviceEvent
from app.security import hash_secret


class FakeScalarResult:
    def __init__(self, items):
        self._items = items

    def all(self):
        return self._items


class FakeDb:
    def __init__(self, devices=None, device=None):
        self.devices = devices or ([] if device is None else [device])
        self.device = device
        self.added = []
        self.committed = False

    def scalars(self, _statement):
        return FakeScalarResult(self.devices)

    def get(self, model, key):
        if model is Device and self.device and key == self.device.id:
            return self.device
        return None

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        self.committed = True


class FakeSessionContext:
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        return self.db

    def __exit__(self, exc_type, exc, tb):
        return False


def make_device(hostname, token="device-token", **overrides):
    now = datetime.now(timezone.utc)
    device = Device(
        id=uuid4(),
        company_id=uuid4(),
        hostname=hostname,
        wg_public_key="pubkey",
        wg_tunnel_ip=f"100.96.0.{10 + (abs(hash(hostname)) % 100)}/32",
        device_token_hash=hash_secret(token),
        status="online",
        health_missed_checks=0,
        health_success_checks=0,
        firmware_status="unknown",
        firmware_update_available=False,
        firmware_update_count=0,
        firmware_reboot_required=False,
        created_at=now,
    )
    for key, value in overrides.items():
        setattr(device, key, value)
    return device


def test_mark_devices_for_firmware_check_marks_only_active_devices_for_the_day():
    scheduled = (
        datetime.now()
        .astimezone()
        .replace(year=2026, month=6, day=25, hour=23, minute=0, second=0, microsecond=0)
    )
    active = make_device("fw-active")
    revoked = make_device("fw-revoked", revoked_at=scheduled)
    already_checked = make_device("fw-checked", firmware_checked_at=scheduled)
    pending = make_device(
        "fw-pending",
        firmware_check_requested_at=scheduled,
        firmware_check_request_reason="scheduled",
    )
    db = FakeDb(devices=[active, revoked, already_checked, pending])

    marked = mark_devices_for_firmware_check(db, now=scheduled)

    assert marked == 1
    assert active.firmware_check_requested_at == scheduled
    assert active.firmware_check_request_reason == "scheduled"
    assert revoked.firmware_check_requested_at is None
    assert already_checked.firmware_check_requested_at is None
    assert pending.firmware_check_requested_at == scheduled


def test_run_firmware_schedule_once_marks_devices_at_2300(monkeypatch):
    scheduled = (
        datetime.now()
        .astimezone()
        .replace(year=2026, month=6, day=25, hour=23, minute=0, second=0, microsecond=0)
    )
    device = make_device("fw-scheduled")
    db = FakeDb(devices=[device])
    monkeypatch.setattr("app.main.SessionLocal", lambda: FakeSessionContext(db))

    marked = asyncio.run(run_firmware_schedule_once(now=scheduled))

    assert marked == 1
    assert db.committed is True
    assert device.firmware_check_requested_at == scheduled


def test_heartbeat_response_includes_pending_firmware_request():
    token = "device-token"
    pending_at = datetime.now(timezone.utc).replace(
        year=2026, month=6, day=25, hour=23, minute=0, second=0, microsecond=0
    )
    device = make_device(
        "fw-heartbeat",
        token=token,
        firmware_check_requested_at=pending_at,
        firmware_check_request_reason="scheduled",
    )
    db = FakeDb(device=device)

    response = heartbeat(
        device.id,
        {"status": "online", "hostname": "fw-heartbeat"},
        db,
        authorization=f"Bearer {token}",
    )

    assert response["ok"] is True
    assert response["firmware_check_requested"] is True
    assert response["firmware_check_requested_at"] == pending_at.isoformat()
    assert response["firmware_check_request_reason"] == "scheduled"
    assert db.committed is True


def test_heartbeat_applies_firmware_result_and_clears_pending_request():
    token = "device-token"
    device = make_device(
        "fw-firmware",
        token=token,
        firmware_check_requested_at=datetime.now(timezone.utc).replace(
            year=2026, month=6, day=25, hour=23, minute=0, second=0, microsecond=0
        ),
        firmware_check_request_reason="scheduled",
    )
    db = FakeDb(device=device)

    response = heartbeat(
        device.id,
        {
            "status": "online",
            "hostname": "fw-firmware",
            "firmware": {
                "status": "update",
                "update_available": True,
                "update_type": "update",
                "current_version": "25.7.10",
                "available_version": "25.7.11",
                "update_count": 5,
                "reboot_required": True,
                "message": "There are 5 updates available.",
                "checked_at": "2026-06-25T23:03:00Z",
            },
        },
        db,
        authorization=f"Bearer {token}",
    )

    assert response["firmware_check_requested"] is False
    assert device.firmware_status == "update"
    assert device.firmware_update_available is True
    assert device.firmware_available_version == "25.7.11"
    assert device.firmware_update_count == 5
    assert device.firmware_reboot_required is True
    assert device.firmware_check_requested_at is None
    assert device.firmware_check_request_reason is None
    assert any(
        isinstance(event, DeviceEvent) and event.event_type == "heartbeat"
        for event in db.added
    )


def test_normalize_device_firmware_payload_normalizes_invalid_status_to_error():
    normalized = normalize_device_firmware_payload(
        {
            "firmware": {
                "status": "bogus",
                "message": "bad status",
                "checked_at": "2026-06-25T23:03:00Z",
            }
        }
    )

    assert normalized is not None
    assert normalized["status"] == "error"
    assert normalized["message"] == "bad status"


def test_firmware_status_ui_returns_expected_tooltip_and_class():
    checked_at = datetime(2026, 6, 25, 23, 3, tzinfo=timezone.utc)
    expected_checked_at = checked_at.astimezone().strftime("%Y-%m-%d %H:%M")
    update_device = SimpleNamespace(
        firmware_status="update",
        firmware_available_version="25.7.11",
        firmware_current_version="25.7.10",
        firmware_status_message=None,
        firmware_checked_at=checked_at,
        opnsense_version="25.7.10",
    )
    error_device = SimpleNamespace(
        firmware_status="error",
        firmware_available_version=None,
        firmware_current_version=None,
        firmware_status_message="probe failed",
        firmware_checked_at=None,
        opnsense_version=None,
    )

    update_ui = firmware_status_ui(update_device)
    error_ui = firmware_status_ui(error_device)

    assert update_ui["class"] == "text-info"
    assert update_ui["icon"] == "fa-solid fa-circle-exclamation"
    assert "Updates available: 25.7.11" in update_ui["tooltip"]
    assert f"Last checked: {expected_checked_at}" in update_ui["tooltip"]
    assert error_ui["class"] == "text-danger"
    assert error_ui["icon"] == "fa-solid fa-circle-xmark"
    assert error_ui["tooltip"] == "Update check failed: probe failed"
