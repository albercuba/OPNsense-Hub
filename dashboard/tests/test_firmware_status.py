import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from app.main import (
    backup_due,
    backup_interval_delta,
    backup_request_pending,
    firmware_status_ui,
    heartbeat,
    request_device_backup_now,
    mark_devices_for_firmware_check,
    normalize_device_firmware_payload,
    run_firmware_schedule_once,
    upload_device_backup,
)
from app.models import Device, DeviceBackup, DeviceEvent
from app.security import hash_secret


class FakeScalarResult:
    def __init__(self, items):
        self._items = items

    def all(self):
        return self._items


class FakeDb:
    def __init__(self, devices=None, device=None, backups=None):
        self.devices = devices or ([] if device is None else [device])
        self.device = device
        self.backups = backups or []
        self.added = []
        self.deleted = []
        self.committed = False

    def scalars(self, statement):
        statement_text = str(statement)
        if "device_backups" in statement_text:
            ordered = sorted(
                self.backups, key=lambda item: (item.created_at, item.id), reverse=True
            )
            return FakeScalarResult(ordered)
        return FakeScalarResult(self.devices)

    def get(self, model, key):
        if model is Device and self.device and key == self.device.id:
            return self.device
        return None

    def add(self, obj):
        self.added.append(obj)
        if isinstance(obj, DeviceBackup) and obj not in self.backups:
            self.backups.append(obj)

    def commit(self):
        self.committed = True

    def flush(self):
        return None

    def delete(self, obj):
        self.deleted.append(obj)
        if obj in self.backups:
            self.backups.remove(obj)


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
        backup_enabled=False,
        backup_retention_count=3,
        backup_interval_value=24,
        backup_interval_unit="hours",
        backup_interval_hours=24,
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


def test_backup_due_when_enabled_and_never_uploaded():
    device = make_device(
        "fw-backup-due",
        backup_enabled=True,
        backup_retention_count=3,
        backup_interval_hours=24,
    )

    assert backup_due(device) is True


def test_backup_interval_delta_supports_days_and_months():
    days_device = make_device(
        "fw-backup-days",
        backup_enabled=True,
        backup_interval_value=2,
        backup_interval_unit="days",
    )
    months_device = make_device(
        "fw-backup-months",
        backup_enabled=True,
        backup_interval_value=3,
        backup_interval_unit="months",
    )

    assert backup_interval_delta(days_device).total_seconds() == 2 * 24 * 3600
    assert backup_interval_delta(months_device).total_seconds() == 90 * 24 * 3600


def test_heartbeat_response_includes_pending_backup_request():
    token = "device-token"
    device = make_device(
        "fw-backup-heartbeat",
        token=token,
        backup_enabled=True,
        backup_retention_count=4,
        backup_interval_value=12,
        backup_interval_unit="hours",
        backup_interval_hours=12,
    )
    db = FakeDb(device=device)

    response = heartbeat(
        device.id,
        {"status": "online", "hostname": "fw-backup-heartbeat"},
        db,
        authorization=f"Bearer {token}",
    )

    assert response["backup_requested"] is True
    assert response["backup_requested_at"] is not None
    assert response["backup_retention_count"] == 4
    assert response["backup_interval_hours"] == 12
    assert db.committed is True


def test_request_backup_now_marks_pending_request(monkeypatch):
    device = make_device(
        "fw-backup-now",
        backup_enabled=False,
        backup_retention_count=3,
        backup_interval_value=24,
        backup_interval_unit="hours",
        backup_interval_hours=24,
    )
    db = FakeDb(device=device)
    monkeypatch.setattr("app.main.has_company_role", lambda *args, **kwargs: True)

    response = request_device_backup_now(
        SimpleNamespace(client=None, headers={}),
        device.id,
        db,
        SimpleNamespace(id=uuid4(), role="administrator"),
    )

    assert response.status_code == 303
    assert backup_request_pending(device) is True
    assert device.backup_last_requested_at is not None
    assert db.committed is True


def test_heartbeat_response_includes_manual_backup_metadata_when_disabled():
    token = "device-token"
    requested_at = datetime.now(timezone.utc).replace(
        year=2026, month=6, day=26, hour=12, minute=0, second=0, microsecond=0
    )
    device = make_device(
        "fw-backup-manual",
        token=token,
        backup_enabled=False,
        backup_retention_count=5,
        backup_interval_value=24,
        backup_interval_unit="hours",
        backup_interval_hours=24,
        backup_last_requested_at=requested_at,
    )
    db = FakeDb(device=device)

    response = heartbeat(
        device.id,
        {"status": "online", "hostname": "fw-backup-manual"},
        db,
        authorization=f"Bearer {token}",
    )

    assert response["backup_requested"] is True
    assert response["backup_retention_count"] == 5
    assert response["backup_interval_hours"] == 24


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


def test_upload_device_backup_rotates_to_retention_limit():
    token = "device-token"
    uploaded_at = datetime(2026, 6, 25, 23, 0, tzinfo=timezone.utc)
    device = make_device(
        "fw-backup-upload",
        token=token,
        backup_enabled=True,
        backup_retention_count=2,
        backup_interval_hours=24,
        backup_last_requested_at=uploaded_at,
    )
    existing_backups = [
        DeviceBackup(
            id=uuid4(),
            device_id=device.id,
            filename="fw-backup-upload-backup-1.xml",
            content="<config>1</config>",
            created_at=datetime(2026, 6, 23, 23, 0, tzinfo=timezone.utc),
        ),
        DeviceBackup(
            id=uuid4(),
            device_id=device.id,
            filename="fw-backup-upload-backup-2.xml",
            content="<config>2</config>",
            created_at=datetime(2026, 6, 24, 23, 0, tzinfo=timezone.utc),
        ),
    ]
    db = FakeDb(device=device, backups=existing_backups)

    response = upload_device_backup(
        device.id,
        {
            "filename": "fw-backup-upload-backup-3.xml",
            "created_at": "2026-06-25T23:00:00Z",
            "content": "<config>3</config>",
        },
        db,
        authorization=f"Bearer {token}",
    )

    assert response["ok"] is True
    assert response["filename"] == "fw-backup-upload-backup-3.xml"
    assert len(db.backups) == 2
    assert len(db.deleted) == 1
    assert device.backup_last_requested_at is None
    assert device.backup_last_uploaded_at is not None
    assert any(
        isinstance(event, DeviceEvent) and event.event_type == "backup_uploaded"
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
    expected_checked_at = checked_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M")
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
