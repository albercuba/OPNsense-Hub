import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from app.main import (
    maybe_send_health_notification,
    run_device_health_checks_once,
    templates,
    update_device_email_notification_settings,
)
from app.models import Company, Device, DeviceEvent, IntegrationSettings
from app.security import hash_secret
from fastapi import HTTPException


class FakeScalarResult:
    def __init__(self, items):
        self._items = items

    def all(self):
        return self._items


class FakeDb:
    def __init__(
        self, device=None, devices=None, integration_settings=None, company=None
    ):
        self.device = device
        self.devices = devices or ([] if device is None else [device])
        self.integration_settings = integration_settings
        self.company = company
        self.added = []
        self.committed = False

    def get(self, model, key):
        if model is Device and self.device and key == self.device.id:
            return self.device
        if model is IntegrationSettings and key == 1:
            return self.integration_settings
        if model is Company and self.company and key == self.company.id:
            return self.company
        return None

    def scalars(self, statement):
        statement_text = str(statement)
        if "FROM devices" in statement_text:
            filtered = [device for device in self.devices if not device.revoked_at]
            return FakeScalarResult(filtered)
        return FakeScalarResult([])

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


class FakeAsyncClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


def make_device(hostname="fw-01", **overrides):
    now = datetime.now(timezone.utc)
    device = Device(
        id=uuid4(),
        company_id=uuid4(),
        hostname=hostname,
        wg_public_key="pubkey",
        wg_tunnel_ip="100.96.0.10/32",
        device_token_hash=hash_secret("device-token"),
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
        email_notifications_enabled=False,
        email_notify_on_warning=True,
        email_notify_on_critical=True,
        created_at=now,
    )
    for key, value in overrides.items():
        setattr(device, key, value)
    return device


def make_integration_settings(configured=True):
    if configured:
        return IntegrationSettings(
            id=1,
            smtp_enabled=True,
            smtp_host="smtp.example.com",
            smtp_port=25,
            smtp_from="hub@example.com",
            graph_enabled=False,
        )
    return IntegrationSettings(id=1, smtp_enabled=False, graph_enabled=False)


def test_device_template_renders_email_notifications_section():
    device = make_device(
        email_notifications_enabled=True,
        email_notification_recipient="alerts@example.com",
    )
    company = Company(id=device.company_id, name="Acme")

    rendered = templates.get_template("device.html").render(
        request=SimpleNamespace(),
        user=SimpleNamespace(role="administrator", email="admin@example.com"),
        company=company,
        device=device,
        backups=[],
        events=[],
        can_edit_notification_settings=True,
        email_settings_configured=True,
        device_license_label=lambda _device: "Community",
        device_license_expiration=lambda _device: "-",
        firmware_status_ui=lambda _device: {},
        brand_logo_url=None,
        active_page="companies",
        status=None,
    )

    assert "Email notifications" in rendered
    assert "Recipient email address" in rendered


def test_device_template_disables_email_form_when_hub_email_not_configured():
    device = make_device(
        email_notifications_enabled=True,
        email_notification_recipient="alerts@example.com",
    )
    company = Company(id=device.company_id, name="Acme")

    rendered = templates.get_template("device.html").render(
        request=SimpleNamespace(),
        user=SimpleNamespace(role="administrator", email="admin@example.com"),
        company=company,
        device=device,
        backups=[],
        events=[],
        can_edit_notification_settings=True,
        email_settings_configured=False,
        device_license_label=lambda _device: "Community",
        device_license_expiration=lambda _device: "-",
        firmware_status_ui=lambda _device: {},
        brand_logo_url=None,
        active_page="companies",
        status=None,
    )

    assert "Email settings are not configured." in rendered
    assert "disabled" in rendered


def test_email_notification_settings_reject_when_email_not_configured(monkeypatch):
    device = make_device()
    db = FakeDb(
        device=device,
        integration_settings=make_integration_settings(configured=False),
        company=Company(id=device.company_id, name="Acme"),
    )
    monkeypatch.setattr("app.main.has_company_role", lambda *args, **kwargs: True)

    with pytest.raises(HTTPException) as exc:
        update_device_email_notification_settings(
            SimpleNamespace(client=None, headers={}),
            device.id,
            db,
            SimpleNamespace(id=uuid4(), role="administrator"),
            email_notifications_enabled="on",
            email_notification_recipient="alerts@example.com",
            email_notify_on_warning="on",
            email_notify_on_critical="on",
        )

    assert exc.value.status_code == 400
    assert "email settings are not configured" in exc.value.detail


def test_company_admin_can_save_email_notification_settings(monkeypatch):
    device = make_device()
    db = FakeDb(
        device=device,
        integration_settings=make_integration_settings(configured=True),
        company=Company(id=device.company_id, name="Acme"),
    )
    monkeypatch.setattr("app.main.has_company_role", lambda *args, **kwargs: True)

    response = update_device_email_notification_settings(
        SimpleNamespace(client=None, headers={}),
        device.id,
        db,
        SimpleNamespace(id=uuid4(), role="administrator"),
        email_notifications_enabled="on",
        email_notification_recipient="alerts@example.com",
        email_notify_on_warning="on",
        email_notify_on_critical=None,
    )

    assert response.status_code == 303
    assert device.email_notifications_enabled is True
    assert device.email_notification_recipient == "alerts@example.com"
    assert device.email_notify_on_warning is True
    assert device.email_notify_on_critical is False
    assert db.committed is True


def test_non_admin_cannot_save_email_notification_settings(monkeypatch):
    device = make_device()
    db = FakeDb(
        device=device,
        integration_settings=make_integration_settings(configured=True),
        company=Company(id=device.company_id, name="Acme"),
    )
    monkeypatch.setattr("app.main.has_company_role", lambda *args, **kwargs: False)

    with pytest.raises(HTTPException) as exc:
        update_device_email_notification_settings(
            SimpleNamespace(client=None, headers={}),
            device.id,
            db,
            SimpleNamespace(id=uuid4(), role="user"),
            email_notifications_enabled="on",
            email_notification_recipient="alerts@example.com",
            email_notify_on_warning="on",
            email_notify_on_critical="on",
        )

    assert exc.value.status_code == 404


def test_online_to_warning_transition_sends_one_email(monkeypatch):
    sent = []
    device = make_device(
        health_missed_checks=2,
        email_notifications_enabled=True,
        email_notification_recipient="alerts@example.com",
    )
    company = Company(id=device.company_id, name="Acme")
    db = FakeDb(
        device=device,
        devices=[device],
        integration_settings=make_integration_settings(configured=True),
        company=company,
    )
    monkeypatch.setattr("app.main.SessionLocal", lambda: FakeSessionContext(db))
    monkeypatch.setattr(
        "app.main.httpx.AsyncClient", lambda **kwargs: FakeAsyncClient()
    )

    async def fake_probe(_client, _device):
        return False, "unreachable"

    monkeypatch.setattr("app.main.probe_device_webgui", fake_probe)
    monkeypatch.setattr(
        "app.main.send_notification_email",
        lambda _db, to_email, subject, body: sent.append((to_email, subject, body)),
    )

    asyncio.run(run_device_health_checks_once())

    assert len(sent) == 1
    assert "warning" in sent[0][1]
    assert device.email_last_notified_status == "warning"
    assert any(
        isinstance(event, DeviceEvent) and event.event_type == "email_notification_sent"
        for event in db.added
    )


def test_repeated_warning_state_does_not_send_duplicate_emails(monkeypatch):
    sent = []
    device = make_device(
        status="warning",
        health_missed_checks=2,
        email_notifications_enabled=True,
        email_notification_recipient="alerts@example.com",
    )
    company = Company(id=device.company_id, name="Acme")
    db = FakeDb(
        device=device,
        devices=[device],
        integration_settings=make_integration_settings(configured=True),
        company=company,
    )
    monkeypatch.setattr("app.main.settings.firewall_health_critical_misses", 99)
    monkeypatch.setattr("app.main.SessionLocal", lambda: FakeSessionContext(db))
    monkeypatch.setattr(
        "app.main.httpx.AsyncClient", lambda **kwargs: FakeAsyncClient()
    )

    async def fake_probe(_client, _device):
        return False, "unreachable"

    monkeypatch.setattr("app.main.probe_device_webgui", fake_probe)
    monkeypatch.setattr(
        "app.main.send_notification_email",
        lambda _db, to_email, subject, body: sent.append((to_email, subject, body)),
    )

    asyncio.run(run_device_health_checks_once())

    assert sent == []
    assert device.status == "warning"


def test_warning_to_critical_transition_sends_email(monkeypatch):
    sent = []
    device = make_device(
        status="warning",
        health_missed_checks=4,
        email_notifications_enabled=True,
        email_notification_recipient="alerts@example.com",
    )
    company = Company(id=device.company_id, name="Acme")
    db = FakeDb(
        device=device,
        devices=[device],
        integration_settings=make_integration_settings(configured=True),
        company=company,
    )
    monkeypatch.setattr("app.main.SessionLocal", lambda: FakeSessionContext(db))
    monkeypatch.setattr(
        "app.main.httpx.AsyncClient", lambda **kwargs: FakeAsyncClient()
    )

    async def fake_probe(_client, _device):
        return False, "unreachable"

    monkeypatch.setattr("app.main.probe_device_webgui", fake_probe)
    monkeypatch.setattr(
        "app.main.send_notification_email",
        lambda _db, to_email, subject, body: sent.append((to_email, subject, body)),
    )

    asyncio.run(run_device_health_checks_once())

    assert len(sent) == 1
    assert "critical" in sent[0][1]
    assert device.status == "offline"


def test_backup_overdue_sends_email_once(monkeypatch):
    sent = []
    now = datetime.now(timezone.utc)
    device = make_device(
        backup_enabled=True,
        backup_last_uploaded_at=now.replace(hour=0, minute=0, second=0, microsecond=0),
        backup_interval_value=1,
        backup_interval_unit="hours",
        backup_interval_hours=1,
        email_notifications_enabled=True,
        email_notification_recipient="alerts@example.com",
    )
    company = Company(id=device.company_id, name="Acme")
    db = FakeDb(
        device=device,
        devices=[device],
        integration_settings=make_integration_settings(configured=True),
        company=company,
    )
    monkeypatch.setattr("app.main.SessionLocal", lambda: FakeSessionContext(db))
    monkeypatch.setattr(
        "app.main.httpx.AsyncClient", lambda **kwargs: FakeAsyncClient()
    )

    async def fake_probe(_client, _device):
        return True, "reachable"

    monkeypatch.setattr("app.main.probe_device_webgui", fake_probe)
    monkeypatch.setattr(
        "app.main.send_notification_email",
        lambda _db, to_email, subject, body: sent.append((to_email, subject, body)),
    )

    asyncio.run(run_device_health_checks_once())

    assert len(sent) == 1
    assert "Backup overdue" in sent[0][1]
    assert device.backup_overdue_notified_at is not None


def test_disabled_notification_status_does_not_send_email():
    sent = []
    device = make_device(
        email_notifications_enabled=True,
        email_notification_recipient="alerts@example.com",
        email_notify_on_warning=False,
    )
    result = maybe_send_health_notification(
        FakeDb(
            device=device,
            integration_settings=make_integration_settings(configured=True),
            company=Company(id=device.company_id, name="Acme"),
        ),
        device,
        "online",
        "warning",
        datetime.now(timezone.utc),
        email_sender=lambda _db, to_email, subject, body: sent.append(
            (to_email, subject, body)
        ),
    )

    assert result is False
    assert sent == []


def test_revoked_device_does_not_send_email():
    sent = []
    now = datetime.now(timezone.utc)
    device = make_device(
        email_notifications_enabled=True,
        email_notification_recipient="alerts@example.com",
        revoked_at=now,
    )
    result = maybe_send_health_notification(
        FakeDb(
            device=device,
            integration_settings=make_integration_settings(configured=True),
            company=Company(id=device.company_id, name="Acme"),
        ),
        device,
        "online",
        "warning",
        now,
        email_sender=lambda _db, to_email, subject, body: sent.append(
            (to_email, subject, body)
        ),
    )

    assert result is False
    assert sent == []


def test_email_send_failure_creates_device_event_and_does_not_crash(monkeypatch):
    device = make_device(
        health_missed_checks=2,
        email_notifications_enabled=True,
        email_notification_recipient="alerts@example.com",
    )
    company = Company(id=device.company_id, name="Acme")
    db = FakeDb(
        device=device,
        devices=[device],
        integration_settings=make_integration_settings(configured=True),
        company=company,
    )
    monkeypatch.setattr("app.main.SessionLocal", lambda: FakeSessionContext(db))
    monkeypatch.setattr(
        "app.main.httpx.AsyncClient", lambda **kwargs: FakeAsyncClient()
    )

    async def fake_probe(_client, _device):
        return False, "unreachable"

    monkeypatch.setattr("app.main.probe_device_webgui", fake_probe)

    def failing_sender(_db, _to_email, _subject, _body):
        raise RuntimeError("boom")

    monkeypatch.setattr("app.main.send_notification_email", failing_sender)

    asyncio.run(run_device_health_checks_once())

    assert any(
        isinstance(event, DeviceEvent)
        and event.event_type == "email_notification_failed"
        for event in db.added
    )
    assert db.committed is True
