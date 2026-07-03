from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from app.dashboard import (
    build_dashboard_context,
    dashboard_backup_status,
    dashboard_license_status,
)
from app.database import get_db
from app.integration import email_settings_configured
from app.main import app, current_user
from app.models import Company, Device, DeviceEvent, IntegrationSettings, User
from app.security import hash_secret
from fastapi.testclient import TestClient


class FakeScalarResult:
    def __init__(self, items):
        self._items = list(items)

    def all(self):
        return list(self._items)


class FakeDb:
    def __init__(self, integration_settings=None, events=None):
        self.integration_settings = integration_settings
        self.events = list(events or [])

    def get(self, model, key):
        if model is IntegrationSettings and key == 1:
            return self.integration_settings
        return None

    def scalars(self, statement):
        statement_text = str(statement)
        if "FROM device_events" not in statement_text:
            return FakeScalarResult([])
        compiled = statement.compile(compile_kwargs={"render_postcompile": True})
        allowed_device_ids = set()
        for key, value in compiled.params.items():
            if "device_id" not in key:
                continue
            if isinstance(value, (list, tuple, set)):
                allowed_device_ids.update(value)
            else:
                allowed_device_ids.add(value)
        items = [
            event
            for event in self.events
            if not allowed_device_ids or event.device_id in allowed_device_ids
        ]
        if "email_notification_failed" in statement_text:
            items = [
                event
                for event in items
                if event.event_type == "email_notification_failed"
            ]
        if "email_notification_sent" in statement_text:
            items = [
                event
                for event in items
                if event.event_type == "email_notification_sent"
            ]
        items.sort(key=lambda event: event.created_at, reverse=True)
        limit_clause = getattr(statement, "_limit_clause", None)
        if (
            limit_clause is not None
            and getattr(limit_clause, "value", None) is not None
        ):
            items = items[: int(limit_clause.value)]
        return FakeScalarResult(items)

    def scalar(self, statement):
        items = self.scalars(statement).all()
        return items[0] if items else None


def make_user(email: str, role: str = "user") -> User:
    return User(
        id=uuid4(),
        email=email,
        password_hash=hash_secret("password"),
        role=role,
    )


def make_company(name: str) -> Company:
    return Company(id=uuid4(), name=name)


def make_device(
    company: Company,
    hostname: str,
    tunnel_ip: str,
    *,
    status: str = "online",
    revoked_at=None,
    backup_enabled: bool = False,
    backup_retention_count: int = 3,
    backup_interval_value: int = 24,
    backup_interval_unit: str = "hours",
    backup_last_requested_at=None,
    backup_last_uploaded_at=None,
    firmware_status: str = "none",
    firmware_update_count: int = 0,
    firmware_reboot_required: bool = False,
    firmware_current_version: str | None = None,
    firmware_available_version: str | None = None,
    firmware_checked_at=None,
    license_type: str | None = "community",
    license_expires_at=None,
    last_seen_at=None,
    health_missed_checks: int = 0,
    email_notifications_enabled: bool = False,
    email_notification_recipient: str | None = None,
) -> Device:
    device = Device(
        id=uuid4(),
        company_id=company.id,
        hostname=hostname,
        wg_public_key=f"{hostname}-pubkey",
        wg_tunnel_ip=tunnel_ip,
        device_token_hash=hash_secret(f"{hostname}-token"),
        status=status,
        revoked_at=revoked_at,
        backup_enabled=backup_enabled,
        backup_retention_count=backup_retention_count,
        backup_interval_value=backup_interval_value,
        backup_interval_unit=backup_interval_unit,
        backup_interval_hours=max(
            1,
            backup_interval_value
            * (
                24
                if backup_interval_unit == "days"
                else 24 * 30
                if backup_interval_unit == "months"
                else 1
            ),
        ),
        backup_last_requested_at=backup_last_requested_at,
        backup_last_uploaded_at=backup_last_uploaded_at,
        firmware_status=firmware_status,
        firmware_update_count=firmware_update_count,
        firmware_reboot_required=firmware_reboot_required,
        firmware_current_version=firmware_current_version,
        firmware_available_version=firmware_available_version,
        firmware_checked_at=firmware_checked_at,
        license_type=license_type,
        license_expires_at=license_expires_at,
        last_seen_at=last_seen_at,
        health_missed_checks=health_missed_checks,
        email_notifications_enabled=email_notifications_enabled,
        email_notification_recipient=email_notification_recipient,
    )
    device.company = company
    return device


def seed_dashboard_data(now: datetime):
    admin = make_user("admin@example.com", role="administrator")
    member = make_user("member@example.com")
    company_a = make_company("Alpha Co")
    company_b = make_company("Beta Co")

    alpha_online = make_device(
        company_a,
        "alpha-online",
        "100.96.0.10/32",
        status="online",
        backup_enabled=True,
        backup_last_uploaded_at=now - timedelta(hours=2),
        firmware_status="none",
        firmware_current_version="25.1",
        license_type="business",
        license_expires_at=now + timedelta(days=20),
        last_seen_at=now - timedelta(minutes=5),
        email_notifications_enabled=True,
        email_notification_recipient="alpha-alerts@example.com",
    )
    alpha_warning = make_device(
        company_a,
        "alpha-warning",
        "100.96.0.11/32",
        status="warning",
        backup_enabled=True,
        backup_last_uploaded_at=now - timedelta(days=2),
        backup_interval_value=12,
        backup_interval_unit="hours",
        firmware_status="update",
        firmware_update_count=2,
        firmware_current_version="25.1",
        firmware_available_version="25.1.1",
        firmware_checked_at=now - timedelta(hours=1),
        license_type="community",
        last_seen_at=now - timedelta(hours=1),
        health_missed_checks=3,
    )
    alpha_critical = make_device(
        company_a,
        "alpha-critical",
        "100.96.0.12/32",
        status="offline",
        backup_enabled=True,
        firmware_status="upgrade",
        firmware_update_count=1,
        firmware_current_version="24.7",
        firmware_available_version="25.1",
        firmware_checked_at=now - timedelta(hours=3),
        license_type="business",
        license_expires_at=now - timedelta(days=1),
        health_missed_checks=4,
    )
    alpha_revoked = make_device(
        company_a,
        "alpha-revoked",
        "100.96.0.13/32",
        status="revoked",
        revoked_at=now - timedelta(days=3),
    )
    beta_unknown = make_device(
        company_b,
        "beta-unknown",
        "100.96.0.20/32",
        status="online",
        backup_enabled=False,
        firmware_status="unknown",
        firmware_reboot_required=True,
        license_type="business",
        license_expires_at=now + timedelta(days=6),
        email_notifications_enabled=True,
    )
    beta_error = make_device(
        company_b,
        "beta-error",
        "100.96.0.21/32",
        status="online",
        backup_enabled=True,
        backup_last_requested_at=now - timedelta(minutes=30),
        backup_last_uploaded_at=now - timedelta(hours=5),
        firmware_status="error",
        firmware_checked_at=now - timedelta(minutes=45),
        license_type="community",
        last_seen_at=now - timedelta(minutes=10),
    )
    events = [
        DeviceEvent(
            device_id=alpha_warning.id,
            event_type="health_check",
            message="WebGUI unreachable at https://100.96.0.11:443/",
            created_at=now - timedelta(hours=2),
        ),
        DeviceEvent(
            device_id=alpha_online.id,
            event_type="health_check",
            message="WebGUI reachable at https://100.96.0.10:443/",
            created_at=now - timedelta(hours=1),
        ),
        DeviceEvent(
            device_id=alpha_online.id,
            event_type="email_notification_sent",
            message="Health status notification sent for warning",
            created_at=now - timedelta(minutes=50),
        ),
        DeviceEvent(
            device_id=beta_error.id,
            event_type="email_notification_failed",
            message="Could not send health status email notification: RuntimeError",
            created_at=now - timedelta(minutes=20),
        ),
        DeviceEvent(
            device_id=beta_error.id,
            event_type="firmware_check",
            message="Firmware status fetch failed",
            created_at=now - timedelta(minutes=15),
        ),
    ]
    integration_settings = IntegrationSettings(
        id=1,
        smtp_enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=25,
        smtp_from="hub@example.com",
    )
    return {
        "admin": admin,
        "member": member,
        "companies": [company_a, company_b],
        "devices": {
            admin.id: [
                alpha_online,
                alpha_warning,
                alpha_critical,
                alpha_revoked,
                beta_unknown,
                beta_error,
            ],
            member.id: [alpha_online, alpha_warning, alpha_critical, alpha_revoked],
        },
        "companies_by_user": {
            admin.id: [company_a, company_b],
            member.id: [company_a],
        },
        "integration_settings": integration_settings,
        "events": events,
        "alpha_online": alpha_online,
        "company_a": company_a,
        "company_b": company_b,
    }


def configure_dashboard_access(monkeypatch, seeded):
    monkeypatch.setattr(
        "app.dashboard.accessible_companies_for_user",
        lambda _db, user: list(seeded["companies_by_user"].get(user.id, [])),
    )
    monkeypatch.setattr(
        "app.dashboard.accessible_devices_for_user",
        lambda _db, user: list(seeded["devices"].get(user.id, [])),
    )


@pytest.fixture
def fixed_now(monkeypatch):
    now = datetime(2026, 6, 26, 10, 0, tzinfo=timezone.utc)
    monkeypatch.setattr("app.dashboard.utc_now", lambda: now)
    return now


def test_dashboard_requires_login(monkeypatch):
    db = FakeDb()

    async def noop():
        return None

    monkeypatch.setattr("app.main.bootstrap", lambda: None)
    monkeypatch.setattr("app.main.apply_startup_hardening", lambda _settings: None)
    monkeypatch.setattr("app.main.device_health_check_loop", noop)
    monkeypatch.setattr("app.main.firmware_check_schedule_loop", noop)

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        response = client.get("/dashboard", follow_redirects=False)
    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_dashboard_only_includes_accessible_companies_and_devices(
    monkeypatch, fixed_now
):
    seeded = seed_dashboard_data(fixed_now)
    configure_dashboard_access(monkeypatch, seeded)
    db = FakeDb(seeded["integration_settings"], seeded["events"])

    context = build_dashboard_context(db, seeded["member"], {})

    assert context["summary"]["total_firewalls"] == 4
    assert [row["company"].name for row in context["company_overview"]] == ["Alpha Co"]
    assert all(row["company"].name == "Alpha Co" for row in context["recent_events"])


def test_dashboard_admin_sees_all_devices(monkeypatch, fixed_now):
    seeded = seed_dashboard_data(fixed_now)
    configure_dashboard_access(monkeypatch, seeded)
    db = FakeDb(seeded["integration_settings"], seeded["events"])

    context = build_dashboard_context(db, seeded["admin"], {})

    assert context["summary"]["total_firewalls"] == 6
    assert {row["company"].name for row in context["company_overview"]} == {
        "Alpha Co",
        "Beta Co",
    }


def test_dashboard_summary_counts_are_correct(monkeypatch, fixed_now):
    seeded = seed_dashboard_data(fixed_now)
    configure_dashboard_access(monkeypatch, seeded)
    db = FakeDb(seeded["integration_settings"], seeded["events"])

    context = build_dashboard_context(db, seeded["member"], {})

    assert context["summary"]["online"] == 1
    assert context["summary"]["warning"] == 1
    assert context["summary"]["critical"] == 1
    assert context["summary"]["revoked"] == 1


def test_dashboard_backup_status_calculations_cover_all_states(fixed_now):
    company = make_company("Test Co")
    disabled = make_device(company, "fw-disabled", "100.96.0.30/32")
    never = make_device(company, "fw-never", "100.96.0.31/32", backup_enabled=True)
    pending = make_device(
        company,
        "fw-pending",
        "100.96.0.32/32",
        backup_enabled=True,
        backup_last_requested_at=fixed_now - timedelta(minutes=30),
        backup_last_uploaded_at=fixed_now - timedelta(hours=2),
    )
    overdue = make_device(
        company,
        "fw-overdue",
        "100.96.0.33/32",
        backup_enabled=True,
        backup_last_uploaded_at=fixed_now - timedelta(days=2),
    )
    ok = make_device(
        company,
        "fw-ok",
        "100.96.0.34/32",
        backup_enabled=True,
        backup_last_uploaded_at=fixed_now - timedelta(hours=1),
    )

    assert dashboard_backup_status(disabled, fixed_now)["label"] == "Disabled"
    assert dashboard_backup_status(never, fixed_now)["label"] == "Never backed up"
    assert dashboard_backup_status(pending, fixed_now)["label"] == "Pending"
    assert dashboard_backup_status(overdue, fixed_now)["label"] == "Overdue"
    assert dashboard_backup_status(ok, fixed_now)["label"] == "OK"


def test_dashboard_firmware_attention_includes_expected_states(monkeypatch, fixed_now):
    seeded = seed_dashboard_data(fixed_now)
    configure_dashboard_access(monkeypatch, seeded)
    db = FakeDb(seeded["integration_settings"], seeded["events"])

    context = build_dashboard_context(db, seeded["admin"], {})
    names = {row["device"].hostname for row in context["firmware_attention_rows"]}

    assert {"alpha-warning", "alpha-critical", "beta-unknown", "beta-error"} <= names


def test_dashboard_license_logic_handles_business_community_and_expiry(fixed_now):
    company = make_company("Licenses Co")
    expired = make_device(
        company,
        "fw-expired",
        "100.96.0.40/32",
        license_type="business",
        license_expires_at=fixed_now - timedelta(days=1),
    )
    within_week = make_device(
        company,
        "fw-week",
        "100.96.0.41/32",
        license_type="business",
        license_expires_at=fixed_now + timedelta(days=6),
    )
    within_month = make_device(
        company,
        "fw-month",
        "100.96.0.42/32",
        license_type="business",
        license_expires_at=fixed_now + timedelta(days=25),
    )
    community = make_device(
        company,
        "fw-community",
        "100.96.0.43/32",
        license_type="community",
    )

    assert dashboard_license_status(expired, fixed_now)["expired"] is True
    assert dashboard_license_status(within_week, fixed_now)["days_left"] == 6
    assert dashboard_license_status(within_month, fixed_now)["expiring_soon"] is True
    assert dashboard_license_status(community, fixed_now)["days_left"] is None


def test_dashboard_recent_events_only_include_accessible_devices(
    monkeypatch, fixed_now
):
    seeded = seed_dashboard_data(fixed_now)
    configure_dashboard_access(monkeypatch, seeded)
    db = FakeDb(seeded["integration_settings"], seeded["events"])

    context = build_dashboard_context(db, seeded["member"], {})

    assert all(row["company"].name == "Alpha Co" for row in context["recent_events"])


def test_dashboard_company_filter_does_not_leak_inaccessible_company(
    monkeypatch, fixed_now
):
    seeded = seed_dashboard_data(fixed_now)
    configure_dashboard_access(monkeypatch, seeded)
    db = FakeDb(seeded["integration_settings"], seeded["events"])

    context = build_dashboard_context(
        db,
        seeded["member"],
        {"company_id": str(seeded["company_b"].id)},
    )

    assert context["summary"]["total_firewalls"] == 0
    assert context["company_overview"] == []
    assert context["recent_events"] == []


def test_dashboard_status_filter_works(monkeypatch, fixed_now):
    seeded = seed_dashboard_data(fixed_now)
    configure_dashboard_access(monkeypatch, seeded)
    db = FakeDb(seeded["integration_settings"], seeded["events"])

    context = build_dashboard_context(db, seeded["admin"], {"status": "critical"})

    assert context["summary"]["total_firewalls"] == 1
    assert context["summary"]["critical"] == 1


def test_dashboard_includes_revoked_firewalls(monkeypatch, fixed_now):
    seeded = seed_dashboard_data(fixed_now)
    configure_dashboard_access(monkeypatch, seeded)
    db = FakeDb(seeded["integration_settings"], seeded["events"])

    context = build_dashboard_context(db, seeded["admin"], {})

    assert context["summary"]["revoked"] == 1
    assert "alpha-revoked" in context["device_filter_options"]["hostnames"]


def test_dashboard_renders_when_zero_devices(monkeypatch, fixed_now):
    user = make_user("viewer@example.com")
    db = FakeDb(IntegrationSettings(id=1, smtp_enabled=False, graph_enabled=False), [])

    async def noop():
        return None

    monkeypatch.setattr("app.main.bootstrap", lambda: None)
    monkeypatch.setattr("app.main.apply_startup_hardening", lambda _settings: None)
    monkeypatch.setattr("app.main.device_health_check_loop", noop)
    monkeypatch.setattr("app.main.firmware_check_schedule_loop", noop)
    monkeypatch.setattr(
        "app.dashboard.accessible_companies_for_user", lambda *_args: []
    )
    monkeypatch.setattr("app.dashboard.accessible_devices_for_user", lambda *_args: [])

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[current_user] = lambda: user
    with TestClient(app) as client:
        response = client.get("/dashboard")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "Dashboard" in response.text
    assert "No device events in the current view." in response.text


def test_dashboard_notification_health_renders_with_and_without_per_firewall_support(
    monkeypatch, fixed_now
):
    seeded = seed_dashboard_data(fixed_now)
    configure_dashboard_access(monkeypatch, seeded)
    db = FakeDb(seeded["integration_settings"], seeded["events"])

    supported = build_dashboard_context(db, seeded["admin"], {})
    monkeypatch.setattr(
        "app.dashboard.device_supports_email_notifications", lambda: False
    )
    unsupported = build_dashboard_context(db, seeded["admin"], {})

    assert supported["notification_health"]["supported"] is True
    assert unsupported["notification_health"]["supported"] is False


def test_email_settings_configured_supports_smtp_graph_and_none():
    smtp = IntegrationSettings(
        id=1,
        smtp_enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=25,
        smtp_from="hub@example.com",
    )
    graph = IntegrationSettings(
        id=1,
        graph_enabled=True,
        graph_tenant_id="tenant",
        graph_client_id="client",
        graph_client_secret="secret",
        graph_sender="sender@example.com",
    )
    none = IntegrationSettings(id=1, smtp_enabled=False, graph_enabled=False)

    assert email_settings_configured(smtp) is True
    assert email_settings_configured(graph) is True
    assert email_settings_configured(none) is False
