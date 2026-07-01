import csv
import io
import ipaddress
import json
import zipfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.audit import write_audit
from app.database import Base, get_db
from app.main import app, current_user, settings
from app.models import AuditLog, Company, Device, DeviceEvent, User
from app.security import hash_secret, utc_now
from app.services.log_retention import (
    create_log_archive_selection,
    export_log_archive,
    get_log_retention_summary,
    run_log_retention_once,
)
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


@compiles(INET, "sqlite")
def compile_inet_sqlite(_type, _compiler, **_kw):
    return "TEXT"


async def noop():
    return None


@contextmanager
def sqlite_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def make_admin(email: str = "admin@example.com") -> User:
    return User(
        id=uuid4(),
        email=email,
        password_hash=hash_secret("StrongPassword123"),
        role="administrator",
    )


def make_member(email: str = "member@example.com") -> User:
    return User(
        id=uuid4(),
        email=email,
        password_hash=hash_secret("StrongPassword123"),
        role="user",
    )


def seed_log_data(session: Session) -> tuple[User, Company, Device]:
    now = utc_now()
    admin = make_admin()
    company = Company(id=uuid4(), name="Acme", created_at=now)
    device = Device(
        id=uuid4(),
        company_id=company.id,
        hostname="fw-acme-1",
        wg_public_key="A" * 43 + "=",
        wg_tunnel_ip="100.96.0.10",
        device_token_hash=hash_secret("device-token"),
        status="online",
        created_at=now,
    )
    session.add_all([admin, company, device])
    session.commit()
    return admin, company, device


def configure_test_client(monkeypatch, session: Session, acting_user: User):
    monkeypatch.setattr("app.main.bootstrap", lambda: None)
    monkeypatch.setattr("app.main.apply_startup_hardening", lambda _settings: None)
    monkeypatch.setattr("app.main.device_health_check_loop", noop)
    monkeypatch.setattr("app.main.firmware_check_schedule_loop", noop)
    monkeypatch.setattr("app.main.log_retention_loop", noop)

    def override_get_db():
        yield session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[current_user] = lambda: acting_user


def get_csrf(client: TestClient, path: str = "/settings/retention") -> str:
    response = client.get(path)
    assert response.status_code == 200
    marker = 'name="csrf_token" value="'
    start = response.text.index(marker) + len(marker)
    end = response.text.index('"', start)
    return response.text[start:end]


def test_run_log_retention_once_deletes_old_device_events_but_keeps_recent(monkeypatch):
    with sqlite_session() as session:
        _admin, _company, device = seed_log_data(session)
        now = datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc)
        old_event = DeviceEvent(
            id=uuid4(),
            device_id=device.id,
            event_type="heartbeat",
            message="old",
            created_at=now - timedelta(days=120),
        )
        recent_event = DeviceEvent(
            id=uuid4(),
            device_id=device.id,
            event_type="heartbeat",
            message="recent",
            created_at=now - timedelta(days=10),
        )
        session.add_all([old_event, recent_event])
        session.commit()

        monkeypatch.setattr(settings, "log_retention_enabled", True)
        monkeypatch.setattr(settings, "device_event_retention_days", 90)
        monkeypatch.setattr(settings, "audit_log_retention_days", 365)
        monkeypatch.setattr(settings, "log_retention_delete_batch_size", 5000)
        result = run_log_retention_once(session, now=now)

        remaining_messages = [
            row.message for row in session.scalars(select(DeviceEvent)).all()
        ]

    assert result.device_events_deleted == 1
    assert result.audit_logs_deleted == 0
    assert remaining_messages == ["recent"]


def test_run_log_retention_once_deletes_old_audit_logs_but_keeps_recent(monkeypatch):
    with sqlite_session() as session:
        admin, company, device = seed_log_data(session)
        now = datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc)
        session.add_all(
            [
                AuditLog(
                    id=uuid4(),
                    user_id=admin.id,
                    company_id=company.id,
                    device_id=device.id,
                    action="old.action",
                    created_at=now - timedelta(days=500),
                ),
                AuditLog(
                    id=uuid4(),
                    user_id=admin.id,
                    company_id=company.id,
                    device_id=device.id,
                    action="recent.action",
                    created_at=now - timedelta(days=20),
                ),
            ]
        )
        session.commit()

        monkeypatch.setattr(settings, "log_retention_enabled", True)
        monkeypatch.setattr(settings, "device_event_retention_days", 90)
        monkeypatch.setattr(settings, "audit_log_retention_days", 365)
        monkeypatch.setattr(settings, "log_retention_delete_batch_size", 5000)
        result = run_log_retention_once(session, now=now)

        remaining_actions = [
            row.action for row in session.scalars(select(AuditLog)).all()
        ]

    assert result.audit_logs_deleted == 1
    assert result.device_events_deleted == 0
    assert remaining_actions == ["recent.action"]


def test_run_log_retention_once_honors_disabled_retention(monkeypatch):
    with sqlite_session() as session:
        admin, company, device = seed_log_data(session)
        now = datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc)
        session.add(
            AuditLog(
                id=uuid4(),
                user_id=admin.id,
                company_id=company.id,
                device_id=device.id,
                action="device.view",
                created_at=now - timedelta(days=500),
            )
        )
        session.commit()

        monkeypatch.setattr(settings, "log_retention_enabled", False)
        result = run_log_retention_once(session, now=now)

        remaining_count = len(session.scalars(select(AuditLog)).all())

    assert result.skipped is True
    assert result.reason == "disabled"
    assert remaining_count == 1


def test_log_retention_clamps_minimum_days_in_development(monkeypatch):
    with sqlite_session() as session:
        _admin, _company, device = seed_log_data(session)
        now = datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc)
        old_event = DeviceEvent(
            id=uuid4(),
            device_id=device.id,
            event_type="heartbeat",
            message="too-old",
            created_at=now - timedelta(days=10),
        )
        recent_event = DeviceEvent(
            id=uuid4(),
            device_id=device.id,
            event_type="heartbeat",
            message="keep",
            created_at=now - timedelta(days=3),
        )
        session.add_all([old_event, recent_event])
        session.commit()

        monkeypatch.setattr(settings, "app_env", "development")
        monkeypatch.setattr(settings, "log_retention_enabled", True)
        monkeypatch.setattr(settings, "device_event_retention_days", 1)
        monkeypatch.setattr(settings, "device_event_min_retention_days", 7)
        monkeypatch.setattr(settings, "audit_log_retention_days", 365)
        monkeypatch.setattr(settings, "log_retention_delete_batch_size", 5000)
        result = run_log_retention_once(session, now=now)

        remaining_messages = [
            row.message for row in session.scalars(select(DeviceEvent)).all()
        ]

    assert result.device_events_deleted == 1
    assert remaining_messages == ["keep"]


def test_run_log_retention_once_deletes_in_batches(monkeypatch):
    with sqlite_session() as session:
        _admin, _company, device = seed_log_data(session)
        now = datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc)
        for index in range(5):
            session.add(
                DeviceEvent(
                    id=uuid4(),
                    device_id=device.id,
                    event_type="heartbeat",
                    message=f"old-{index}",
                    created_at=now - timedelta(days=120, minutes=index),
                )
            )
        session.commit()

        monkeypatch.setattr(settings, "log_retention_enabled", True)
        monkeypatch.setattr(settings, "device_event_retention_days", 90)
        monkeypatch.setattr(settings, "audit_log_retention_days", 365)
        monkeypatch.setattr(settings, "log_retention_delete_batch_size", 2)
        result = run_log_retention_once(session, now=now)

    assert result.device_events_deleted == 5


def test_get_log_retention_summary_reports_counts(monkeypatch):
    with sqlite_session() as session:
        admin, company, device = seed_log_data(session)
        now = datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc)
        session.add_all(
            [
                AuditLog(
                    id=uuid4(),
                    user_id=admin.id,
                    company_id=company.id,
                    device_id=device.id,
                    action="old.audit",
                    created_at=now - timedelta(days=500),
                ),
                DeviceEvent(
                    id=uuid4(),
                    device_id=device.id,
                    event_type="heartbeat",
                    message="old-event",
                    created_at=now - timedelta(days=120),
                ),
            ]
        )
        session.commit()

        monkeypatch.setattr(settings, "log_retention_enabled", True)
        monkeypatch.setattr(settings, "audit_log_retention_days", 365)
        monkeypatch.setattr(settings, "device_event_retention_days", 90)
        summary = get_log_retention_summary(session, now=now)

    assert summary["audit_logs"].total_rows == 1
    assert summary["audit_logs"].rows_older_than_cutoff == 1
    assert summary["device_events"].total_rows == 1
    assert summary["device_events"].rows_older_than_cutoff == 1


def test_export_log_archive_exports_audit_logs_csv(monkeypatch):
    with sqlite_session() as session:
        admin, company, device = seed_log_data(session)
        now = datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc)
        log_row = AuditLog(
            id=uuid4(),
            user_id=admin.id,
            company_id=company.id,
            device_id=device.id,
            action="device.view",
            created_at=now - timedelta(days=40),
        )
        session.add(log_row)
        session.commit()
        log_row.ip_address = ipaddress.ip_address("192.0.2.10")
        selection = create_log_archive_selection(
            now.isoformat(),
            include_audit_logs=True,
            include_device_events=False,
        )
        archive, _filename, media_type, manifest = export_log_archive(
            session, selection
        )

    assert media_type == "application/zip"
    assert manifest["row_counts"]["audit_logs"] == 1
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        names = set(bundle.namelist())
        assert "manifest.json" in names
        assert "audit_logs.csv" in names
        assert "device_events.csv" not in names
        rows = list(csv.DictReader(io.StringIO(bundle.read("audit_logs.csv").decode())))
    assert rows[0]["action"] == "device.view"
    assert rows[0]["ip_address"] == "192.0.2.10"


def test_export_log_archive_exports_device_events_csv(monkeypatch):
    with sqlite_session() as session:
        _admin, _company, device = seed_log_data(session)
        now = datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc)
        session.add(
            DeviceEvent(
                id=uuid4(),
                device_id=device.id,
                event_type="heartbeat",
                message="archived",
                created_at=now - timedelta(days=20),
            )
        )
        session.commit()
        selection = create_log_archive_selection(
            now.isoformat(),
            include_audit_logs=False,
            include_device_events=True,
        )
        archive, _filename, _media_type, manifest = export_log_archive(
            session, selection
        )

    assert manifest["row_counts"]["device_events"] == 1
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        rows = list(
            csv.DictReader(io.StringIO(bundle.read("device_events.csv").decode()))
        )
    assert rows[0]["event_type"] == "heartbeat"


def test_export_log_archive_exports_both_tables_and_manifest(monkeypatch):
    with sqlite_session() as session:
        admin, company, device = seed_log_data(session)
        now = datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc)
        session.add_all(
            [
                AuditLog(
                    id=uuid4(),
                    user_id=admin.id,
                    company_id=company.id,
                    device_id=device.id,
                    action="device.proxy.open",
                    created_at=now - timedelta(days=10),
                ),
                DeviceEvent(
                    id=uuid4(),
                    device_id=device.id,
                    event_type="heartbeat",
                    message="both",
                    created_at=now - timedelta(days=10),
                ),
            ]
        )
        session.commit()
        selection = create_log_archive_selection(
            now.isoformat(),
            include_audit_logs=True,
            include_device_events=True,
        )
        archive, _filename, _media_type, manifest = export_log_archive(
            session, selection
        )

    assert manifest["included_tables"] == ["audit_logs", "device_events"]
    assert manifest["selected_cutoff_at"] == now.isoformat()
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        assert {"manifest.json", "audit_logs.csv", "device_events.csv"}.issubset(
            set(bundle.namelist())
        )


def test_retention_page_requires_admin(monkeypatch):
    with sqlite_session() as session:
        member = make_member()
        session.add(member)
        session.commit()
        configure_test_client(monkeypatch, session, member)
        with TestClient(app) as client:
            response = client.get("/settings/retention")
        app.dependency_overrides.clear()

    assert response.status_code == 403
    assert response.json()["detail"] == "administrator access required"


def test_retention_page_shows_summary_counts(monkeypatch):
    with sqlite_session() as session:
        admin, company, device = seed_log_data(session)
        now = utc_now()
        session.add_all(
            [
                AuditLog(
                    id=uuid4(),
                    user_id=admin.id,
                    company_id=company.id,
                    device_id=device.id,
                    action="device.view",
                    created_at=now - timedelta(days=400),
                ),
                DeviceEvent(
                    id=uuid4(),
                    device_id=device.id,
                    event_type="heartbeat",
                    message="summary",
                    created_at=now - timedelta(days=100),
                ),
            ]
        )
        session.commit()
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            response = client.get("/settings/retention")
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "Retention management" in response.text
    assert "Database summary" in response.text
    assert ">1<" in response.text


def test_retention_cleanup_requires_admin_and_csrf(monkeypatch):
    with sqlite_session() as session:
        admin, _company, _device = seed_log_data(session)
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app, raise_server_exceptions=False) as client:
            missing_csrf = client.post(
                "/settings/retention/run-cleanup", follow_redirects=False
            )
            csrf_token = get_csrf(client)
            ok = client.post(
                "/settings/retention/run-cleanup",
                data={"csrf_token": csrf_token},
                follow_redirects=False,
            )
        app.dependency_overrides.clear()

    assert missing_csrf.status_code == 403
    assert ok.status_code == 303
    assert ok.headers["location"] == "/settings/retention?status=retention-cleanup-ran"


def test_retention_export_requires_admin_and_csrf(monkeypatch):
    with sqlite_session() as session:
        admin, company, device = seed_log_data(session)
        session.add(
            AuditLog(
                id=uuid4(),
                user_id=admin.id,
                company_id=company.id,
                device_id=device.id,
                action="device.view",
                created_at=utc_now() - timedelta(days=2),
            )
        )
        session.commit()
        configure_test_client(monkeypatch, session, admin)
        cutoff_at = utc_now().replace(microsecond=0).isoformat()
        with TestClient(app, raise_server_exceptions=False) as client:
            missing_csrf = client.post(
                "/settings/retention/export",
                data={
                    "cutoff_at": cutoff_at,
                    "include_audit_logs": "on",
                },
            )
            csrf_token = get_csrf(client)
            ok = client.post(
                "/settings/retention/export",
                data={
                    "csrf_token": csrf_token,
                    "cutoff_at": cutoff_at,
                    "include_audit_logs": "on",
                },
            )
        app.dependency_overrides.clear()

    assert missing_csrf.status_code == 403
    assert ok.status_code == 200
    assert ok.headers["content-type"] == "application/zip"


def test_retention_export_requires_admin(monkeypatch):
    with sqlite_session() as session:
        member = make_member()
        session.add(member)
        session.commit()
        configure_test_client(monkeypatch, session, member)
        cutoff_at = utc_now().replace(microsecond=0).isoformat()
        with TestClient(app) as client:
            csrf_token = get_csrf(client, "/companies")
            response = client.post(
                "/settings/retention/export",
                data={
                    "csrf_token": csrf_token,
                    "cutoff_at": cutoff_at,
                    "include_audit_logs": "on",
                },
            )
        app.dependency_overrides.clear()

    assert response.status_code == 403
    assert response.json()["detail"] == "administrator access required"


def test_device_view_audit_is_throttled(monkeypatch):
    with sqlite_session() as session:
        admin, company, device = seed_log_data(session)
        now = datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc)
        monkeypatch.setattr(settings, "audit_device_view_throttle_minutes", 15)
        monkeypatch.setattr("app.audit.utc_now", lambda: now)

        first = write_audit(
            session,
            None,
            "device.view",
            user=admin,
            company_id=company.id,
            device_id=device.id,
        )
        session.commit()
        second = write_audit(
            session,
            None,
            "device.view",
            user=admin,
            company_id=company.id,
            device_id=device.id,
        )
        session.commit()
        entries = session.scalars(
            select(AuditLog).where(AuditLog.action == "device.view")
        ).all()

    assert first is True
    assert second is False
    assert len(entries) == 1


def test_device_view_audit_writes_again_after_throttle_window(monkeypatch):
    with sqlite_session() as session:
        admin, company, device = seed_log_data(session)
        base_now = datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc)
        monkeypatch.setattr(settings, "audit_device_view_throttle_minutes", 15)
        monkeypatch.setattr("app.audit.utc_now", lambda: base_now)
        write_audit(
            session,
            None,
            "device.view",
            user=admin,
            company_id=company.id,
            device_id=device.id,
        )
        session.commit()
        monkeypatch.setattr(
            "app.audit.utc_now", lambda: base_now + timedelta(minutes=16)
        )
        write_audit(
            session,
            None,
            "device.view",
            user=admin,
            company_id=company.id,
            device_id=device.id,
        )
        session.commit()
        entries = session.scalars(
            select(AuditLog).where(AuditLog.action == "device.view")
        ).all()

    assert len(entries) == 2


def test_device_view_audit_is_separate_per_user_and_device(monkeypatch):
    with sqlite_session() as session:
        admin, company, device = seed_log_data(session)
        second_user = make_admin("other@example.com")
        second_device = Device(
            id=uuid4(),
            company_id=company.id,
            hostname="fw-acme-2",
            wg_public_key="B" * 43 + "=",
            wg_tunnel_ip="100.96.0.11",
            device_token_hash=hash_secret("device-token-2"),
            status="online",
            created_at=utc_now(),
        )
        session.add_all([second_user, second_device])
        session.commit()
        now = datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc)
        monkeypatch.setattr(settings, "audit_device_view_throttle_minutes", 15)
        monkeypatch.setattr("app.audit.utc_now", lambda: now)

        write_audit(
            session,
            None,
            "device.view",
            user=admin,
            company_id=company.id,
            device_id=device.id,
        )
        session.commit()
        write_audit(
            session,
            None,
            "device.view",
            user=second_user,
            company_id=company.id,
            device_id=device.id,
        )
        session.commit()
        write_audit(
            session,
            None,
            "device.view",
            user=admin,
            company_id=company.id,
            device_id=second_device.id,
        )
        session.commit()
        entries = session.scalars(
            select(AuditLog).where(AuditLog.action == "device.view")
        ).all()

    assert len(entries) == 3


def test_device_proxy_open_is_not_throttled(monkeypatch):
    with sqlite_session() as session:
        admin, company, device = seed_log_data(session)
        monkeypatch.setattr(settings, "audit_device_view_throttle_minutes", 15)
        write_audit(
            session,
            None,
            "device.proxy.open",
            user=admin,
            company_id=company.id,
            device_id=device.id,
        )
        session.commit()
        write_audit(
            session,
            None,
            "device.proxy.open",
            user=admin,
            company_id=company.id,
            device_id=device.id,
        )
        session.commit()
        entries = session.scalars(
            select(AuditLog).where(AuditLog.action == "device.proxy.open")
        ).all()

    assert len(entries) == 2
