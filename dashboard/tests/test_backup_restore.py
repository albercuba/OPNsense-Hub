import io
import json
import os
import zipfile
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from app.database import Base, get_db
from app.main import app, current_user, export_backup_bundle, settings
from app.models import (
    AuditLog,
    Company,
    CompanyUser,
    Device,
    DeviceBackup,
    DeviceEvent,
    EnrollmentCode,
    IntegrationSettings,
    SessionToken,
    User,
)
from app.security import hash_secret, hash_session_token, utc_now
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


@compiles(INET, "sqlite")
def compile_inet_sqlite(_type, _compiler, **_kw):
    return "TEXT"


PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0cIDATx\x9cc``\x00\x00\x00\x02"
    b"\x00\x01\xe2!\xbc3\x00\x00\x00\x00IEND\xaeB`\x82"
)
VALID_WG_PUBLIC_KEY = "A" * 43 + "="
VALID_WG_PUBLIC_KEY_2 = "B" * 43 + "="


async def noop():
    return None


@contextmanager
def sqlite_session(tmp_path: Path, name: str):
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


def seed_backup_source(session: Session) -> User:
    now = utc_now()
    admin = User(
        id=uuid4(),
        email="admin@example.com",
        password_hash=hash_secret("StrongPassword123"),
        role="administrator",
        first_name="Admin",
        last_name="User",
    )
    company = Company(id=uuid4(), name="Acme", created_at=now)
    session.add_all(
        [
            admin,
            IntegrationSettings(
                id=1,
                smtp_enabled=True,
                smtp_host="smtp.example.com",
                smtp_port=2525,
                smtp_from="hub@example.com",
                branding_logo_url="https://example.com/logo.png",
                updated_at=now,
            ),
            company,
        ]
    )
    session.flush()
    device = Device(
        id=uuid4(),
        company_id=company.id,
        name="HQ Firewall",
        hostname="fw-acme-1",
        wg_public_key=VALID_WG_PUBLIC_KEY,
        wg_tunnel_ip="100.96.0.10",
        device_token_hash=hash_secret("device-token"),
        status="online",
        created_at=now,
    )
    session.add_all(
        [
            CompanyUser(
                company_id=company.id, user_id=admin.id, role="owner", created_at=now
            ),
            EnrollmentCode(
                id=uuid4(),
                company_id=company.id,
                code_hash=hash_secret("otp-code"),
                expires_at=now + timedelta(minutes=10),
                created_by=admin.id,
                created_at=now,
            ),
            device,
        ]
    )
    session.flush()
    session.add_all(
        [
            DeviceBackup(
                id=uuid4(),
                device_id=device.id,
                filename="config.xml",
                content="<config />",
                created_at=now,
            ),
            DeviceEvent(
                id=uuid4(),
                device_id=device.id,
                event_type="backup_uploaded",
                message="Stored backup uploaded",
                created_at=now,
            ),
            AuditLog(
                id=uuid4(),
                user_id=admin.id,
                company_id=company.id,
                device_id=device.id,
                action="seeded.backup",
                ip_address="127.0.0.1",
                user_agent="pytest",
                created_at=now,
            ),
            SessionToken(
                id=uuid4(),
                user_id=admin.id,
                token_hash=hash_session_token(settings.secret_key, "session-token"),
                created_at=now,
                expires_at=now + timedelta(hours=1),
            ),
        ]
    )
    session.commit()
    return admin


def seed_restore_target(session: Session) -> User:
    now = utc_now()
    admin = User(
        id=uuid4(),
        email="restore-admin@example.com",
        password_hash=hash_secret("RestorePassword123"),
        role="administrator",
    )
    company = Company(id=uuid4(), name="Old Company", created_at=now)
    session.add_all(
        [admin, company, IntegrationSettings(id=1, smtp_enabled=False, updated_at=now)]
    )
    session.flush()
    session.add_all(
        [
            CompanyUser(
                company_id=company.id, user_id=admin.id, role="owner", created_at=now
            ),
            Device(
                id=uuid4(),
                company_id=company.id,
                hostname="old-firewall",
                wg_public_key=VALID_WG_PUBLIC_KEY_2,
                wg_tunnel_ip="100.96.0.99",
                device_token_hash=hash_secret("old-token"),
                status="online",
                created_at=now,
            ),
            SessionToken(
                id=uuid4(),
                user_id=admin.id,
                token_hash=hash_session_token(settings.secret_key, "old-session"),
                created_at=now,
                expires_at=now + timedelta(hours=1),
            ),
        ]
    )
    session.commit()
    return admin


def configure_test_client(monkeypatch, session: Session, acting_user: User):
    monkeypatch.setattr("app.main.bootstrap", lambda: None)
    monkeypatch.setattr("app.main.apply_startup_hardening", lambda _settings: None)
    monkeypatch.setattr("app.main.device_health_check_loop", noop)
    monkeypatch.setattr("app.main.firmware_check_schedule_loop", noop)

    def override_get_db():
        yield session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[current_user] = lambda: acting_user


def get_csrf(client: TestClient, path: str = "/settings/backup") -> str:
    response = client.get(path)
    assert response.status_code == 200
    csrf_cookie = client.cookies.get(settings.csrf_cookie_name)
    assert csrf_cookie
    marker = 'name="csrf_token" value="'
    start = response.text.index(marker) + len(marker)
    end = response.text.index('"', start)
    return response.text[start:end]


def test_backup_export_bundle_includes_database_and_files(monkeypatch, tmp_path):
    branding_dir = tmp_path / "branding-source"
    branding_dir.mkdir(parents=True, exist_ok=True)
    (branding_dir / "logo.png").write_bytes(PNG_BYTES)
    wg_key_path = tmp_path / "wireguard-source" / "server.key"
    wg_key_path.parent.mkdir(parents=True, exist_ok=True)
    wg_key_path.write_text("test-private-key\n")
    monkeypatch.setattr(settings, "branding_upload_dir", str(branding_dir))
    monkeypatch.setattr(settings, "wg_server_private_key_path", str(wg_key_path))

    with sqlite_session(tmp_path, "export") as session:
        admin = seed_backup_source(session)
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            csrf_token = get_csrf(client)
            response = client.post(
                "/settings/backup/export", data={"csrf_token": csrf_token}
            )
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert (
        'attachment; filename="opnsense-hub-backup-'
        in response.headers["content-disposition"]
    )

    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert {
            "manifest.json",
            "data.json",
            "branding/logo.png",
            "wireguard/server.key",
        }.issubset(set(archive.namelist()))
        manifest = json.loads(archive.read("manifest.json"))
        data = json.loads(archive.read("data.json"))
        exported_key = archive.read("wireguard/server.key").decode("utf-8").strip()

    assert manifest["format_version"] == 1
    assert manifest["includes"]["branding_logo"] == "logo.png"
    assert manifest["includes"]["wireguard_private_key"] == "server.key"
    assert data["users"][0]["email"] == "admin@example.com"
    assert data["companies"][0]["name"] == "Acme"
    assert data["devices"][0]["hostname"] == "fw-acme-1"
    assert data["device_backups"][0]["filename"] == "config.xml"
    assert exported_key == "test-private-key"


def test_externally_managed_users_cannot_be_edited_from_settings(monkeypatch, tmp_path):
    with sqlite_session(tmp_path, "external_user_settings") as session:
        admin = seed_backup_source(session)
        external_user = User(
            id=uuid4(),
            email="entra-user@example.com",
            password_hash=hash_secret("StrongPassword123"),
            role="user",
            auth_provider="microsoft",
        )
        session.add(external_user)
        session.commit()
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            response = client.get("/settings/manage-users")
            csrf_token = get_csrf(client, "/settings/manage-users")
            update_response = client.post(
                f"/settings/users/{external_user.id}",
                data={
                    "csrf_token": csrf_token,
                    "email": external_user.email,
                    "first_name": "Changed",
                    "last_name": "User",
                    "role": "administrator",
                    "password": "",
                },
            )
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "cannot be edited here" in response.text
    assert update_response.status_code == 400
    assert (
        update_response.json()["detail"]
        == "users managed by Microsoft 365 or Local AD cannot be edited here"
    )


def test_legacy_external_users_without_auth_provider_are_still_locked(
    monkeypatch, tmp_path
):
    with sqlite_session(tmp_path, "legacy_external_user_settings") as session:
        admin = seed_backup_source(session)
        external_user = User(
            id=uuid4(),
            email="legacy-entra-user@example.com",
            password_hash=hash_secret("StrongPassword123"),
            role="user",
            auth_provider=None,
        )
        session.add(external_user)
        session.flush()
        session.add(
            AuditLog(
                id=uuid4(),
                user_id=external_user.id,
                action="auth.microsoft.login",
                created_at=utc_now(),
            )
        )
        session.commit()
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            response = client.get("/settings/manage-users")
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert (
        "Users managed by Microsoft 365 or Local AD cannot be edited here"
        in response.text
    )


def test_backup_export_requires_admin(monkeypatch, tmp_path):
    monkeypatch.setattr(
        settings, "branding_upload_dir", str(tmp_path / "branding-non-admin")
    )
    monkeypatch.setattr(
        settings,
        "wg_server_private_key_path",
        str(tmp_path / "wireguard-non-admin" / "server.key"),
    )

    with sqlite_session(tmp_path, "non_admin") as session:
        member = User(
            id=uuid4(),
            email="member@example.com",
            password_hash=hash_secret("MemberPassword123"),
            role="user",
        )
        session.add(member)
        session.commit()
        configure_test_client(monkeypatch, session, member)
        with TestClient(app) as client:
            csrf_token = get_csrf(client, "/companies")
            response = client.post(
                "/settings/backup/export", data={"csrf_token": csrf_token}
            )
        app.dependency_overrides.clear()

    assert response.status_code == 403
    assert response.json()["detail"] == "administrator access required"


def test_audit_logs_page_lists_firewall_access_entries(monkeypatch, tmp_path):
    with sqlite_session(tmp_path, "audit_logs_page") as session:
        admin = seed_backup_source(session)
        device = session.scalars(select(Device)).first()
        company = session.scalars(select(Company)).first()
        assert device is not None
        assert company is not None
        session.add(
            AuditLog(
                id=uuid4(),
                user_id=admin.id,
                company_id=company.id,
                device_id=device.id,
                action="device.view",
                ip_address="127.0.0.1",
                user_agent="pytest",
                created_at=utc_now(),
            )
        )
        session.commit()
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            response = client.get("/audit-logs")
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "Audit logs" in response.text
    assert admin.email in response.text
    assert device.hostname in response.text
    assert company.name in response.text


def test_device_page_writes_firewall_access_audit_log(monkeypatch, tmp_path):
    with sqlite_session(tmp_path, "device_view_audit") as session:
        admin = seed_backup_source(session)
        device = session.scalars(select(Device)).first()
        assert device is not None
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            response = client.get(f"/devices/{device.id}")
        app.dependency_overrides.clear()
        access_logs = session.scalars(
            select(AuditLog).where(AuditLog.action == "device.view")
        ).all()

    assert response.status_code == 200
    assert len(access_logs) == 1
    assert access_logs[0].device_id == device.id
    assert access_logs[0].company_id == device.company_id
    assert access_logs[0].user_id == admin.id


def test_delete_stored_backup_removes_backup_record(monkeypatch, tmp_path):
    with sqlite_session(tmp_path, "delete_backup") as session:
        admin = seed_backup_source(session)
        configure_test_client(monkeypatch, session, admin)
        device = session.scalars(select(Device)).first()
        backup = session.scalars(select(DeviceBackup)).first()
        assert device is not None
        assert backup is not None

        with TestClient(app) as client:
            csrf_token = get_csrf(client, f"/devices/{device.id}")
            response = client.post(
                f"/devices/{device.id}/backups/{backup.id}/delete",
                data={"csrf_token": csrf_token},
                follow_redirects=False,
            )
        app.dependency_overrides.clear()

        remaining_backups = session.scalars(select(DeviceBackup)).all()

    assert response.status_code == 303
    assert response.headers["location"] == f"/devices/{device.id}?status=backup-deleted"
    assert remaining_backups == []


def test_backup_restore_replaces_configuration_and_clears_sessions(
    monkeypatch, tmp_path
):
    source_branding_dir = tmp_path / "branding-source-restore"
    source_branding_dir.mkdir(parents=True, exist_ok=True)
    (source_branding_dir / "logo.png").write_bytes(PNG_BYTES)
    source_wg_key_path = tmp_path / "wireguard-source-restore" / "server.key"
    source_wg_key_path.parent.mkdir(parents=True, exist_ok=True)
    source_wg_key_path.write_text("restored-private-key\n")

    with sqlite_session(tmp_path, "source_restore") as source_session:
        seed_backup_source(source_session)
        monkeypatch.setattr(settings, "branding_upload_dir", str(source_branding_dir))
        monkeypatch.setattr(
            settings, "wg_server_private_key_path", str(source_wg_key_path)
        )
        bundle, _filename, _media_type = export_backup_bundle(source_session)

    target_branding_dir = tmp_path / "branding-target-restore"
    target_branding_dir.mkdir(parents=True, exist_ok=True)
    (target_branding_dir / "logo.png").write_bytes(PNG_BYTES)
    target_wg_key_path = tmp_path / "wireguard-target-restore" / "server.key"
    target_wg_key_path.parent.mkdir(parents=True, exist_ok=True)
    target_wg_key_path.write_text("old-private-key\n")
    monkeypatch.setattr(settings, "branding_upload_dir", str(target_branding_dir))
    monkeypatch.setattr(settings, "wg_server_private_key_path", str(target_wg_key_path))

    with sqlite_session(tmp_path, "target_restore") as target_session:
        acting_admin = seed_restore_target(target_session)
        configure_test_client(monkeypatch, target_session, acting_admin)
        with TestClient(app) as client:
            csrf_token = get_csrf(client)
            response = client.post(
                "/settings/backup/restore",
                data={"csrf_token": csrf_token},
                files={"backup_file": ("hub-backup.zip", bundle, "application/zip")},
                follow_redirects=False,
            )
        app.dependency_overrides.clear()

        restored_users = target_session.scalars(select(User).order_by(User.email)).all()
        restored_companies = target_session.scalars(
            select(Company).order_by(Company.name)
        ).all()
        restored_devices = target_session.scalars(
            select(Device).order_by(Device.hostname)
        ).all()
        restored_sessions = target_session.scalars(select(SessionToken)).all()
        restored_settings = target_session.get(IntegrationSettings, 1)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert settings.session_cookie_name in response.headers.get("set-cookie", "")
    assert [user.email for user in restored_users] == ["admin@example.com"]
    assert [company.name for company in restored_companies] == ["Acme"]
    assert [device.hostname for device in restored_devices] == ["fw-acme-1"]
    assert restored_sessions == []
    assert restored_settings is not None
    assert restored_settings.smtp_host == "smtp.example.com"
    assert (target_branding_dir / "logo.png").read_bytes() == PNG_BYTES
    assert target_wg_key_path.read_text().strip() == "restored-private-key"
