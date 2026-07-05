import io
import json
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
    UserDashboardFilter,
)
from app.security import hash_secret, hash_session_token, totp_code, utc_now
from app.services.backup_service import parse_backup_bundle
from app.services.notification_service import maybe_notify_for_repeated_auth_failures
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


def test_backup_verification_reports_structural_integrity(monkeypatch, tmp_path):
    branding_dir = tmp_path / "branding-verify"
    branding_dir.mkdir(parents=True, exist_ok=True)
    (branding_dir / "logo.png").write_bytes(PNG_BYTES)
    wg_key_path = tmp_path / "wireguard-verify" / "server.key"
    wg_key_path.parent.mkdir(parents=True, exist_ok=True)
    wg_key_path.write_text("verify-private-key\n")
    monkeypatch.setattr(settings, "branding_upload_dir", str(branding_dir))
    monkeypatch.setattr(settings, "wg_server_private_key_path", str(wg_key_path))

    with sqlite_session(tmp_path, "backup_verify") as session:
        admin = seed_backup_source(session)
        bundle, _filename, _media_type = export_backup_bundle(session)
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            csrf_token = get_csrf(client)
            response = client.post(
                "/settings/backup/verify",
                data={"csrf_token": csrf_token},
                files={"backup_file": ("hub-backup.zip", bundle, "application/zip")},
            )
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "Backup integrity check passed" in response.text
    assert (
        "wireguard_private_key" in response.text
        or "WireGuard private key" in response.text
    )


def test_security_settings_allowlist_can_be_saved(monkeypatch, tmp_path):
    with sqlite_session(tmp_path, "security_settings") as session:
        admin = seed_backup_source(session)
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            security_page = client.get("/settings/security")
            assert security_page.status_code == 200
            assert "Administrator login IP allowlist" in security_page.text
            csrf_token = get_csrf(client, "/settings/security")
            response = client.post(
                "/settings/security",
                data={
                    "csrf_token": csrf_token,
                    "admin_login_allowlist": "203.0.113.10/32\n198.51.100.0/24",
                },
                follow_redirects=False,
            )
            integration_settings = session.get(IntegrationSettings, 1)
        app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/settings/security?status=security-saved"
    assert integration_settings is not None
    assert (
        integration_settings.admin_login_allowlist == "203.0.113.10/32\n198.51.100.0/24"
    )


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


def test_device_page_renders_phase_one_sections(monkeypatch, tmp_path):
    with sqlite_session(tmp_path, "device_phase_one_page") as session:
        admin = seed_backup_source(session)
        device = session.scalar(select(Device).where(Device.hostname == "fw-acme-1"))
        assert device is not None
        device.runbook_notes = "Primary edge firewall"
        device.runbook_owner = "Ops Team"
        device.health_acknowledged_at = utc_now()
        device.health_acknowledged_note = "Tracked in INC-42"
        device.health_acknowledged_by = admin.id
        session.add(
            AuditLog(
                id=uuid4(),
                user_id=admin.id,
                company_id=device.company_id,
                device_id=device.id,
                action="device.runbook.update",
                ip_address="127.0.0.1",
                user_agent="pytest",
                created_at=utc_now(),
            )
        )
        session.commit()
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            response = client.get(f"/devices/{device.id}")
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "Health drill-down" in response.text
    assert "Runbook and internal notes" in response.text
    assert "Health acknowledgement" in response.text
    assert "Activity timeline" in response.text
    assert "timeline-scroll-panel" in response.text
    assert "<span>Escalation hint</span>" in response.text
    assert "<span>Acknowledgement note</span>" in response.text
    assert "<span>Internal notes</span>" in response.text
    assert "Tracked in INC-42" in response.text
    assert "Runbook updated" in response.text


def test_network_settings_page_renders_diagnostics(monkeypatch, tmp_path):
    with sqlite_session(tmp_path, "network_settings_page") as session:
        admin = seed_backup_source(session)
        device = session.scalar(select(Device).where(Device.hostname == "fw-acme-1"))
        assert device is not None
        monkeypatch.setattr(
            "app.services.network_diagnostics.get_runtime_peers",
            lambda: [
                __import__(
                    "app.wireguard", fromlist=["RuntimeWireGuardPeer"]
                ).RuntimeWireGuardPeer(
                    public_key=device.wg_public_key,
                    preshared_key="(off)",
                    endpoint="198.51.100.10:51820",
                    allowed_ips=[f"{device.wg_tunnel_ip}/32"],
                    last_handshake_at=utc_now(),
                    rx_bytes=123,
                    tx_bytes=456,
                    persistent_keepalive=25,
                )
            ],
        )
        monkeypatch.setattr(
            "app.services.network_diagnostics.verify_nftables_rule_present",
            lambda _settings: None,
        )
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            response = client.get("/settings/network")
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "Isolation verification" in response.text
    assert "WireGuard state visibility" in response.text
    assert "Enrollment diagnostics" in response.text
    assert "fw-acme-1" in response.text


def test_build_isolation_check_distinguishes_external_isolation(monkeypatch, tmp_path):
    from app.services import network_diagnostics

    monkeypatch.setattr(
        network_diagnostics.settings, "network_control_mode", "external"
    )
    monkeypatch.setattr(
        network_diagnostics.settings, "hub_manage_firewall_rules", False
    )
    monkeypatch.setattr(
        network_diagnostics,
        "verify_nftables_rule_present",
        lambda _settings: (_ for _ in ()).throw(RuntimeError("should not run")),
    )

    result = network_diagnostics.build_isolation_check()

    assert result["state"] == "warning"
    assert result["label"] == "Externally enforced"
    assert "outside the app runtime" in result["summary"]


def test_device_page_renders_tunnel_diagnostics(monkeypatch, tmp_path):
    with sqlite_session(tmp_path, "device_network_page") as session:
        admin = seed_backup_source(session)
        device = session.scalar(select(Device).where(Device.hostname == "fw-acme-1"))
        assert device is not None
        session.add(
            AuditLog(
                id=uuid4(),
                company_id=device.company_id,
                action="enrollment.peer_add_failed",
                ip_address="198.51.100.20",
                created_at=utc_now(),
            )
        )
        session.commit()
        monkeypatch.setattr(
            "app.services.network_diagnostics.get_runtime_peers",
            lambda: [
                __import__(
                    "app.wireguard", fromlist=["RuntimeWireGuardPeer"]
                ).RuntimeWireGuardPeer(
                    public_key=device.wg_public_key,
                    preshared_key="(off)",
                    endpoint="198.51.100.10:51820",
                    allowed_ips=[f"{device.wg_tunnel_ip}/32"],
                    last_handshake_at=utc_now(),
                    rx_bytes=100,
                    tx_bytes=200,
                    persistent_keepalive=25,
                )
            ],
        )
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            response = client.get(f"/devices/{device.id}")
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "Tunnel diagnostics" in response.text
    assert "Network policy simulation" in response.text
    assert "Plugin compatibility" in response.text
    assert "Hub failed to add the WireGuard peer" in response.text


def test_enrollment_invalid_otp_writes_audit_log(monkeypatch, tmp_path):
    with sqlite_session(tmp_path, "enrollment_invalid_otp") as session:
        admin = seed_backup_source(session)
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/enroll",
                json={
                    "otp": "BADOTP",
                    "hostname": "fw-test",
                    "wg_public_key": VALID_WG_PUBLIC_KEY,
                },
            )
        entry = session.scalar(
            select(AuditLog)
            .where(AuditLog.action == "enrollment.invalid_otp")
            .order_by(AuditLog.created_at.desc())
        )
        app.dependency_overrides.clear()

    assert response.status_code == 401
    assert entry is not None


def test_device_firmware_card_uses_normalized_update_count(monkeypatch, tmp_path):
    with sqlite_session(tmp_path, "device_firmware_card_detail") as session:
        admin = seed_backup_source(session)
        device = session.scalar(select(Device).where(Device.hostname == "fw-acme-1"))
        assert device is not None
        device.firmware_status = "update"
        device.firmware_update_count = 0
        device.firmware_status_message = "There are 0 updates available."
        device.firmware_checked_at = utc_now()
        session.commit()
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            response = client.get(f"/devices/{device.id}")
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "Updates available" in response.text
    assert "Updates are available." in response.text
    assert "There are 0 updates available." not in response.text


def test_device_runbook_update_persists_fields(monkeypatch, tmp_path):
    with sqlite_session(tmp_path, "device_runbook_update") as session:
        admin = seed_backup_source(session)
        device = session.scalar(select(Device).where(Device.hostname == "fw-acme-1"))
        assert device is not None
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            csrf_token = get_csrf(client, f"/devices/{device.id}")
            response = client.post(
                f"/devices/{device.id}/runbook",
                data={
                    "csrf_token": csrf_token,
                    "runbook_owner": "Ops Team",
                    "runbook_contact": "ops@example.com",
                    "runbook_site": "HQ",
                    "support_contract_expires_at": "2030-01-01T09:30",
                    "maintenance_until": "2030-01-01T10:30",
                    "escalation_hint": "Escalate to MSP after 15 minutes",
                    "runbook_notes": "Primary site firewall",
                },
                follow_redirects=False,
            )
        session.refresh(device)
        audit_entry = session.scalar(
            select(AuditLog)
            .where(
                AuditLog.device_id == device.id,
                AuditLog.action == "device.runbook.update",
            )
            .order_by(AuditLog.created_at.desc())
        )
        app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"].endswith("status=runbook-saved")
    assert device.runbook_owner == "Ops Team"
    assert device.runbook_contact == "ops@example.com"
    assert device.runbook_site == "HQ"
    assert device.escalation_hint == "Escalate to MSP after 15 minutes"
    assert device.runbook_notes == "Primary site firewall"
    assert device.support_contract_expires_at is not None
    assert device.maintenance_until is not None
    assert audit_entry is not None


def test_device_health_acknowledgement_can_be_saved_and_cleared(monkeypatch, tmp_path):
    with sqlite_session(tmp_path, "device_health_acknowledgement") as session:
        admin = seed_backup_source(session)
        device = session.scalar(select(Device).where(Device.hostname == "fw-acme-1"))
        assert device is not None
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            csrf_token = get_csrf(client, f"/devices/{device.id}")
            acknowledge_response = client.post(
                f"/devices/{device.id}/acknowledge-health",
                data={
                    "csrf_token": csrf_token,
                    "acknowledgement_note": "Investigating upstream tunnel issue",
                },
                follow_redirects=False,
            )
            clear_response = client.post(
                f"/devices/{device.id}/clear-acknowledgement",
                data={"csrf_token": csrf_token},
                follow_redirects=False,
            )
        audit_actions = {
            row.action
            for row in session.scalars(
                select(AuditLog).where(AuditLog.device_id == device.id)
            ).all()
        }
        session.refresh(device)
        app.dependency_overrides.clear()

    assert acknowledge_response.status_code == 303
    assert acknowledge_response.headers["location"].endswith(
        "status=health-acknowledged"
    )
    assert clear_response.status_code == 303
    assert clear_response.headers["location"].endswith(
        "status=health-acknowledgement-cleared"
    )
    assert device.health_acknowledged_at is None
    assert device.health_acknowledged_note is None
    assert device.health_acknowledged_by is None
    assert "device.health_acknowledge" in audit_actions
    assert "device.health_acknowledge.clear" in audit_actions


def test_company_detail_shows_overview_timeline_and_risks(monkeypatch, tmp_path):
    with sqlite_session(tmp_path, "company_detail_overview") as session:
        admin = seed_backup_source(session)
        device = session.scalar(select(Device).where(Device.hostname == "fw-acme-1"))
        assert device is not None
        device.status = "warning"
        device.health_missed_checks = 2
        device.backup_enabled = True
        device.backup_last_uploaded_at = utc_now() - timedelta(days=3)
        session.add(
            DeviceEvent(
                id=uuid4(),
                device_id=device.id,
                event_type="health_check",
                message="WebGUI unreachable",
                created_at=utc_now(),
            )
        )
        session.add(
            AuditLog(
                id=uuid4(),
                user_id=admin.id,
                company_id=device.company_id,
                device_id=device.id,
                action="device.health_acknowledge",
                ip_address="127.0.0.1",
                user_agent="pytest",
                created_at=utc_now(),
            )
        )
        session.commit()
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            response = client.get(f"/companies/{device.company_id}")
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "Company overview" in response.text
    assert "Risky firewalls" in response.text
    assert "Recent company activity" in response.text
    assert "company-overview-grid" in response.text
    assert "timeline-scroll-panel" in response.text
    assert "Health issue acknowledged" in response.text
    assert "fw-acme-1" in response.text


def test_parse_backup_bundle_rejects_archives_with_too_many_members(monkeypatch):
    monkeypatch.setattr(settings, "max_backup_restore_entries", 2)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("manifest.json", json.dumps({"format_version": 1}))
        bundle.writestr(
            "data.json",
            json.dumps(
                {
                    "users": [],
                    "integration_settings": [],
                    "companies": [],
                    "company_users": [],
                    "enrollment_codes": [],
                    "devices": [],
                    "device_backups": [],
                    "device_events": [],
                    "audit_logs": [],
                }
            ),
        )
        bundle.writestr("extra.txt", "unexpected")

    try:
        parse_backup_bundle(archive.getvalue())
        assert False, "expected parse_backup_bundle to reject oversized member count"
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 400
        assert "too many files" in str(getattr(exc, "detail", exc))


def test_admin_can_regenerate_local_user_mfa_from_manage_users(monkeypatch, tmp_path):
    with sqlite_session(tmp_path, "admin_manage_user_mfa") as session:
        admin = seed_backup_source(session)
        managed_user = User(
            id=uuid4(),
            email="local-user@example.com",
            password_hash=hash_secret("StrongPassword123"),
            role="user",
        )
        session.add(managed_user)
        session.commit()
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            page = client.get(f"/settings/users/{managed_user.id}/mfa")
            assert page.status_code == 200
            csrf_token = get_csrf(client, f"/settings/users/{managed_user.id}/mfa")
            begin = client.post(
                f"/settings/users/{managed_user.id}/mfa/begin",
                data={"csrf_token": csrf_token},
            )
            assert begin.status_code == 200
            assert "data:image/svg+xml;base64," in begin.text
            secret_marker = 'name="secret" value="'
            secret_start = begin.text.index(secret_marker) + len(secret_marker)
            secret_end = begin.text.index('"', secret_start)
            secret = begin.text[secret_start:secret_end]
            csrf_marker = 'name="csrf_token" value="'
            csrf_start = begin.text.index(csrf_marker) + len(csrf_marker)
            csrf_end = begin.text.index('"', csrf_start)
            apply_csrf = begin.text[csrf_start:csrf_end]
            apply = client.post(
                f"/settings/users/{managed_user.id}/mfa/apply",
                data={"csrf_token": apply_csrf, "secret": secret},
                follow_redirects=False,
            )
            session.refresh(managed_user)
            assert apply.status_code == 303
            assert (
                apply.headers["location"]
                == "/settings/manage-users?status=user-updated"
            )
            assert managed_user.mfa_enabled is False
            assert managed_user.mfa_secret is not None

            configure_test_client(monkeypatch, session, admin)
            pending_page = client.get(f"/settings/users/{managed_user.id}/mfa")
            assert pending_page.status_code == 200
            assert "pending user confirmation" in pending_page.text
            assert "data:image/svg+xml;base64," in pending_page.text

            configure_test_client(monkeypatch, session, managed_user)
            account_page = client.get("/account/security")
            assert account_page.status_code == 200
            assert "data:image/svg+xml;base64," in account_page.text
            enable_csrf = get_csrf(client, "/account/security")
            enable_response = client.post(
                "/account/security/mfa/enable",
                data={
                    "csrf_token": enable_csrf,
                    "secret": secret,
                    "code": totp_code(secret),
                },
                follow_redirects=False,
            )
            assert enable_response.status_code == 303
            assert (
                enable_response.headers["location"]
                == "/account/security?status=mfa-enabled"
            )
            session.refresh(managed_user)
            assert managed_user.mfa_enabled is True
        app.dependency_overrides.clear()


def test_non_admin_user_can_view_assigned_companies_and_firewalls(
    monkeypatch, tmp_path
):
    with sqlite_session(tmp_path, "non_admin_company_visibility") as session:
        seed_backup_source(session)
        company = session.scalar(select(Company).where(Company.name == "Acme"))
        assert company is not None
        member = User(
            id=uuid4(),
            email="member@example.com",
            password_hash=hash_secret("MemberPassword123"),
            role="user",
        )
        session.add(member)
        session.flush()
        session.add(
            CompanyUser(company_id=company.id, user_id=member.id, role="viewer")
        )
        session.commit()
        configure_test_client(monkeypatch, session, member)
        with TestClient(app) as client:
            companies_response = client.get("/companies")
            dashboard_response = client.get("/dashboard")
        app.dependency_overrides.clear()

    assert companies_response.status_code == 200
    assert "Acme" in companies_response.text
    assert "fw-acme-1" in companies_response.text
    assert "Bulk actions" not in companies_response.text
    assert "data-company-row" in companies_response.text
    assert f'href="/companies/{company.id}"' in companies_response.text
    assert "You need company admin access to add firewalls" in companies_response.text
    assert "Add Firewall" not in companies_response.text
    assert dashboard_response.status_code == 200
    assert "fw-acme-1" in dashboard_response.text


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


def test_audit_logs_page_lists_firewall_lifecycle_and_access_entries(
    monkeypatch, tmp_path
):
    with sqlite_session(tmp_path, "audit_logs_page") as session:
        admin = seed_backup_source(session)
        device = session.scalars(select(Device)).first()
        company = session.scalars(select(Company)).first()
        assert device is not None
        assert company is not None
        for action in (
            "device.enroll",
            "device.revoke",
            "device.delete_revoked",
            "device.view",
            "device.proxy.open",
        ):
            session.add(
                AuditLog(
                    id=uuid4(),
                    user_id=admin.id,
                    company_id=company.id,
                    device_id=device.id,
                    action=action,
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
    assert "Firewall added" in response.text
    assert "Firewall revoked" in response.text
    assert "Firewall removed" in response.text
    assert "Firewall viewed" in response.text
    assert "Firewall UI opened" in response.text


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


def test_email_settings_persist_phase_two_notification_rules(monkeypatch, tmp_path):
    with sqlite_session(tmp_path, "email_phase_two_rules") as session:
        admin = seed_backup_source(session)
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            csrf_token = get_csrf(client, "/settings/email-settings")
            response = client.post(
                "/settings/email",
                data={
                    "csrf_token": csrf_token,
                    "smtp_enabled": "on",
                    "smtp_host": "smtp.example.com",
                    "smtp_port": "2525",
                    "smtp_from": "hub@example.com",
                    "notify_on_offline": "on",
                    "notify_on_backup_overdue": "on",
                    "notify_on_license_expiring": "",
                    "notify_on_firmware_available": "on",
                    "notify_on_repeated_auth_failures": "",
                },
                follow_redirects=False,
            )
        settings_row = session.get(IntegrationSettings, 1)
        app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/settings/email-settings?status=email-saved"
    assert settings_row is not None
    assert settings_row.notify_on_offline is True
    assert settings_row.notify_on_backup_overdue is True
    assert settings_row.notify_on_license_expiring is False
    assert settings_row.notify_on_firmware_available is True
    assert settings_row.notify_on_repeated_auth_failures is False


def test_dashboard_saved_filters_can_be_created_deleted_and_exported(
    monkeypatch, tmp_path
):
    with sqlite_session(tmp_path, "dashboard_filters_export") as session:
        admin = seed_backup_source(session)
        company = session.scalars(select(Company)).first()
        device = session.scalars(select(Device)).first()
        assert company is not None
        assert device is not None
        company_name = company.name
        device_hostname = device.hostname
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            csrf_token = get_csrf(client, "/dashboard")
            create_response = client.post(
                "/dashboard/filters",
                data={
                    "csrf_token": csrf_token,
                    "name": "Alpha online",
                    "company_id": str(company.id),
                    "status": "online",
                },
                follow_redirects=False,
            )
            saved_filter = session.scalars(select(UserDashboardFilter)).first()
            assert saved_filter is not None
            dashboard_response = client.get("/dashboard")
            export_response = client.get(
                f"/dashboard/export/devices.csv?company_id={company.id}&status=online"
            )
            delete_response = client.post(
                f"/dashboard/filters/{saved_filter.id}/delete",
                data={"csrf_token": csrf_token},
                follow_redirects=False,
            )
        remaining_filters = session.scalars(select(UserDashboardFilter)).all()
        app.dependency_overrides.clear()

    assert create_response.status_code == 303
    assert "result=filter-saved" in create_response.headers["location"]
    assert "company_id=" in create_response.headers["location"]
    assert dashboard_response.status_code == 200
    assert "Select a saved filter" in dashboard_response.text
    assert "Alpha online" in dashboard_response.text
    assert export_response.status_code == 200
    assert export_response.headers["content-type"].startswith("text/csv")
    csv_text = export_response.text
    assert "company,hostname,status,backup_status,firmware_status,license" in csv_text
    assert company_name in csv_text
    assert device_hostname in csv_text
    assert delete_response.status_code == 303
    assert "result=filter-deleted" in delete_response.headers["location"]
    assert remaining_filters == []


def test_companies_bulk_actions_update_selected_devices(monkeypatch, tmp_path):
    with sqlite_session(tmp_path, "companies_bulk_actions") as session:
        admin = seed_backup_source(session)
        company = session.scalars(select(Company)).first()
        assert company is not None
        second_device = Device(
            id=uuid4(),
            company_id=company.id,
            hostname="fw-acme-2",
            wg_public_key="C" * 43 + "=",
            wg_tunnel_ip="100.96.0.11",
            device_token_hash=hash_secret("device-token-2"),
            status="online",
            created_at=utc_now(),
        )
        session.add(second_device)
        session.commit()
        devices = session.scalars(select(Device).order_by(Device.hostname)).all()
        configure_test_client(monkeypatch, session, admin)
        with TestClient(app) as client:
            csrf_token = get_csrf(client, "/companies")
            backup_response = client.post(
                "/companies/devices/bulk-action",
                data={
                    "csrf_token": csrf_token,
                    "action": "request-backup",
                    "device_ids": [str(device.id) for device in devices],
                },
                follow_redirects=False,
            )
            firmware_response = client.post(
                "/companies/devices/bulk-action",
                data={
                    "csrf_token": csrf_token,
                    "action": "request-firmware-check",
                    "device_ids": [str(device.id) for device in devices],
                },
                follow_redirects=False,
            )
        for device in devices:
            session.refresh(device)
        app.dependency_overrides.clear()

    assert backup_response.status_code == 303
    assert (
        backup_response.headers["location"] == "/companies?result=bulk-backup-requested"
    )
    assert firmware_response.status_code == 303
    assert (
        firmware_response.headers["location"]
        == "/companies?result=bulk-firmware-requested"
    )
    assert all(device.backup_last_requested_at is not None for device in devices)
    assert all(device.firmware_check_requested_at is not None for device in devices)
    assert all(device.firmware_check_request_reason == "manual" for device in devices)


def test_repeated_auth_failures_notify_on_fifth_attempt(monkeypatch, tmp_path):
    with sqlite_session(tmp_path, "repeated_auth_failures") as session:
        seed_backup_source(session)
        now = utc_now()
        sent_messages: list[tuple[str, str]] = []

        def fake_send_security_alert_email(_db, subject: str, body: str) -> bool:
            sent_messages.append((subject, body))
            return True

        monkeypatch.setattr(
            "app.services.notification_service.send_security_alert_email",
            fake_send_security_alert_email,
        )
        for index in range(5):
            session.add(
                AuditLog(
                    id=uuid4(),
                    action="auth.local.failed",
                    ip_address="127.0.0.1",
                    user_agent="pytest",
                    created_at=now - timedelta(minutes=1) + timedelta(seconds=index),
                )
            )
        session.commit()

        notified = maybe_notify_for_repeated_auth_failures(
            session,
            "auth.local.failed",
            "bad password",
            current_time=now,
        )

    assert notified is True
    assert len(sent_messages) == 1
    assert "Repeated auth failures" in sent_messages[0][0]
    assert "Recent failures in the last 15 minutes: 5" in sent_messages[0][1]
