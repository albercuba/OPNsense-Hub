import re
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from app.database import Base
from app.deps import device_from_token
from app.main import (
    app,
    current_user,
    get_db,
    login,
    logout,
    session_from_request,
    settings,
)
from app.models import Device, IntegrationSettings, SessionToken, User
from app.security import hash_secret, hash_session_token, totp_code, utc_now
from app.security.secrets import encrypt_secret
from app.services.auth_service import upsert_external_user
from fastapi import HTTPException, Response
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.requests import Request
from starlette.testclient import TestClient


@compiles(INET, "sqlite")
def compile_inet_sqlite(_type, _compiler, **_kw):
    return "TEXT"


class FakeDb:
    def __init__(self, user=None, session=None, integration_settings=None, device=None):
        self.user = user
        self.session = session
        self.integration_settings = integration_settings
        self.device = device
        self.added = []
        self.committed = False

    def scalar(self, _statement):
        if self.session is not None:
            return self.session
        return self.user

    def get(self, model, key):
        if model is User and self.user and key == self.user.id:
            return self.user
        if model is IntegrationSettings and key == 1:
            return self.integration_settings
        if model is Device and self.device and key == self.device.id:
            return self.device
        return None

    def add(self, obj):
        self.added.append(obj)
        if isinstance(obj, SessionToken):
            self.session = obj

    def flush(self):
        return None

    def commit(self):
        self.committed = True


def make_request(cookie_value=None):
    headers = []
    if cookie_value is not None:
        headers.append(
            (b"cookie", f"{settings.session_cookie_name}={cookie_value}".encode())
        )
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
    }
    return Request(scope)


def test_login_sets_random_session_cookie_not_user_uuid(monkeypatch):
    user = User(
        id=uuid4(),
        email="admin@example.org",
        password_hash=hash_secret("StrongPassword123"),
        role="administrator",
    )
    db = FakeDb(user=user)
    response = login(
        make_request(),
        Response(),
        cast(Session, db),
        email=user.email,
        password="StrongPassword123",
    )
    cookie_header = response.headers["set-cookie"]
    assert str(user.id) not in cookie_header
    assert settings.session_cookie_name in cookie_header
    assert any(isinstance(item, SessionToken) for item in db.added)


def test_session_from_request_rejects_expired_or_revoked_session():
    user_id = uuid4()
    expired = SessionToken(
        user_id=user_id,
        token_hash="hash",
        expires_at=utc_now() - timedelta(minutes=1),
    )
    db = FakeDb(session=expired)
    with pytest.raises(HTTPException):
        session_from_request(make_request("token"), cast(Session, db))

    revoked = SessionToken(
        user_id=user_id,
        token_hash="hash",
        expires_at=utc_now() + timedelta(hours=1),
        revoked_at=utc_now(),
    )
    db = FakeDb(session=revoked)
    with pytest.raises(HTTPException):
        session_from_request(make_request("token"), cast(Session, db))


def test_current_user_looks_up_user_from_hashed_session_token():
    user = User(id=uuid4(), email="admin@example.org", password_hash="hash")
    token = "session-token"
    session = SessionToken(
        user_id=user.id,
        token_hash=hash_session_token(settings.secret_key, token),
        expires_at=utc_now() + timedelta(hours=1),
    )
    db = FakeDb(user=user, session=session)
    assert current_user(make_request(token), cast(Session, db)).id == user.id


def test_device_from_token_returns_gone_for_revoked_device():
    device_token = "device-token"
    device = Device(
        id=uuid4(),
        company_id=uuid4(),
        hostname="fw-1",
        wg_public_key="pubkey",
        wg_tunnel_ip="100.96.0.2",
        device_token_hash=hash_secret(device_token),
        revoked_at=utc_now(),
    )
    db = FakeDb(device=device)

    with pytest.raises(HTTPException) as exc_info:
        device_from_token(cast(Session, db), device.id, f"Bearer {device_token}")

    assert exc_info.value.status_code == 410
    assert exc_info.value.detail == "device revoked"


def test_upsert_external_user_marks_auth_provider():
    db = FakeDb()

    user = upsert_external_user(
        cast(Session, db),
        "entra-user@example.org",
        first_name="Entra",
        last_name="User",
        role="administrator",
        auth_provider="microsoft",
    )

    assert user.auth_provider == "microsoft"
    assert any(isinstance(item, User) for item in db.added)


def test_upsert_external_user_rejects_existing_local_account():
    existing = User(
        id=uuid4(),
        email="local-user@example.org",
        password_hash=hash_secret("StrongPassword123"),
        role="administrator",
    )
    db = FakeDb(user=existing)

    with pytest.raises(RuntimeError, match="must be explicitly linked"):
        upsert_external_user(
            cast(Session, db),
            existing.email,
            first_name="Local",
            last_name="User",
            role="administrator",
            auth_provider="microsoft",
        )


def test_logout_revokes_session_and_clears_cookie():
    user = User(id=uuid4(), email="admin@example.org", password_hash="hash")
    token = "session-token"
    session = SessionToken(
        user_id=user.id,
        token_hash=hash_session_token(settings.secret_key, token),
        expires_at=utc_now() + timedelta(hours=1),
    )
    db = FakeDb(user=user, session=session)
    response = logout(make_request(token), cast(Session, db), user)
    assert session.revoked_at is not None
    assert db.committed is True
    assert settings.session_cookie_name in response.headers.get("set-cookie", "")


def test_active_sessions_helpers_exclude_expired_sessions():
    from app.services.admin_security import (
        active_sessions_for_admin,
        active_sessions_for_user,
    )

    with sqlite_session(Path(".")) as session:
        user = User(
            id=uuid4(),
            email="user@example.org",
            password_hash=hash_secret("StrongPassword123"),
            role="user",
        )
        session.add(user)
        session.flush()
        session.add_all(
            [
                SessionToken(
                    user_id=user.id,
                    token_hash="active-session",
                    expires_at=utc_now() + timedelta(hours=1),
                ),
                SessionToken(
                    user_id=user.id,
                    token_hash="expired-session",
                    expires_at=utc_now() - timedelta(minutes=1),
                ),
            ]
        )
        session.commit()

        user_sessions = active_sessions_for_user(session, user.id)
        admin_sessions = active_sessions_for_admin(session)

    assert len(user_sessions) == 1
    assert user_sessions[0].token_hash == "active-session"
    assert len(admin_sessions) == 1
    assert admin_sessions[0].token_hash == "active-session"


def test_login_page_only_shows_external_auth_buttons_when_fully_configured(monkeypatch):
    async def noop():
        return None

    monkeypatch.setattr("app.main.bootstrap", lambda: None)
    monkeypatch.setattr("app.main.apply_startup_hardening", lambda _settings: None)
    monkeypatch.setattr("app.main.device_health_check_loop", noop)
    monkeypatch.setattr("app.main.firmware_check_schedule_loop", noop)

    cases = [
        (
            IntegrationSettings(
                id=1,
                microsoft_enabled=True,
                microsoft_tenant_id="tenant",
                microsoft_client_id="client",
                microsoft_client_secret="secret",
                microsoft_audience="api://hub-client",
                ad_enabled=True,
                ad_host="ldaps://ad.example.com",
                ad_base_dn="DC=example,DC=com",
            ),
            True,
            True,
        ),
        (
            IntegrationSettings(
                id=1,
                microsoft_enabled=True,
                microsoft_tenant_id="tenant",
                microsoft_client_id="client",
                microsoft_client_secret=None,
                microsoft_audience=None,
                ad_enabled=True,
                ad_host="ldaps://ad.example.com",
                ad_base_dn=None,
            ),
            False,
            False,
        ),
        (IntegrationSettings(id=1), False, False),
    ]

    for integration_settings, expect_microsoft, expect_local_ad in cases:
        db = FakeDb(integration_settings=integration_settings)

        def override_get_db():
            yield db

        app.dependency_overrides[get_db] = override_get_db
        with TestClient(app) as client:
            response = client.get("/login")
        app.dependency_overrides.clear()

        assert response.status_code == 200
        assert ('id="microsoft-login-button"' in response.text) == expect_microsoft
        assert ('formaction="/auth/local-ad"' in response.text) == expect_local_ad


def test_microsoft_login_start_redirects_and_sets_pkce_cookies(monkeypatch):
    db = FakeDb(
        integration_settings=IntegrationSettings(
            id=1,
            microsoft_enabled=True,
            microsoft_tenant_id="tenant",
            microsoft_client_id="client",
            microsoft_client_secret="secret",
            microsoft_audience="api://hub-client",
        )
    )

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
        response = client.get(
            "/auth/microsoft/start?login_hint=user@example.com",
            follow_redirects=False,
        )
    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"].startswith(
        "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?"
    )
    assert "login_hint=user%40example.com" in response.headers["location"]
    cookie_header = response.headers.get("set-cookie", "")
    assert "opnhub_ms_state=" in cookie_header
    assert "opnhub_ms_verifier=" in cookie_header
    assert response.headers["location"].startswith(
        "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?"
    )
    assert "login_hint=user%40example.com" in response.headers["location"]
    cookie_header = response.headers.get("set-cookie", "")
    assert "opnhub_ms_state=" in cookie_header
    assert "opnhub_ms_verifier=" in cookie_header


def disable_background_startup(monkeypatch):
    async def noop():
        return None

    monkeypatch.setattr("app.main.bootstrap", lambda: None)
    monkeypatch.setattr("app.main.apply_startup_hardening", lambda _settings: None)
    monkeypatch.setattr("app.main.device_health_check_loop", noop)
    monkeypatch.setattr("app.main.firmware_check_schedule_loop", noop)


@contextmanager
def sqlite_session(_tmp_path: Path):
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


def extract_csrf_token(response_text: str) -> str:
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response_text)
    assert match is not None
    return match.group(1)


def extract_input_value(response_text: str, field_name: str) -> str:
    match = re.search(
        rf'name="{re.escape(field_name)}"\s+value="([^"]*)"', response_text
    )
    assert match is not None
    return match.group(1)


def test_dashboard_redirects_to_login_when_not_authenticated(monkeypatch):
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


def test_local_user_can_enable_and_disable_totp_mfa(monkeypatch, tmp_path):
    disable_background_startup(monkeypatch)
    with sqlite_session(tmp_path) as session:
        user = User(
            id=uuid4(),
            email="local-user@example.org",
            password_hash=hash_secret("StrongPassword123"),
            role="user",
        )
        session.add(user)
        session.commit()

        def override_get_db():
            yield session

        app.dependency_overrides[get_db] = override_get_db
        with TestClient(app) as client:
            login_page = client.get("/login")
            csrf_token = extract_csrf_token(login_page.text)
            login_response = client.post(
                "/api/v1/auth/login",
                data={
                    "csrf_token": csrf_token,
                    "email": user.email,
                    "password": "StrongPassword123",
                },
                follow_redirects=False,
            )
            assert login_response.status_code == 303
            assert login_response.headers["location"] == "/dashboard"

            account_page = client.get("/account/security")
            assert account_page.status_code == 200
            csrf_token = extract_csrf_token(account_page.text)
            begin_response = client.post(
                "/account/security/mfa/begin",
                data={"csrf_token": csrf_token},
            )
            assert begin_response.status_code == 200
            assert "data:image/svg+xml;base64," in begin_response.text
            assert "Provisioning URI" not in begin_response.text
            secret = extract_input_value(begin_response.text, "secret")
            enable_csrf = extract_csrf_token(begin_response.text)
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

            session.refresh(user)
            assert user.mfa_enabled is True
            assert user.mfa_secret is not None

            disable_page = client.get("/account/security")
            disable_csrf = extract_csrf_token(disable_page.text)
            disable_response = client.post(
                "/account/security/mfa/disable",
                data={
                    "csrf_token": disable_csrf,
                    "password": "StrongPassword123",
                    "code": totp_code(secret),
                },
                follow_redirects=False,
            )
            assert disable_response.status_code == 303
            assert (
                disable_response.headers["location"]
                == "/account/security?status=mfa-disabled"
            )

            session.refresh(user)
            assert user.mfa_enabled is False
            assert user.mfa_secret is None
        app.dependency_overrides.clear()


def test_local_login_with_enabled_totp_requires_second_step(monkeypatch, tmp_path):
    disable_background_startup(monkeypatch)
    secret = "JBSWY3DPEHPK3PXP"
    with sqlite_session(tmp_path) as session:
        user = User(
            id=uuid4(),
            email="mfa-user@example.org",
            password_hash=hash_secret("StrongPassword123"),
            role="user",
            mfa_enabled=True,
            mfa_secret=encrypt_secret(secret),
        )
        session.add(user)
        session.commit()

        def override_get_db():
            yield session

        app.dependency_overrides[get_db] = override_get_db
        with TestClient(app) as client:
            login_page = client.get("/login")
            csrf_token = extract_csrf_token(login_page.text)
            login_response = client.post(
                "/api/v1/auth/login",
                data={
                    "csrf_token": csrf_token,
                    "email": user.email,
                    "password": "StrongPassword123",
                },
                follow_redirects=False,
            )
            assert login_response.status_code == 303
            assert login_response.headers["location"] == "/auth/mfa"

            mfa_page = client.get("/auth/mfa")
            assert mfa_page.status_code == 200
            mfa_csrf = extract_csrf_token(mfa_page.text)
            mfa_response = client.post(
                "/auth/mfa",
                data={"csrf_token": mfa_csrf, "code": totp_code(secret)},
                follow_redirects=False,
            )
            assert mfa_response.status_code == 303
            assert mfa_response.headers["location"] == "/dashboard"

            dashboard_response = client.get("/dashboard", follow_redirects=False)
            assert dashboard_response.status_code == 200
        app.dependency_overrides.clear()


def test_account_security_allows_revoking_another_active_session(monkeypatch, tmp_path):
    disable_background_startup(monkeypatch)
    with sqlite_session(tmp_path) as session:
        user = User(
            id=uuid4(),
            email="local-user@example.org",
            password_hash=hash_secret("StrongPassword123"),
            role="user",
        )
        session.add(user)
        session.commit()

        def override_get_db():
            yield session

        app.dependency_overrides[get_db] = override_get_db
        with TestClient(app) as client:
            login_page = client.get("/login")
            csrf_token = extract_csrf_token(login_page.text)
            login_response = client.post(
                "/api/v1/auth/login",
                data={
                    "csrf_token": csrf_token,
                    "email": user.email,
                    "password": "StrongPassword123",
                },
                follow_redirects=False,
            )
            assert login_response.status_code == 303
            extra_session = SessionToken(
                user_id=user.id,
                token_hash="secondary-token-hash",
                ip_address="203.0.113.5",
                user_agent="pytest secondary session",
                expires_at=utc_now() + timedelta(hours=1),
            )
            session.add(extra_session)
            session.commit()

            account_page = client.get("/account/security")
            assert account_page.status_code == 200
            assert "Active sessions" in account_page.text
            csrf_token = extract_csrf_token(account_page.text)
            revoke_response = client.post(
                f"/account/security/sessions/{extra_session.id}/revoke",
                data={"csrf_token": csrf_token},
                follow_redirects=False,
            )
            assert revoke_response.status_code == 303
            assert (
                revoke_response.headers["location"]
                == "/account/security?status=session-revoked"
            )
            session.refresh(extra_session)
            assert extra_session.revoked_at is not None
        app.dependency_overrides.clear()


def test_admin_login_allowlist_blocks_disallowed_local_login(monkeypatch, tmp_path):
    disable_background_startup(monkeypatch)
    monkeypatch.setattr(
        "app.services.admin_security.client_ip", lambda _request: "198.51.100.20"
    )
    with sqlite_session(tmp_path) as session:
        user = User(
            id=uuid4(),
            email="admin@example.org",
            password_hash=hash_secret("StrongPassword123"),
            role="administrator",
        )
        session.add_all(
            [
                user,
                IntegrationSettings(id=1, admin_login_allowlist="203.0.113.10/32"),
            ]
        )
        session.commit()

        def override_get_db():
            yield session

        app.dependency_overrides[get_db] = override_get_db
        with TestClient(app) as client:
            login_page = client.get("/login")
            csrf_token = extract_csrf_token(login_page.text)
            response = client.post(
                "/api/v1/auth/login",
                data={
                    "csrf_token": csrf_token,
                    "email": user.email,
                    "password": "StrongPassword123",
                },
            )
        app.dependency_overrides.clear()

    assert response.status_code == 403
    assert "Administrator login is not allowed from this IP address." in response.text
