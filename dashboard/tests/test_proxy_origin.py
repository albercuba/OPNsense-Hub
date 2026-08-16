import re
from contextlib import contextmanager
from http.cookies import SimpleCookie
from typing import ClassVar
from uuid import uuid4

from app.database import Base, get_db
from app.main import app, current_user
from app.models import Company, CompanyUser, Device, DeviceProxySession, User
from app.security import hash_secret
from app.security.csrf import sign_csrf_token
from app.services.proxy_auth import proxy_session_cookie_name
from app.web import settings
from sqlalchemy import create_engine, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient


@compiles(INET, "sqlite")
def compile_inet_sqlite(_type, _compiler, **_kw):
    return "TEXT"


async def noop():
    return None


@contextmanager
def proxy_test_session():
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


def seed_proxy_data(session: Session):
    user = User(
        id=uuid4(),
        email="viewer@example.com",
        password_hash=hash_secret("StrongPassword123"),
        role="user",
    )
    allowed_company = Company(id=uuid4(), name="Allowed Company")
    denied_company = Company(id=uuid4(), name="Denied Company")
    allowed_device = Device(
        id=uuid4(),
        company_id=allowed_company.id,
        hostname="allowed-fw",
        wg_public_key="A" * 43 + "=",
        wg_tunnel_ip="100.96.0.10",
        device_token_hash=hash_secret("allowed-token"),
        status="online",
    )
    denied_device = Device(
        id=uuid4(),
        company_id=denied_company.id,
        hostname="denied-fw",
        wg_public_key="B" * 43 + "=",
        wg_tunnel_ip="100.96.0.11",
        device_token_hash=hash_secret("denied-token"),
        status="online",
    )
    session.add_all(
        [user, allowed_company, denied_company, allowed_device, denied_device]
    )
    session.flush()
    membership = CompanyUser(
        company_id=allowed_company.id,
        user_id=user.id,
        role="viewer",
    )
    session.add(membership)
    session.commit()
    return user, allowed_device, denied_device, membership


def configure_test_client(monkeypatch, session: Session, user: User):
    monkeypatch.setattr("app.main.bootstrap", lambda: None)
    monkeypatch.setattr("app.main.apply_startup_hardening", lambda _settings: None)
    monkeypatch.setattr("app.main.device_health_check_loop", noop)
    monkeypatch.setattr("app.main.firmware_check_schedule_loop", noop)
    monkeypatch.setattr("app.main.log_retention_loop", noop)

    def override_get_db():
        yield session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[current_user] = lambda: user


def csrf_form_data(client: TestClient) -> dict[str, str]:
    token = "proxy-origin-csrf-token"
    client.cookies.set(settings.csrf_cookie_name, sign_csrf_token(token))
    return {"csrf_token": token}


def extract_grant(response) -> str:
    match = re.search(r'name="grant" value="([^"]+)"', response.text)
    assert match is not None
    return match.group(1)


class FakeHeaders(dict):
    def get_list(self, name: str) -> list[str]:
        value = self.get(name)
        return [value] if value else []


class FakeProxyResponse:
    status_code = 200
    headers = FakeHeaders({"content-type": "text/html; charset=utf-8"})

    async def aiter_bytes(self):
        yield b'<html><script src="/ui.js"></script></html>'


class FakeProxyStream:
    async def __aenter__(self):
        return FakeProxyResponse()

    async def __aexit__(self, exc_type, exc, traceback):
        return False


class FakeAsyncClient:
    captured_headers: ClassVar[dict[str, str]] = {}

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    def stream(self, method, url, *, headers, content):
        self.__class__.captured_headers = dict(headers)
        return FakeProxyStream()


def test_proxy_origin_handoff_is_one_time_device_scoped_and_host_isolated(monkeypatch):
    with proxy_test_session() as session:
        user, allowed_device, denied_device, membership = seed_proxy_data(session)
        configure_test_client(monkeypatch, session, user)
        proxy_origin = settings.proxy_public_url.rstrip("/")
        dashboard_origin = settings.public_url.rstrip("/")

        with TestClient(app) as client:
            handoff = client.post(
                f"/devices/{allowed_device.id}/proxy/open",
                data=csrf_form_data(client),
                follow_redirects=False,
            )
            assert handoff.status_code == 200
            assert handoff.headers["cache-control"] == "no-store"
            assert handoff.headers["referrer-policy"] == "no-referrer"
            assert f'action="{proxy_origin}/proxy/bootstrap"' in handoff.text
            grant = extract_grant(handoff)
            assert grant not in f"{proxy_origin}/proxy/bootstrap"

            grant_row = session.scalar(
                select(DeviceProxySession).where(
                    DeviceProxySession.phase == "grant"
                )
            )
            assert grant_row is not None
            assert grant_row.token_hash != grant
            assert grant_row.device_id == allowed_device.id

            wrong_origin = client.post(
                f"{proxy_origin}/proxy/bootstrap",
                data={"grant": grant},
                headers={"Origin": "https://attacker.example"},
                follow_redirects=False,
            )
            assert wrong_origin.status_code == 403

            bootstrap = client.post(
                f"{proxy_origin}/proxy/bootstrap",
                data={"grant": grant},
                headers={"Origin": dashboard_origin},
                follow_redirects=False,
            )
            assert bootstrap.status_code == 303
            assert bootstrap.headers["location"] == (
                f"/proxy/devices/{allowed_device.id}/"
            )
            assert grant not in bootstrap.headers["location"]
            assert bootstrap.headers["cache-control"] == "no-store"

            cookie_name = proxy_session_cookie_name(allowed_device.id)
            set_cookie = bootstrap.headers["set-cookie"]
            assert cookie_name in set_cookie
            assert "HttpOnly" in set_cookie
            assert "SameSite=lax" in set_cookie
            assert f"Path=/proxy/devices/{allowed_device.id}" in set_cookie
            assert "Domain=" not in set_cookie
            parsed_cookie = SimpleCookie()
            parsed_cookie.load(set_cookie)
            proxy_token = parsed_cookie[cookie_name].value

            replay = client.post(
                f"{proxy_origin}/proxy/bootstrap",
                data={"grant": grant},
                headers={"Origin": dashboard_origin},
                follow_redirects=False,
            )
            assert replay.status_code == 401

            proxy_dashboard = client.get(f"{proxy_origin}/dashboard")
            assert proxy_dashboard.status_code == 404
            dashboard_proxy = client.get(
                f"{dashboard_origin}/proxy/devices/{allowed_device.id}/"
            )
            assert dashboard_proxy.status_code == 404

            dashboard_cookie_only = client.get(
                f"{proxy_origin}/proxy/devices/{allowed_device.id}/",
                headers={"Cookie": f"{settings.session_cookie_name}=dashboard-token"},
            )
            assert dashboard_cookie_only.status_code == 401

            wrong_device = client.get(
                f"{proxy_origin}/proxy/devices/{denied_device.id}/",
                headers={"Cookie": f"{cookie_name}={proxy_token}"},
            )
            assert wrong_device.status_code == 401

            monkeypatch.setattr(
                "app.routers.proxy.httpx.AsyncClient", FakeAsyncClient
            )
            proxied = client.get(
                f"{proxy_origin}/proxy/devices/{allowed_device.id}/",
                headers={
                    "Cookie": (
                        f"{cookie_name}={proxy_token}; "
                        f"{settings.session_cookie_name}=dashboard-token"
                    )
                },
            )
            assert proxied.status_code == 200
            assert (
                f"/proxy/devices/{allowed_device.id}/ui.js"
                in proxied.text
            )
            assert "cookie" not in {
                key.lower() for key in FakeAsyncClient.captured_headers
            }

            session.delete(membership)
            session.commit()
            membership_removed = client.get(
                f"{proxy_origin}/proxy/devices/{allowed_device.id}/",
                headers={"Cookie": f"{cookie_name}={proxy_token}"},
            )
            assert membership_removed.status_code == 401

        app.dependency_overrides.clear()


def test_proxy_grant_creation_rejects_cross_company_viewer(monkeypatch):
    with proxy_test_session() as session:
        user, _allowed_device, denied_device, _membership = seed_proxy_data(session)
        configure_test_client(monkeypatch, session, user)

        with TestClient(app) as client:
            response = client.post(
                f"/devices/{denied_device.id}/proxy/open",
                data=csrf_form_data(client),
                follow_redirects=False,
            )

        app.dependency_overrides.clear()
        assert response.status_code == 404
        assert session.scalars(select(DeviceProxySession)).all() == []

