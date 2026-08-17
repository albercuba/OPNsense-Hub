import asyncio
from contextlib import contextmanager
import re
import threading
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from app.database import Base, get_db
from app.main import app, current_user
from app.models import (
    Company,
    CompanyUser,
    Device,
    DeviceProxySession,
    SessionToken,
    User,
)
from app.security import hash_secret, hash_session_token
from app.routers import proxy as proxy_router
from app.security.csrf import sign_csrf_token
from app.services.proxy_auth import create_connector_session
from app.services.tcp_relay import TcpRelayAllocation
from app.web import settings
from sqlalchemy import create_engine, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect


@compiles(INET, "sqlite")
def compile_inet_sqlite(_type, _compiler, **_kw):
    return "TEXT"


async def noop():
    return None


@contextmanager
def connector_test_database():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SessionFactory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(engine)
    session = SessionFactory()
    try:
        yield session, SessionFactory
    finally:
        session.close()
        engine.dispose()


def seed_connector_data(session: Session):
    user = User(
        id=uuid4(),
        email="viewer@example.com",
        password_hash=hash_secret("StrongPassword123"),
        role="user",
    )
    company = Company(id=uuid4(), name="Allowed Company")
    other_company = Company(id=uuid4(), name="Other Company")
    device = Device(
        id=uuid4(),
        company_id=company.id,
        hostname="allowed-fw",
        wg_public_key="A" * 43 + "=",
        wg_tunnel_ip="100.96.0.10",
        device_token_hash=hash_secret("allowed-token"),
        status="online",
    )
    other_device = Device(
        id=uuid4(),
        company_id=other_company.id,
        hostname="other-fw",
        wg_public_key="B" * 43 + "=",
        wg_tunnel_ip="100.96.0.11",
        device_token_hash=hash_secret("other-token"),
        status="online",
    )
    session.add_all([user, company, other_company, device, other_device])
    session.flush()
    session.add(CompanyUser(company_id=company.id, user_id=user.id, role="viewer"))
    session.commit()
    return user, device, other_device


def configure_test_client(monkeypatch, session, session_factory, user):
    dashboard_session = SessionToken(
        id=uuid4(),
        user_id=user.id,
        token_hash=hash_session_token(settings.secret_key, f"dashboard-{uuid4()}"),
        created_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    session.add(dashboard_session)
    session.commit()

    monkeypatch.setattr("app.main.bootstrap", lambda: None)
    monkeypatch.setattr("app.main.apply_startup_hardening", lambda _settings: None)
    monkeypatch.setattr("app.main.device_health_check_loop", noop)
    monkeypatch.setattr("app.main.firmware_check_schedule_loop", noop)
    monkeypatch.setattr("app.main.log_retention_loop", noop)
    monkeypatch.setattr("app.routers.proxy.SessionLocal", session_factory)
    monkeypatch.setattr(
        "app.routers.proxy.session_from_request",
        lambda _request, _db: dashboard_session,
    )

    def override_get_db():
        yield session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[current_user] = lambda: user
    return dashboard_session


def csrf_form_data(client: TestClient) -> dict[str, str]:
    token = "connector-csrf-token"
    client.cookies.set(settings.csrf_cookie_name, sign_csrf_token(token))
    return {"csrf_token": token}


def extract_connector_token(response) -> str:
    match = re.search(
        r'<textarea readonly aria-label="Connector token">([^<]+)</textarea>',
        response.text,
    )
    assert match is not None
    return match.group(1).strip()


class FakeRelayManager:
    def __init__(self):
        self.created: list[TcpRelayAllocation] = []
        self.closed_allocations: list[TcpRelayAllocation] = []

    async def close_device(self, _device_id):
        return 0

    async def create_relay(
        self,
        device_id,
        _target_host,
        _target_port,
        _source_ip,
        public_base_host,
    ):
        allocation = TcpRelayAllocation(
            device_id=device_id,
            bind_host="127.0.0.1",
            public_host=f"d-{device_id.hex}.{public_base_host}",
            port=55000,
            url=f"https://d-{device_id.hex}.{public_base_host}:55000/",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        self.created.append(allocation)
        return allocation

    async def close_allocation(self, allocation):
        self.closed_allocations.append(allocation)
        return True

    async def close_all(self):
        return 0


class FakeUpstreamWriter:
    def __init__(self):
        self.received = bytearray()
        self.data_received = asyncio.Event()
        self.closed = False
        self.closed_event = threading.Event()

    def write(self, data: bytes) -> None:
        self.received.extend(data)
        self.data_received.set()

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True
        self.closed_event.set()

    async def wait_closed(self) -> None:
        return None


class FakeUpstreamReader:
    def __init__(self, writer: FakeUpstreamWriter):
        self.writer = writer
        self.sent = False

    async def read(self, _size: int) -> bytes:
        if self.sent:
            return b""
        await self.writer.data_received.wait()
        self.sent = True
        return b"firewall-tls:" + bytes(self.writer.received)


def test_connector_session_forwards_only_opaque_binary_data(monkeypatch):
    with connector_test_database() as (session, session_factory):
        user, device, other_device = seed_connector_data(session)
        configure_test_client(monkeypatch, session, session_factory, user)

        with TestClient(app) as client:
            handoff = client.post(
                f"/devices/{device.id}/proxy/open",
                data=csrf_form_data(client),
                follow_redirects=False,
            )
            assert handoff.status_code == 200
            assert handoff.headers["cache-control"] == "no-store"
            assert "local connector" in handoff.text.lower()
            assert "/proxy/bootstrap" not in handoff.text
            token = extract_connector_token(handoff)

            stored = session.scalar(
                select(DeviceProxySession).where(
                    DeviceProxySession.phase == "connector"
                )
            )
            assert stored is not None
            assert stored.token_hash != token
            assert stored.device_id == device.id
            assert stored.dashboard_session_id is not None

            fake_writer = FakeUpstreamWriter()
            fake_reader = FakeUpstreamReader(fake_writer)

            async def fake_open_connection(*_args, **_kwargs):
                return fake_reader, fake_writer

            monkeypatch.setattr(
                "app.routers.proxy.asyncio.open_connection", fake_open_connection
            )
            opaque_client_tls = b"\x16\x03\x01encrypted-client-hello-and-login"
            with client.websocket_connect(
                f"/api/v1/connector/devices/{device.id}",
                headers={"Authorization": f"Bearer {token}"},
            ) as websocket:
                websocket.send_bytes(opaque_client_tls)
                assert websocket.receive_bytes() == (
                    b"firewall-tls:" + opaque_client_tls
                )

            assert bytes(fake_writer.received) == opaque_client_tls
            assert fake_writer.closed_event.wait(timeout=1)
            assert fake_writer.closed is True

            try:
                with client.websocket_connect(
                    f"/api/v1/connector/devices/{other_device.id}",
                    headers={"Authorization": f"Bearer {token}"},
                ):
                    raise AssertionError("device-scoped connector token was accepted")
            except WebSocketDisconnect as exc:
                assert exc.code == 4401

            assert client.get(f"/proxy/devices/{device.id}/").status_code == 404
            assert client.post("/proxy/bootstrap").status_code == 404
            assert client.get(f"{settings.proxy_public_url}/dashboard").status_code == 404

        app.dependency_overrides.clear()


def test_connector_open_rejects_cross_company_viewer(monkeypatch):
    with connector_test_database() as (session, session_factory):
        user, _device, other_device = seed_connector_data(session)
        configure_test_client(monkeypatch, session, session_factory, user)

        with TestClient(app) as client:
            response = client.post(
                f"/devices/{other_device.id}/proxy/open",
                data=csrf_form_data(client),
                follow_redirects=False,
            )

        app.dependency_overrides.clear()
        assert response.status_code == 404
        assert session.scalars(select(DeviceProxySession)).all() == []


def test_connector_websocket_requires_bearer_token(monkeypatch):
    with connector_test_database() as (session, session_factory):
        user, device, _other_device = seed_connector_data(session)
        configure_test_client(monkeypatch, session, session_factory, user)

        with TestClient(app) as client:
            try:
                with client.websocket_connect(
                    f"/api/v1/connector/devices/{device.id}"
                ):
                    raise AssertionError("connector accepted a missing bearer token")
            except WebSocketDisconnect as exc:
                assert exc.code == 4401

        app.dependency_overrides.clear()


def test_connector_token_is_revoked_with_issuing_dashboard_session(monkeypatch):
    with connector_test_database() as (session, session_factory):
        user, device, _other_device = seed_connector_data(session)
        dashboard_session = configure_test_client(
            monkeypatch, session, session_factory, user
        )

        with TestClient(app) as client:
            handoff = client.post(
                f"/devices/{device.id}/proxy/open",
                data=csrf_form_data(client),
            )
            assert handoff.status_code == 200
            token = extract_connector_token(handoff)

            dashboard_session.revoked_at = datetime.now(timezone.utc)
            session.commit()

            try:
                with client.websocket_connect(
                    f"/api/v1/connector/devices/{device.id}",
                    headers={"Authorization": f"Bearer {token}"},
                ):
                    raise AssertionError(
                        "connector token survived dashboard-session revocation"
                    )
            except WebSocketDisconnect as exc:
                assert exc.code == 4401

        app.dependency_overrides.clear()


def _enable_fake_public_relay(monkeypatch):
    fake_manager = FakeRelayManager()
    monkeypatch.setattr(proxy_router, "relay_manager", fake_manager)
    monkeypatch.setattr(proxy_router, "client_ip", lambda _request: "127.0.0.1")
    monkeypatch.setattr(settings, "public_l4_relay_enabled", True)
    monkeypatch.setattr(settings, "public_l4_relay_mtls_required", True)
    monkeypatch.setattr(
        settings, "proxy_public_url", "https://relay.example.test"
    )
    return fake_manager


def test_public_relay_handoff_template_renders(monkeypatch):
    with connector_test_database() as (session, session_factory):
        user, device, _other_device = seed_connector_data(session)
        configure_test_client(monkeypatch, session, session_factory, user)
        fake_manager = _enable_fake_public_relay(monkeypatch)

        with TestClient(app) as client:
            response = client.post(
                f"/devices/{device.id}/relay/open",
                data=csrf_form_data(client),
            )

        app.dependency_overrides.clear()
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert "Temporary L4 relay" in response.text
        assert fake_manager.created
        assert fake_manager.closed_allocations == []


def test_public_relay_is_closed_if_handoff_rendering_fails(monkeypatch):
    with connector_test_database() as (session, session_factory):
        user, device, _other_device = seed_connector_data(session)
        configure_test_client(monkeypatch, session, session_factory, user)
        fake_manager = _enable_fake_public_relay(monkeypatch)
        monkeypatch.setattr(
            proxy_router,
            "render_template",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                RuntimeError("template failure")
            ),
        )

        with TestClient(app) as client, pytest.raises(RuntimeError):
            client.post(
                f"/devices/{device.id}/relay/open",
                data=csrf_form_data(client),
            )

        app.dependency_overrides.clear()
        assert fake_manager.closed_allocations == fake_manager.created


def test_active_connector_monitor_detects_dashboard_session_revocation(monkeypatch):
    with connector_test_database() as (session, session_factory):
        user, device, _other_device = seed_connector_data(session)
        dashboard_session = configure_test_client(
            monkeypatch, session, session_factory, user
        )
        token = create_connector_session(session, user, device, dashboard_session)
        session.commit()
        stored = session.scalar(
            select(DeviceProxySession).where(
                DeviceProxySession.token_hash
                == hash_session_token(settings.secret_key, token)
            )
        )
        assert stored is not None

        dashboard_session.revoked_at = datetime.now(timezone.utc)
        session.commit()
        monkeypatch.setattr(
            settings, "connector_authorization_recheck_seconds", 0.01
        )

        async def scenario():
            with pytest.raises(proxy_router.ConnectorAuthorizationEnded):
                await asyncio.wait_for(
                    proxy_router._monitor_connector_authorization(
                        stored.id, device.id
                    ),
                    timeout=0.5,
                )

        asyncio.run(scenario())
        app.dependency_overrides.clear()


def test_device_cleanup_cancels_connector_during_upstream_connect(monkeypatch):
    class PendingWebSocket:
        def __init__(self, token):
            self.headers = {"authorization": f"Bearer {token}"}
            self.accepted = False
            self.close_codes: list[int] = []

        async def accept(self):
            self.accepted = True

        async def close(self, code=1000, reason=None):
            self.close_codes.append(code)

    with connector_test_database() as (session, session_factory):
        user, device, _other_device = seed_connector_data(session)
        dashboard_session = configure_test_client(
            monkeypatch, session, session_factory, user
        )
        token = create_connector_session(session, user, device, dashboard_session)
        session.commit()
        websocket = PendingWebSocket(token)

        async def scenario():
            upstream_started = asyncio.Event()

            async def blocked_open_connection(*_args, **_kwargs):
                upstream_started.set()
                await asyncio.Event().wait()

            monkeypatch.setattr(
                proxy_router.asyncio,
                "open_connection",
                blocked_open_connection,
            )
            tunnel_task = asyncio.create_task(
                proxy_router.connector_device_tunnel(websocket, device.id)  # type: ignore[arg-type]
            )
            await asyncio.wait_for(upstream_started.wait(), timeout=1)
            await proxy_router.close_device_access(device.id)
            assert tunnel_task.done()

        asyncio.run(scenario())
        app.dependency_overrides.clear()
        assert websocket.accepted is False
        assert 4403 in websocket.close_codes


def test_concurrent_relay_replacements_are_serialized(monkeypatch):
    class RecordingRelayManager:
        def __init__(self):
            self.events: list[str] = []

        async def close_device(self, _device_id):
            self.events.append("close")
            await asyncio.sleep(0)

        async def create_relay(self, *_args):
            self.events.append("create-start")
            await asyncio.sleep(0.01)
            self.events.append("create-end")
            return object()

    manager = RecordingRelayManager()
    monkeypatch.setattr(proxy_router, "relay_manager", manager)
    proxy_router._relay_device_locks.clear()
    device_id = uuid4()

    async def scenario():
        await asyncio.gather(
            proxy_router._replace_device_relay(
                device_id, "100.96.0.10", 443, "127.0.0.1", "relay.test"
            ),
            proxy_router._replace_device_relay(
                device_id, "100.96.0.10", 443, "127.0.0.1", "relay.test"
            ),
        )

    asyncio.run(scenario())
    assert manager.events == [
        "close",
        "create-start",
        "create-end",
        "close",
        "create-start",
        "create-end",
    ]
