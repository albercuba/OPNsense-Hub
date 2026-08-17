from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..models import Device, DeviceProxySession, SessionToken, User
from ..rbac import has_company_access
from ..security import hash_session_token, random_token, utc_now
from ..web import settings

PROXY_GRANT_PHASE = "grant"
PROXY_SESSION_PHASE = "session"
CONNECTOR_SESSION_PHASE = "connector"


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def _delete_expired_proxy_sessions(db: Session, now: datetime) -> None:
    db.execute(
        delete(DeviceProxySession)
        .where(DeviceProxySession.expires_at <= now)
        .execution_options(synchronize_session=False)
    )


def _require_proxy_access(
    db: Session, user_id: uuid.UUID, device_id: uuid.UUID
) -> tuple[User, Device]:
    user = db.get(User, user_id)
    device = db.get(Device, device_id)
    if (
        user is None
        or device is None
        or device.revoked_at is not None
        or (device.status or "").lower() == "revoked"
        or not has_company_access(db, user, device.company_id, "viewer")
    ):
        raise HTTPException(status_code=401, detail="invalid proxy authorization")
    return user, device


def proxy_session_cookie_name(device_id: uuid.UUID) -> str:
    return f"{settings.proxy_session_cookie_prefix}{device_id.hex}"


def create_proxy_grant(db: Session, user: User, device: Device) -> str:
    now = utc_now()
    _delete_expired_proxy_sessions(db, now)
    _require_proxy_access(db, user.id, device.id)

    token = random_token(32)
    db.add(
        DeviceProxySession(
            user_id=user.id,
            device_id=device.id,
            token_hash=hash_session_token(settings.secret_key, token),
            phase=PROXY_GRANT_PHASE,
            created_at=now,
            expires_at=now + timedelta(seconds=settings.proxy_grant_ttl_seconds),
        )
    )
    db.flush()
    return token


def _require_active_dashboard_session(
    db: Session,
    dashboard_session_id: uuid.UUID | None,
    user_id: uuid.UUID,
    now: datetime,
) -> SessionToken:
    dashboard_session = (
        db.get(SessionToken, dashboard_session_id)
        if dashboard_session_id is not None
        else None
    )
    if (
        dashboard_session is None
        or dashboard_session.user_id != user_id
        or dashboard_session.revoked_at is not None
        or _utc_datetime(dashboard_session.expires_at) <= now
    ):
        raise HTTPException(status_code=401, detail="dashboard session is no longer active")
    return dashboard_session


def create_connector_session(
    db: Session,
    user: User,
    device: Device,
    dashboard_session: SessionToken,
) -> str:
    now = utc_now()
    _delete_expired_proxy_sessions(db, now)
    _require_proxy_access(db, user.id, device.id)
    _require_active_dashboard_session(db, dashboard_session.id, user.id, now)

    token = random_token(48)
    db.add(
        DeviceProxySession(
            user_id=user.id,
            device_id=device.id,
            dashboard_session_id=dashboard_session.id,
            token_hash=hash_session_token(settings.secret_key, token),
            phase=CONNECTOR_SESSION_PHASE,
            created_at=now,
            expires_at=now
            + timedelta(minutes=settings.connector_session_ttl_minutes),
        )
    )
    db.flush()
    return token


def exchange_proxy_grant(
    db: Session, grant_token: str
) -> tuple[str, DeviceProxySession]:
    now = utc_now()
    _delete_expired_proxy_sessions(db, now)
    grant_hash = hash_session_token(settings.secret_key, grant_token)
    grant = db.scalar(
        select(DeviceProxySession)
        .where(DeviceProxySession.token_hash == grant_hash)
        .with_for_update()
    )
    if (
        grant is None
        or grant.phase != PROXY_GRANT_PHASE
        or grant.consumed_at is not None
        or _utc_datetime(grant.expires_at) <= now
    ):
        raise HTTPException(status_code=401, detail="invalid or expired proxy grant")

    _require_proxy_access(db, grant.user_id, grant.device_id)
    session_token = random_token(48)
    grant.consumed_at = now
    proxy_session = DeviceProxySession(
        user_id=grant.user_id,
        device_id=grant.device_id,
        token_hash=hash_session_token(settings.secret_key, session_token),
        phase=PROXY_SESSION_PHASE,
        created_at=now,
        expires_at=now + timedelta(minutes=settings.proxy_session_ttl_minutes),
    )
    db.add(proxy_session)
    db.flush()
    return session_token, proxy_session


def _validate_connector_session_record(
    db: Session,
    connector_session: DeviceProxySession | None,
    device_id: uuid.UUID,
    now: datetime,
) -> tuple[DeviceProxySession, User, Device]:
    if (
        connector_session is None
        or connector_session.phase != CONNECTOR_SESSION_PHASE
        or connector_session.device_id != device_id
        or connector_session.consumed_at is not None
        or _utc_datetime(connector_session.expires_at) <= now
    ):
        raise HTTPException(
            status_code=401, detail="invalid or expired connector session"
        )

    _require_active_dashboard_session(
        db,
        connector_session.dashboard_session_id,
        connector_session.user_id,
        now,
    )
    user, device = _require_proxy_access(
        db, connector_session.user_id, connector_session.device_id
    )
    return connector_session, user, device


def validate_connector_session(
    db: Session, token: str, device_id: uuid.UUID
) -> tuple[DeviceProxySession, User, Device]:
    now = utc_now()
    _delete_expired_proxy_sessions(db, now)
    token_hash = hash_session_token(settings.secret_key, token)
    connector_session = db.scalar(
        select(DeviceProxySession).where(
            DeviceProxySession.token_hash == token_hash,
            DeviceProxySession.phase == CONNECTOR_SESSION_PHASE,
            DeviceProxySession.device_id == device_id,
        )
    )
    return _validate_connector_session_record(db, connector_session, device_id, now)


def validate_connector_session_id(
    db: Session, connector_session_id: uuid.UUID, device_id: uuid.UUID
) -> tuple[DeviceProxySession, User, Device]:
    now = utc_now()
    connector_session = db.get(DeviceProxySession, connector_session_id)
    return _validate_connector_session_record(db, connector_session, device_id, now)


def validate_proxy_session(
    db: Session, session_token: str, device_id: uuid.UUID
) -> tuple[DeviceProxySession, User, Device]:
    now = utc_now()
    _delete_expired_proxy_sessions(db, now)
    token_hash = hash_session_token(settings.secret_key, session_token)
    proxy_session = db.scalar(
        select(DeviceProxySession).where(
            DeviceProxySession.token_hash == token_hash,
            DeviceProxySession.phase == PROXY_SESSION_PHASE,
            DeviceProxySession.device_id == device_id,
        )
    )
    if (
        proxy_session is None
        or proxy_session.consumed_at is not None
        or _utc_datetime(proxy_session.expires_at) <= now
    ):
        raise HTTPException(status_code=401, detail="invalid or expired proxy session")

    user, device = _require_proxy_access(
        db, proxy_session.user_id, proxy_session.device_id
    )
    return proxy_session, user, device
