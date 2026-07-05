from __future__ import annotations

from datetime import timedelta, timezone

from fastapi import HTTPException, Request, Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..models import SessionToken, User
from ..security import hash_secret, hash_session_token, random_token, utc_now
from ..security.request_context import client_ip
from ..web import settings
from .common import clean_optional


def _utc_datetime(value):
    if value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        secure=settings.session_secure,
        samesite="lax",
        max_age=settings.session_ttl_hours * 3600,
    )


def create_user_session(db: Session, user: User, request: Request | None = None) -> str:
    token = random_token(48)
    now = utc_now()
    db.add(
        SessionToken(
            user_id=user.id,
            token_hash=hash_session_token(settings.secret_key, token),
            ip_address=client_ip(request) if request is not None else None,
            user_agent=(request.headers.get("user-agent") or "")[:500]
            if request is not None
            else None,
            created_at=now,
            expires_at=now + timedelta(hours=settings.session_ttl_hours),
        )
    )
    return token


def session_from_request(request: Request, db: Session) -> SessionToken:
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise HTTPException(status_code=401)
    token_hash = hash_session_token(settings.secret_key, token)
    session = db.scalar(
        select(SessionToken).where(SessionToken.token_hash == token_hash)
    )
    if not session:
        raise HTTPException(status_code=401)
    revoked_at = _utc_datetime(session.revoked_at) if session.revoked_at else None
    expires_at = _utc_datetime(session.expires_at)
    if revoked_at or expires_at <= utc_now():
        raise HTTPException(status_code=401)
    return session


def revoke_session_token(db: Session, session: SessionToken) -> None:
    session.revoked_at = utc_now()


def revoke_all_user_sessions(db: Session, user_id) -> None:
    db.execute(delete(SessionToken).where(SessionToken.user_id == user_id))


def upsert_external_user(
    db: Session,
    email: str,
    *,
    first_name: str | None = None,
    last_name: str | None = None,
    role: str | None = None,
    auth_provider: str,
) -> User:
    normalized_email = email.strip().lower()
    existing = db.scalar(select(User).where(User.email == normalized_email))
    if existing:
        existing.first_name = clean_optional(first_name) or existing.first_name
        existing.last_name = clean_optional(last_name) or existing.last_name
        existing.auth_provider = auth_provider
        if role:
            existing.role = role
        return existing
    user = User(
        email=normalized_email,
        password_hash=hash_secret(random_token(32)),
        first_name=clean_optional(first_name),
        last_name=clean_optional(last_name),
        role=role or "user",
        auth_provider=auth_provider,
    )
    db.add(user)
    db.flush()
    return user
