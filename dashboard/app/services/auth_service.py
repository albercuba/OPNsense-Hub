from __future__ import annotations

from datetime import timedelta

from fastapi import HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import SessionToken, User
from ..security import hash_secret, hash_session_token, random_token, utc_now
from ..web import settings
from .common import clean_optional


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        secure=settings.session_secure,
        samesite="lax",
        max_age=settings.session_ttl_hours * 3600,
    )


def create_user_session(db: Session, user: User) -> str:
    token = random_token(48)
    now = utc_now()
    db.add(
        SessionToken(
            user_id=user.id,
            token_hash=hash_session_token(settings.secret_key, token),
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
    if not session or session.revoked_at or session.expires_at <= utc_now():
        raise HTTPException(status_code=401)
    return session


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
