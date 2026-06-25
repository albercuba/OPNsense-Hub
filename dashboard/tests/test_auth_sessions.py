from datetime import timedelta
from typing import cast
from uuid import uuid4

import pytest
from app.main import current_user, login, logout, session_from_request, settings
from app.models import SessionToken, User
from app.security import hash_secret, hash_session_token, utc_now
from fastapi import HTTPException, Response
from sqlalchemy.orm import Session
from starlette.requests import Request


class FakeDb:
    def __init__(self, user=None, session=None):
        self.user = user
        self.session = session
        self.added = []
        self.committed = False

    def scalar(self, _statement):
        if self.session is not None:
            return self.session
        return self.user

    def get(self, model, key):
        if model is User and self.user and key == self.user.id:
            return self.user
        return None

    def add(self, obj):
        self.added.append(obj)
        if isinstance(obj, SessionToken):
            self.session = obj

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
