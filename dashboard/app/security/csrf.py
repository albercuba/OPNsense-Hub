from __future__ import annotations

import hmac
from hashlib import sha256

from fastapi import HTTPException, Request

from ..config import get_settings
from ..security import random_token

settings = get_settings()
_CSRF_FORM_FIELD = "csrf_token"
_CSRF_HEADER = "x-csrf-token"


def _csrf_signature(token: str) -> str:
    return hmac.new(
        settings.secret_key.encode("utf-8"), token.encode("utf-8"), sha256
    ).hexdigest()


def sign_csrf_token(token: str) -> str:
    return f"{token}.{_csrf_signature(token)}"


def unsign_csrf_token(signed_token: str | None) -> str | None:
    if not signed_token or "." not in signed_token:
        return None
    token, signature = signed_token.rsplit(".", 1)
    expected = _csrf_signature(token)
    if not hmac.compare_digest(signature, expected):
        return None
    return token


def get_or_create_csrf_token(request: Request) -> str:
    existing = unsign_csrf_token(request.cookies.get(settings.csrf_cookie_name))
    if existing:
        return existing
    state_token = getattr(request.state, "csrf_token", None)
    if state_token:
        return state_token
    token = random_token(32)
    request.state.csrf_token = token
    request.state.csrf_cookie_needs_set = True
    return token


def csrf_cookie_value_for_request(request: Request) -> str:
    return sign_csrf_token(get_or_create_csrf_token(request))


def should_enforce_csrf(request: Request) -> bool:
    if request.method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
        return False
    path = request.url.path
    if path.startswith("/proxy/"):
        return False
    exempt_paths = {
        "/api/v1/enroll",
        "/auth/microsoft",
        "/auth/microsoft/callback",
    }
    if path in exempt_paths:
        return False
    if path.startswith("/api/v1/devices/") and (
        path.endswith("/heartbeat") or path.endswith("/backups")
    ):
        return False
    return True


async def validate_csrf_request(request: Request) -> None:
    expected = unsign_csrf_token(request.cookies.get(settings.csrf_cookie_name))
    if not expected:
        raise HTTPException(status_code=403, detail="missing or invalid CSRF token")
    provided = request.headers.get(_CSRF_HEADER)
    if not provided:
        await request.body()
        form = await request.form()
        provided = form.get(_CSRF_FORM_FIELD)
    if not provided or not hmac.compare_digest(str(provided), expected):
        raise HTTPException(status_code=403, detail="missing or invalid CSRF token")
