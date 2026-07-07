from __future__ import annotations

import hmac
from hashlib import sha256
from urllib.parse import urlparse

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
    exempt_paths = {
        "/api/v1/enroll",
        "/auth/microsoft/callback",
    }
    if path in exempt_paths:
        return False
    if path.startswith("/api/v1/devices/") and (
        path.endswith("/heartbeat") or path.endswith("/backups")
    ):
        return False
    return not path.startswith("/proxy/")


def _origin_matches_request(request: Request) -> bool:
    origin = (request.headers.get("origin") or "").strip()
    if not origin:
        return False
    try:
        origin_url = urlparse(origin)
    except ValueError:
        return False
    if origin_url.scheme not in {"http", "https"}:
        return False
    request_host = (
        (request.headers.get("host") or request.url.netloc or "").strip().lower()
    )
    if not request_host:
        return False
    origin_host = (origin_url.netloc or "").strip().lower()
    if origin_host == request_host:
        return True
    public_host = (urlparse(settings.public_url).netloc or "").strip().lower()
    return bool(public_host and origin_host == public_host)


def validate_proxy_unsafe_request(request: Request) -> None:
    if request.method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    sec_fetch_site = (request.headers.get("sec-fetch-site") or "").strip().lower()
    if sec_fetch_site == "cross-site":
        raise HTTPException(status_code=403, detail="cross-site proxy request blocked")
    origin = (request.headers.get("origin") or "").strip()
    if origin and not _origin_matches_request(request):
        raise HTTPException(
            status_code=403, detail="cross-origin proxy request blocked"
        )
    if not origin and sec_fetch_site not in {"", "same-origin", "same-site", "none"}:
        raise HTTPException(status_code=403, detail="untrusted proxy request blocked")


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
