from __future__ import annotations

import hmac
from hashlib import sha256
from urllib.parse import urlparse

from fastapi import HTTPException, Request

from ..config import get_settings
from ..security import random_token
from .request_context import is_proxy_path

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
    return not is_proxy_path(path)


def _configured_origin(url: str) -> str:
    try:
        parsed = urlparse(url)
        _ = parsed.port
    except ValueError:
        return ""
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return ""
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _request_origin(request: Request) -> str:
    host = (request.headers.get("host") or request.url.netloc or "").strip()
    if not host:
        return ""
    return _configured_origin(f"{request.url.scheme}://{host}")


def _normalized_origin(origin: str) -> str:
    try:
        parsed = urlparse(origin)
    except ValueError:
        return ""
    if parsed.path or parsed.params or parsed.query or parsed.fragment:
        return ""
    return _configured_origin(origin)


def _origin_matches_proxy_request(request: Request, origin: str) -> bool:
    normalized = _normalized_origin(origin)
    if not normalized:
        return False
    expected_origins = {
        _configured_origin(settings.proxy_public_url),
        _request_origin(request),
    }
    expected_origins.discard("")
    return normalized in expected_origins


def validate_proxy_unsafe_request(request: Request) -> None:
    if request.method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    path = request.url.path
    if not is_proxy_path(path):
        return
    origin = (request.headers.get("origin") or "").strip()
    if path == "/proxy/bootstrap":
        if not origin or _normalized_origin(origin) != _configured_origin(
            settings.public_url
        ):
            raise HTTPException(
                status_code=403, detail="proxy bootstrap origin is not allowed"
            )
        return
    sec_fetch_site = (request.headers.get("sec-fetch-site") or "").strip().lower()
    if sec_fetch_site == "cross-site":
        raise HTTPException(status_code=403, detail="cross-site proxy request blocked")
    if not origin or not _origin_matches_proxy_request(request, origin):
        raise HTTPException(
            status_code=403, detail="cross-origin proxy request blocked"
        )


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
