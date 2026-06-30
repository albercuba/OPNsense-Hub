from __future__ import annotations

from datetime import timedelta
from uuid import UUID

import jwt
from fastapi import HTTPException, Request, Response
from jwt import PyJWTError

from ..models import User
from ..security import utc_now
from ..web import settings

MFA_PENDING_COOKIE_NAME = "opnhub_mfa_pending"
MFA_PENDING_PURPOSE = "login-mfa"


def set_pending_mfa_cookie(response: Response, user: User) -> None:
    expires_at = utc_now() + timedelta(minutes=settings.otp_ttl_minutes)
    token = jwt.encode(
        {
            "sub": str(user.id),
            "purpose": MFA_PENDING_PURPOSE,
            "exp": int(expires_at.timestamp()),
        },
        settings.secret_key,
        algorithm="HS256",
    )
    response.set_cookie(
        MFA_PENDING_COOKIE_NAME,
        token,
        httponly=True,
        secure=settings.session_secure,
        samesite="lax",
        max_age=settings.otp_ttl_minutes * 60,
    )


def clear_pending_mfa_cookie(response: Response) -> None:
    response.delete_cookie(MFA_PENDING_COOKIE_NAME)


def pending_mfa_user_id_from_request(request: Request) -> UUID:
    token = request.cookies.get(MFA_PENDING_COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="missing MFA sign-in state")
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except PyJWTError as exc:
        raise HTTPException(
            status_code=401, detail="invalid MFA sign-in state"
        ) from exc
    if payload.get("purpose") != MFA_PENDING_PURPOSE:
        raise HTTPException(status_code=401, detail="invalid MFA sign-in state")
    subject = payload.get("sub")
    if not subject:
        raise HTTPException(status_code=401, detail="invalid MFA sign-in state")
    try:
        return UUID(str(subject))
    except ValueError as exc:
        raise HTTPException(
            status_code=401, detail="invalid MFA sign-in state"
        ) from exc
