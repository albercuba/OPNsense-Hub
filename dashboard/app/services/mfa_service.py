from __future__ import annotations

import base64
from datetime import timedelta
from io import BytesIO
from uuid import UUID

import jwt
import qrcode
import qrcode.image.svg
from fastapi import HTTPException, Request, Response
from jwt import PyJWTError

from ..models import User
from ..security import totp_provisioning_uri, utc_now
from ..services.common import clean_optional
from ..web import settings

MFA_PENDING_COOKIE_NAME = "opnhub_mfa_pending"
MFA_PENDING_PURPOSE = "login-mfa"


def local_user_supports_hub_mfa(user: User) -> bool:
    return clean_optional(user.auth_provider) is None


def totp_qr_code_data_url(secret: str, account_name: str) -> str:
    uri = totp_provisioning_uri(secret, account_name)
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgImage)
    buffer = BytesIO()
    image.save(buffer)
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


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
