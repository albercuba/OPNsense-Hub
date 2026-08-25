from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from io import BytesIO
from uuid import UUID

import jwt
import qrcode
import qrcode.image.svg
from fastapi import HTTPException, Request, Response
from jwt import PyJWTError
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import PendingMfaLogin, User
from ..security import hash_session_token, random_token, totp_provisioning_uri, utc_now
from ..services.common import clean_optional
from ..web import settings

MFA_PENDING_COOKIE_NAME = "opnhub_mfa_pending"
MFA_PENDING_PURPOSE = "login-mfa"


@dataclass(frozen=True)
class PendingMfaState:
    user_id: UUID
    nonce: str
    login: PendingMfaLogin

    @property
    def attempts(self) -> int:
        return self.login.failed_attempts

    @property
    def expires_at(self) -> datetime:
        expires_at = self.login.expires_at
        if expires_at.tzinfo is None:
            return expires_at.replace(tzinfo=timezone.utc)
        return expires_at


def local_user_supports_hub_mfa(user: User) -> bool:
    return clean_optional(user.auth_provider) is None


def totp_qr_code_data_url(secret: str, account_name: str) -> str:
    uri = totp_provisioning_uri(secret, account_name)
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgImage)
    buffer = BytesIO()
    image.save(buffer)
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


def _nonce_hash(nonce: str) -> str:
    return hash_session_token(settings.secret_key, nonce)


def _set_pending_mfa_cookie(
    response: Response,
    *,
    user_id: UUID,
    expires_at: datetime,
    nonce: str,
) -> None:
    max_age = max(0, int((expires_at - utc_now()).total_seconds()))
    token = jwt.encode(
        {
            "sub": str(user_id),
            "purpose": MFA_PENDING_PURPOSE,
            "nonce": nonce,
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
        max_age=max_age,
    )


def set_pending_mfa_cookie(db: Session, response: Response, user: User) -> None:
    expires_at = utc_now() + timedelta(minutes=settings.otp_ttl_minutes)
    nonce = random_token(24)
    db.add(
        PendingMfaLogin(
            user_id=user.id,
            nonce_hash=_nonce_hash(nonce),
            failed_attempts=0,
            expires_at=expires_at,
        )
    )
    _set_pending_mfa_cookie(
        response,
        user_id=user.id,
        expires_at=expires_at,
        nonce=nonce,
    )


def clear_pending_mfa_cookie(response: Response) -> None:
    response.delete_cookie(MFA_PENDING_COOKIE_NAME)


def pending_mfa_state_from_request(db: Session, request: Request) -> PendingMfaState:
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
    nonce = payload.get("nonce")
    if not subject or not nonce:
        raise HTTPException(status_code=401, detail="invalid MFA sign-in state")
    try:
        user_id = UUID(str(subject))
    except ValueError as exc:
        raise HTTPException(
            status_code=401, detail="invalid MFA sign-in state"
        ) from exc
    pending_login = db.scalar(
        select(PendingMfaLogin)
        .where(PendingMfaLogin.nonce_hash == _nonce_hash(str(nonce)))
        .with_for_update()
    )
    now = utc_now()
    if (
        not pending_login
        or pending_login.user_id != user_id
        or pending_login.consumed_at is not None
    ):
        raise HTTPException(status_code=401, detail="invalid MFA sign-in state")
    expires_at = pending_login.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        pending_login.consumed_at = now
        db.add(pending_login)
        db.commit()
        raise HTTPException(status_code=401, detail="invalid MFA sign-in state")
    return PendingMfaState(user_id=user_id, nonce=str(nonce), login=pending_login)


def pending_mfa_user_id_from_request(db: Session, request: Request) -> UUID:
    return pending_mfa_state_from_request(db, request).user_id


def record_pending_mfa_failure(db: Session, state: PendingMfaState) -> int:
    state.login.failed_attempts += 1
    db.add(state.login)
    db.flush()
    return state.login.failed_attempts


def consume_pending_mfa_login(db: Session, state: PendingMfaState) -> None:
    state.login.consumed_at = utc_now()
    db.add(state.login)
