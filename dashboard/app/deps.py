from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .database import get_db
from .models import Company, Device, User
from .rbac import has_company_role
from .security import verify_secret
from .services.auth_service import session_from_request


def current_user(request: Request, db: Annotated[Session, Depends(get_db)]) -> User:
    session = session_from_request(request, db)
    user = db.get(User, session.user_id)
    if not user:
        raise HTTPException(status_code=401)
    return user


def ui_user(request: Request, db: Session) -> User | None:
    try:
        return current_user(request, db)
    except HTTPException:
        return None


def has_company_access(
    db: Session, user: User, company_id: uuid.UUID, minimum: str = "viewer"
) -> bool:
    return user.role == "administrator" or has_company_role(
        db, user, company_id, minimum
    )


def require_company(
    db: Session, user: User, company_id: uuid.UUID, minimum: str = "viewer"
) -> Company:
    company = db.get(Company, company_id)
    if not company or not has_company_access(db, user, company_id, minimum):
        raise HTTPException(status_code=404, detail="company not found")
    return company


def require_admin(user: User) -> None:
    if user.role != "administrator":
        raise HTTPException(status_code=403, detail="administrator access required")


def device_from_token(
    db: Session, device_id: uuid.UUID, authorization: str | None
) -> Device:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401)
    token = authorization.removeprefix("Bearer ").strip()
    device = db.get(Device, device_id)
    if (
        not device
        or device.revoked_at
        or not verify_secret(token, device.device_token_hash)
    ):
        raise HTTPException(status_code=401)
    return device
