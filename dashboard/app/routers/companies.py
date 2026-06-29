from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..database import get_db
from ..deps import current_user, require_company
from ..models import Company, CompanyUser, Device, EnrollmentCode, User
from ..security import hash_secret, random_otp, utc_now
from ..security.rate_limit import apply_rate_limit
from ..web import format_datetime, render_template, settings

router = APIRouter()


@router.get("/api/v1/companies")
def list_companies(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    companies = db.scalars(
        select(Company)
        .join(CompanyUser)
        .where(CompanyUser.user_id == user.id)
        .order_by(Company.name)
    ).all()
    return [
        {"id": str(c.id), "name": c.name, "created_at": c.created_at.isoformat()}
        for c in companies
    ]


@router.post("/api/v1/companies")
def create_company(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    name: str = Form(...),
):
    company = Company(name=name.strip())
    db.add(company)
    db.flush()
    db.add(CompanyUser(company_id=company.id, user_id=user.id, role="owner"))
    write_audit(db, request, "company.create", user=user, company_id=company.id)
    db.commit()
    return RedirectResponse(f"/companies/{company.id}", status_code=303)


@router.get("/companies/{company_id}", response_class=HTMLResponse)
def company_detail(
    request: Request,
    company_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    company = require_company(db, user, company_id)
    devices = db.scalars(
        select(Device).where(Device.company_id == company.id).order_by(Device.hostname)
    ).all()
    codes = db.scalars(
        select(EnrollmentCode)
        .where(EnrollmentCode.company_id == company.id)
        .order_by(EnrollmentCode.created_at.desc())
        .limit(5)
    ).all()
    return render_template(
        db,
        "company_detail.html",
        {
            "request": request,
            "user": user,
            "company": company,
            "devices": devices,
            "codes": codes,
            "now": utc_now(),
            "active_page": "companies",
        },
    )


@router.get("/api/v1/companies/{company_id}")
def get_company(
    company_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    company = require_company(db, user, company_id)
    return {"id": str(company.id), "name": company.name}


@router.post("/api/v1/companies/{company_id}/enrollment-codes")
def create_enrollment_code(
    request: Request,
    company_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    company = require_company(db, user, company_id, "admin")
    apply_rate_limit(
        request,
        "enrollment-code",
        str(company.id),
        settings.rate_limit_enrollment_code_attempts,
        settings.rate_limit_enrollment_code_window_seconds,
    )
    code = random_otp()
    expires_at = utc_now() + timedelta(minutes=settings.otp_ttl_minutes)
    db.add(
        EnrollmentCode(
            company_id=company.id,
            code_hash=hash_secret(code),
            expires_at=expires_at,
            created_by=user.id,
        )
    )
    write_audit(db, request, "enrollment_code.create", user=user, company_id=company.id)
    db.commit()
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse(
            {
                "code": code,
                "company": company.name,
                "expires_at": expires_at.isoformat(),
                "expires_at_display": format_datetime(expires_at, include_tz=True),
            }
        )
    return render_template(
        db,
        "otp.html",
        {
            "request": request,
            "company": company,
            "code": code,
            "expires_at": expires_at,
        },
    )
