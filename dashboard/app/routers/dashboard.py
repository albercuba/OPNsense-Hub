from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..dashboard import accessible_companies_for_user, build_dashboard_context
from ..database import get_db
from ..deps import current_user, has_company_access, require_admin
from ..models import AuditLog, Company, Device, User
from ..web import render_template

router = APIRouter()

AUDIT_ACTION_LABELS = {
    "device.enroll": "Firewall added",
    "device.revoke": "Firewall revoked",
    "device.delete_revoked": "Firewall removed",
    "device.view": "Firewall viewed",
    "device.proxy.open": "Firewall UI opened",
}


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    company_id: str | None = None,
    status: str | None = None,
):
    context = build_dashboard_context(
        db,
        user,
        {
            "company_id": company_id,
            "status": status,
        },
    )
    context.update({"request": request, "user": user, "active_page": "dashboard"})
    return render_template(db, "dashboard.html", context)


@router.get("/companies", response_class=HTMLResponse)
def companies_page(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    companies = accessible_companies_for_user(db, user)
    company_ids = [company.id for company in companies]
    devices = (
        db.scalars(
            select(Device)
            .where(Device.company_id.in_(company_ids))
            .order_by(Device.hostname)
        ).all()
        if company_ids
        else []
    )
    devices_by_company: dict[uuid.UUID, list[Device]] = {
        company.id: [] for company in companies
    }
    for device in devices:
        devices_by_company.setdefault(device.company_id, []).append(device)
    for company in companies:
        company.devices = devices_by_company.get(company.id, [])
    company_admin_access = {
        company.id: has_company_access(db, user, company.id, "admin")
        for company in companies
    }
    return render_template(
        db,
        "companies.html",
        {
            "request": request,
            "user": user,
            "companies": companies,
            "company_admin_access": company_admin_access,
            "active_page": "companies",
        },
    )


@router.get("/audit-logs", response_class=HTMLResponse)
def audit_logs_page(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    require_admin(user)
    audit_actions = set(AUDIT_ACTION_LABELS)
    audit_entries = db.scalars(
        select(AuditLog)
        .where(AuditLog.action.in_(audit_actions))
        .order_by(AuditLog.created_at.desc())
        .limit(500)
    ).all()
    user_ids = {entry.user_id for entry in audit_entries if entry.user_id is not None}
    company_ids = {
        entry.company_id for entry in audit_entries if entry.company_id is not None
    }
    device_ids = {
        entry.device_id for entry in audit_entries if entry.device_id is not None
    }
    users_by_id = {
        row.id: row
        for row in (
            db.scalars(select(User).where(User.id.in_(user_ids))).all()
            if user_ids
            else []
        )
    }
    companies_by_id = {
        row.id: row
        for row in (
            db.scalars(select(Company).where(Company.id.in_(company_ids))).all()
            if company_ids
            else []
        )
    }
    devices_by_id = {
        row.id: row
        for row in (
            db.scalars(select(Device).where(Device.id.in_(device_ids))).all()
            if device_ids
            else []
        )
    }
    audit_rows = [
        {
            "entry": entry,
            "user": users_by_id.get(entry.user_id),
            "company": companies_by_id.get(entry.company_id),
            "device": devices_by_id.get(entry.device_id),
            "action_label": AUDIT_ACTION_LABELS.get(entry.action, entry.action),
        }
        for entry in audit_entries
    ]
    usernames = sorted(
        {
            row["user"].email
            for row in audit_rows
            if row["user"] is not None and row["user"].email
        },
        key=str.lower,
    )
    company_names = sorted(
        {
            row["company"].name
            for row in audit_rows
            if row["company"] is not None and row["company"].name
        },
        key=str.lower,
    )
    device_names = sorted(
        {
            row["device"].hostname
            for row in audit_rows
            if row["device"] is not None and row["device"].hostname
        },
        key=str.lower,
    )
    return render_template(
        db,
        "audit_logs.html",
        {
            "request": request,
            "user": user,
            "audit_rows": audit_rows,
            "audit_usernames": usernames,
            "audit_company_names": company_names,
            "audit_device_names": device_names,
            "active_page": "audit-logs",
        },
    )
