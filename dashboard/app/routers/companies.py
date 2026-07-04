from __future__ import annotations

import uuid
from datetime import timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..dashboard import (
    accessible_companies_for_user,
    dashboard_backup_status,
    dashboard_firmware_status,
    dashboard_license_status,
    normalized_status,
)
from ..database import get_db
from ..deps import current_user, has_company_access, require_company
from ..models import (
    AuditLog,
    Company,
    CompanyUser,
    Device,
    DeviceEvent,
    EnrollmentCode,
    User,
)
from ..security import hash_secret, random_otp, utc_now
from ..security.rate_limit import apply_rate_limit
from ..web import format_datetime, render_template, settings

router = APIRouter()

COMPANY_TIMELINE_LIMIT = 12
COMPANY_AUDIT_ACTION_LABELS = {
    "device.enroll": "Firewall added",
    "device.revoke": "Firewall revoked",
    "device.runbook.update": "Runbook updated",
    "device.health_acknowledge": "Health issue acknowledged",
    "device.health_acknowledge.clear": "Health acknowledgement cleared",
    "device.backup.request_now": "Backup requested",
}


@router.get("/api/v1/companies")
def list_companies(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    companies = accessible_companies_for_user(db, user)
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
    now = utc_now()
    devices = db.scalars(
        select(Device).where(Device.company_id == company.id).order_by(Device.hostname)
    ).all()
    codes = db.scalars(
        select(EnrollmentCode)
        .where(EnrollmentCode.company_id == company.id)
        .order_by(EnrollmentCode.created_at.desc())
        .limit(5)
    ).all()
    device_ids = [device.id for device in devices]
    recent_events = (
        db.scalars(
            select(DeviceEvent)
            .where(DeviceEvent.device_id.in_(device_ids))
            .order_by(DeviceEvent.created_at.desc())
            .limit(COMPANY_TIMELINE_LIMIT)
        ).all()
        if device_ids
        else []
    )
    recent_audit = (
        db.scalars(
            select(AuditLog)
            .where(
                AuditLog.company_id == company.id,
                AuditLog.device_id.is_not(None),
                AuditLog.action != "device.view",
            )
            .order_by(AuditLog.created_at.desc())
            .limit(COMPANY_TIMELINE_LIMIT)
        ).all()
        if device_ids
        else []
    )
    users_by_id = {
        row.id: row
        for row in (
            db.scalars(
                select(User).where(
                    User.id.in_(
                        {entry.user_id for entry in recent_audit if entry.user_id}
                    )
                )
            ).all()
            if recent_audit
            else []
        )
    }
    devices_by_id = {device.id: device for device in devices}
    timeline = [
        {
            "title": event.event_type.replace("_", " ").title(),
            "detail": event.message or "Firewall activity recorded.",
            "timestamp": event.created_at,
            "actor": devices_by_id.get(event.device_id).hostname
            if event.device_id in devices_by_id
            else "Firewall",
            "source": "event",
        }
        for event in recent_events
    ]
    timeline.extend(
        {
            "title": COMPANY_AUDIT_ACTION_LABELS.get(
                entry.action,
                entry.action.replace(".", " ").replace("_", " ").title(),
            ),
            "detail": "Administrative activity recorded in the audit log.",
            "timestamp": entry.created_at,
            "actor": users_by_id.get(entry.user_id).email
            if entry.user_id in users_by_id
            else "Hub user",
            "source": "audit",
        }
        for entry in recent_audit
    )
    timeline.sort(key=lambda item: item["timestamp"], reverse=True)
    risky_devices = []
    for device in devices:
        status = normalized_status(device)
        backup_status = dashboard_backup_status(device, now)
        firmware_status = dashboard_firmware_status(device)
        license_status = dashboard_license_status(device, now)
        risk_count = sum(
            [
                1 if status in {"warning", "critical"} else 0,
                1 if backup_status["label"] in {"Overdue", "Never backed up"} else 0,
                1 if firmware_status["attention"] else 0,
                1
                if license_status["expired"] or license_status["expiring_soon"]
                else 0,
            ]
        )
        if risk_count <= 0:
            continue
        risky_devices.append(
            {
                "device": device,
                "status": status,
                "backup_status": backup_status,
                "firmware_status": firmware_status,
                "license_status": license_status,
                "risk_count": risk_count,
            }
        )
    risky_devices.sort(
        key=lambda row: (-row["risk_count"], row["device"].hostname.lower())
    )
    last_contact = max(
        (device.last_seen_at for device in devices if device.last_seen_at is not None),
        default=None,
    )
    active_devices = [
        device for device in devices if normalized_status(device) != "revoked"
    ]
    summary = {
        "firewalls": len(devices),
        "online": sum(1 for device in devices if normalized_status(device) == "online"),
        "warning": sum(
            1 for device in devices if normalized_status(device) == "warning"
        ),
        "critical": sum(
            1 for device in devices if normalized_status(device) == "critical"
        ),
        "revoked": sum(
            1 for device in devices if normalized_status(device) == "revoked"
        ),
        "backups_overdue": sum(
            1
            for device in active_devices
            if dashboard_backup_status(device, now)["label"] == "Overdue"
        ),
        "firmware_attention": sum(
            1
            for device in active_devices
            if dashboard_firmware_status(device)["attention"]
        ),
        "licenses_expiring": sum(
            1
            for device in active_devices
            if dashboard_license_status(device, now)["expired"]
            or dashboard_license_status(device, now)["expiring_soon"]
        ),
        "last_contact": last_contact,
    }
    return render_template(
        db,
        "company_detail.html",
        {
            "request": request,
            "user": user,
            "company": company,
            "devices": devices,
            "codes": codes,
            "now": now,
            "summary": summary,
            "risky_devices": risky_devices,
            "timeline": timeline[:COMPANY_TIMELINE_LIMIT],
            "can_manage_company": has_company_access(db, user, company.id, "admin"),
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
