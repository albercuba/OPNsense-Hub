from __future__ import annotations

import csv
import io
import uuid
from typing import Annotated, cast
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..dashboard import (
    accessible_companies_for_user,
    build_dashboard_context,
    dashboard_backup_status,
    dashboard_firmware_status,
    dashboard_revision_token,
)
from ..database import get_db
from ..deps import current_user, has_company_access, require_admin
from ..models import AuditLog, Company, Device, User, UserDashboardFilter
from ..security import utc_now
from ..services.firmware_scheduler import device_license_label
from ..web import render_template

router = APIRouter()

AUDIT_ACTION_LABELS = {
    "device.enroll": "Firewall added",
    "device.revoke": "Firewall revoked",
    "device.delete_revoked": "Firewall removed",
    "device.view": "Firewall viewed",
    "device.proxy.open": "Firewall UI opened",
}


def _saved_dashboard_filters(db: Session, user: User) -> list[UserDashboardFilter]:
    return list(
        db.scalars(
            select(UserDashboardFilter)
            .where(UserDashboardFilter.user_id == user.id)
            .order_by(UserDashboardFilter.created_at.desc(), UserDashboardFilter.name)
        ).all()
    )


def _query_url(path: str, **params: str | None) -> str:
    filtered = {key: value for key, value in params.items() if value}
    if not filtered:
        return path
    return f"{path}?{urlencode(filtered)}"


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    company_id: str | None = None,
    status: str | None = None,
    result: str | None = None,
):
    context = build_dashboard_context(
        db,
        user,
        {
            "company_id": company_id,
            "status": status,
        },
    )
    context.update(
        {
            "request": request,
            "user": user,
            "active_page": "dashboard",
            "dashboard_revision": dashboard_revision_token(
                db,
                user,
                {
                    "company_id": company_id,
                    "status": status,
                },
            ),
            "saved_filters": _saved_dashboard_filters(db, user),
            "toast": (
                {"message": "Dashboard filter saved.", "level": "success"}
                if result == "filter-saved"
                else {"message": "Dashboard filter deleted.", "level": "success"}
                if result == "filter-deleted"
                else {"message": "Dashboard export ready.", "level": "info"}
                if result == "devices-exported"
                else None
            ),
        }
    )
    return render_template(db, "dashboard.html", context)


@router.get("/dashboard/updates")
def dashboard_updates(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    company_id: str | None = None,
    status: str | None = None,
):
    return JSONResponse(
        {
            "revision": dashboard_revision_token(
                db,
                user,
                {
                    "company_id": company_id,
                    "status": status,
                },
            )
        }
    )


@router.post("/dashboard/filters")
def save_dashboard_filter(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    name: str = Form(...),
    company_id: str = Form(""),
    status: str = Form(""),
):
    filter_name = name.strip()
    if not filter_name:
        raise HTTPException(status_code=400, detail="filter name is required")
    company_uuid = uuid.UUID(company_id) if company_id.strip() else None
    if company_uuid and not has_company_access(db, user, company_uuid):
        raise HTTPException(status_code=404)
    saved_filter = UserDashboardFilter(
        user_id=user.id,
        name=filter_name[:120],
        company_id=company_uuid,
        status=status.strip().lower()[:30] or None,
    )
    db.add(saved_filter)
    write_audit(
        db, request, "dashboard.filter.save", user=user, company_id=company_uuid
    )
    db.commit()
    return RedirectResponse(
        _query_url(
            "/dashboard",
            company_id=company_id.strip() or None,
            status=status.strip().lower() or None,
            result="filter-saved",
        ),
        status_code=303,
    )


@router.post("/dashboard/filters/{filter_id}/delete")
def delete_dashboard_filter(
    request: Request,
    filter_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    saved_filter = db.get(UserDashboardFilter, filter_id)
    if not saved_filter or saved_filter.user_id != user.id:
        raise HTTPException(status_code=404)
    company_id = str(saved_filter.company_id) if saved_filter.company_id else None
    status = saved_filter.status
    write_audit(
        db,
        request,
        "dashboard.filter.delete",
        user=user,
        company_id=saved_filter.company_id,
    )
    db.delete(saved_filter)
    db.commit()
    return RedirectResponse(
        _query_url(
            "/dashboard",
            company_id=company_id,
            status=status,
            result="filter-deleted",
        ),
        status_code=303,
    )


@router.get("/dashboard/export/devices.csv")
def export_dashboard_devices_csv(
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
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "company",
            "hostname",
            "status",
            "backup_status",
            "firmware_status",
            "license",
            "license_expires_at",
            "last_seen_at",
            "maintenance_until",
        ]
    )
    now = utc_now()
    for device in cast(list[Device], context["filtered_devices"]):
        backup_status = dashboard_backup_status(device, now)["label"]
        firmware_status = dashboard_firmware_status(device)["label"]
        writer.writerow(
            [
                device.company.name if device.company else "",
                device.hostname,
                device.status,
                backup_status,
                firmware_status,
                device_license_label(device),
                device.license_expires_at.isoformat()
                if device.license_expires_at
                else "",
                device.last_seen_at.isoformat() if device.last_seen_at else "",
                device.maintenance_until.isoformat()
                if device.maintenance_until
                else "",
            ]
        )
    write_audit(
        db,
        request,
        "dashboard.export.devices_csv",
        user=user,
        company_id=uuid.UUID(company_id) if company_id else None,
    )
    db.commit()
    content = output.getvalue()
    headers = {"Content-Disposition": 'attachment; filename="dashboard-devices.csv"'}
    return Response(content=content, media_type="text/csv", headers=headers)


@router.get("/companies", response_class=HTMLResponse)
def companies_page(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    result: str | None = None,
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
            "toast": (
                {
                    "message": "Bulk backup requested for selected firewalls.",
                    "level": "success",
                }
                if result == "bulk-backup-requested"
                else {
                    "message": "Bulk firmware check requested for selected firewalls.",
                    "level": "success",
                }
                if result == "bulk-firmware-requested"
                else None
            ),
        },
    )


@router.post("/companies/devices/bulk-action")
def bulk_device_action(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    action: str = Form(...),
    device_ids: list[str] = Form(...),
):
    valid_actions = {"request-backup", "request-firmware-check"}
    if action not in valid_actions:
        raise HTTPException(status_code=400, detail="unsupported bulk action")
    unique_ids: list[uuid.UUID] = []
    seen_ids: set[uuid.UUID] = set()
    for raw_device_id in device_ids:
        try:
            device_id = uuid.UUID(raw_device_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid device id") from exc
        if device_id in seen_ids:
            continue
        unique_ids.append(device_id)
        seen_ids.add(device_id)
    if not unique_ids:
        raise HTTPException(status_code=400, detail="select at least one firewall")
    devices = db.scalars(
        select(Device).where(Device.id.in_(unique_ids)).order_by(Device.hostname)
    ).all()
    if len(devices) != len(unique_ids):
        raise HTTPException(status_code=404)
    now = utc_now()
    action_name = (
        "device.backup.request_now"
        if action == "request-backup"
        else "device.firmware.check.request_now"
    )
    for device in devices:
        if not has_company_access(db, user, device.company_id, "admin"):
            raise HTTPException(status_code=404)
        if device.revoked_at is not None:
            continue
        if action == "request-backup":
            device.backup_last_requested_at = now
        else:
            device.firmware_check_requested_at = now
            device.firmware_check_request_reason = "manual"
        write_audit(
            db,
            request,
            action_name,
            user=user,
            company_id=device.company_id,
            device_id=device.id,
        )
    db.commit()
    return RedirectResponse(
        _query_url(
            "/companies",
            result=(
                "bulk-backup-requested"
                if action == "request-backup"
                else "bulk-firmware-requested"
            ),
        ),
        status_code=303,
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
