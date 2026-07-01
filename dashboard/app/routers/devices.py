from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..backups import (
    DEVICE_BACKUP_INTERVAL_VALUE_MAX,
    DEVICE_BACKUP_RETENTION_MAX,
    backup_interval_delta,
    backup_request_pending,
    mark_device_backup_requested,
)
from ..database import get_db
from ..deps import current_user, device_from_token, has_company_access
from ..integration import email_settings_configured
from ..models import Company, Device, DeviceBackup, DeviceEvent, User
from ..security import hash_secret, random_token, utc_now
from ..security.rate_limit import apply_rate_limit
from ..services.common import (
    clean_optional,
    get_or_create_integration_settings,
    is_valid_email_address,
)
from ..services.firmware_scheduler import (
    DEVICE_BACKUP_CONTENT_MAX_LENGTH,
    apply_device_firmware_payload,
    apply_device_license_payload,
    device_license_label,
    normalize_backup_filename,
    parse_backup_interval_unit,
    parse_bounded_int,
    parse_uploaded_backup_created_at,
)
from ..web import render_template, settings

router = APIRouter()


@router.post("/api/v1/devices/{device_id}/heartbeat")
def heartbeat(
    device_id: uuid.UUID,
    payload: dict[str, object],
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
):
    apply_rate_limit(
        request,
        "device-heartbeat",
        str(device_id),
        settings.rate_limit_device_heartbeat_attempts,
        settings.rate_limit_device_heartbeat_window_seconds,
    )
    device = device_from_token(db, device_id, authorization)
    device.status = str(payload.get("status", "online"))[:30]
    device.health_missed_checks = 0
    device.health_success_checks += 1
    device.hostname = str(payload.get("hostname", device.hostname))[:255]
    opnsense_version = payload.get("opnsense_version")
    if opnsense_version is not None:
        device.opnsense_version = str(opnsense_version)[:80]
    plugin_version = payload.get("plugin_version")
    if plugin_version is not None:
        device.plugin_version = str(plugin_version)[:80]
    apply_device_license_payload(device, payload)
    firmware_applied = apply_device_firmware_payload(device, payload)
    device.last_seen_at = utc_now()
    if firmware_applied or device.status != "online":
        event_message = device.status
        if firmware_applied:
            event_message = (
                f"{device.status}; firmware={device.firmware_status}; updates={device.firmware_update_count}"
            )[:1000]
        db.add(
            DeviceEvent(
                device_id=device.id, event_type="heartbeat", message=event_message
            )
        )
    pending_firmware_check = device.firmware_check_requested_at is not None
    pending_firmware_check_at = device.firmware_check_requested_at
    pending_firmware_check_reason = device.firmware_check_request_reason
    pending_backup = mark_device_backup_requested(device)
    pending_backup_at = device.backup_last_requested_at
    db.commit()
    return {
        "ok": True,
        "firmware_check_requested": pending_firmware_check,
        "firmware_check_requested_at": pending_firmware_check_at.isoformat()
        if pending_firmware_check_at
        else None,
        "firmware_check_request_reason": pending_firmware_check_reason,
        "backup_requested": pending_backup,
        "backup_requested_at": pending_backup_at.isoformat()
        if pending_backup_at
        else None,
        "backup_retention_count": device.backup_retention_count
        if (device.backup_enabled or pending_backup)
        else None,
        "backup_interval_hours": device.backup_interval_hours
        if (device.backup_enabled or pending_backup)
        else None,
    }


@router.post("/api/v1/devices/{device_id}/backups")
def upload_device_backup(
    device_id: uuid.UUID,
    payload: dict[str, object],
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
):
    apply_rate_limit(
        request,
        "device-backup",
        str(device_id),
        settings.rate_limit_device_backup_attempts,
        settings.rate_limit_device_backup_window_seconds,
    )
    device = device_from_token(db, device_id, authorization)
    if not device.backup_enabled and not backup_request_pending(device):
        raise HTTPException(
            status_code=400, detail="backups are disabled for this firewall"
        )
    content = str(payload.get("content", ""))
    if not content.strip():
        raise HTTPException(status_code=400, detail="backup content is required")
    if len(content) > DEVICE_BACKUP_CONTENT_MAX_LENGTH:
        raise HTTPException(status_code=400, detail="backup content is too large")
    created_at = parse_uploaded_backup_created_at(payload.get("created_at"))
    filename = clean_optional(
        str(payload.get("filename", ""))
    ) or normalize_backup_filename(device, created_at)
    backup = DeviceBackup(
        device_id=device.id,
        filename=filename[:255],
        content=content,
        created_at=created_at,
    )
    device.backup_last_uploaded_at = utc_now()
    device.backup_last_requested_at = None
    db.add(backup)
    db.flush()
    backups = db.scalars(
        select(DeviceBackup)
        .where(DeviceBackup.device_id == device.id)
        .order_by(DeviceBackup.created_at.desc(), DeviceBackup.id.desc())
    ).all()
    for stale_backup in backups[device.backup_retention_count :]:
        db.delete(stale_backup)
    db.add(
        DeviceEvent(
            device_id=device.id,
            event_type="backup_uploaded",
            message=f"Configuration backup uploaded: {backup.filename}"[:1000],
        )
    )
    db.commit()
    return {
        "ok": True,
        "backup_id": str(backup.id),
        "filename": backup.filename,
        "created_at": backup.created_at.isoformat(),
        "retained_count": min(len(backups), device.backup_retention_count),
    }


@router.get("/api/v1/companies/{company_id}/devices")
def list_devices(
    company_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    from ..deps import require_company

    company = require_company(db, user, company_id)
    devices = db.scalars(
        select(Device).where(Device.company_id == company.id).order_by(Device.hostname)
    ).all()
    return [
        {
            "id": str(d.id),
            "hostname": d.hostname,
            "status": d.status,
            "tunnel_ip": str(d.wg_tunnel_ip),
            "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
            "license": device_license_label(d),
            "license_expires_at": d.license_expires_at.isoformat()
            if d.license_expires_at
            else None,
            "firmware_status": d.firmware_status,
            "firmware_update_available": d.firmware_update_available,
            "firmware_available_version": d.firmware_available_version,
            "firmware_checked_at": d.firmware_checked_at.isoformat()
            if d.firmware_checked_at
            else None,
        }
        for d in devices
    ]


@router.get("/devices/{device_id}", response_class=HTMLResponse)
def device_page(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id):
        raise HTTPException(status_code=404)
    write_audit(
        db,
        request,
        "device.view",
        user=user,
        company_id=device.company_id,
        device_id=device.id,
    )
    db.commit()
    can_edit_notification_settings = has_company_access(
        db, user, device.company_id, "admin"
    )
    integration_settings = get_or_create_integration_settings(db)
    company = db.get(Company, device.company_id)
    backups = db.scalars(
        select(DeviceBackup)
        .where(DeviceBackup.device_id == device.id)
        .order_by(DeviceBackup.created_at.desc())
    ).all()
    events = db.scalars(
        select(DeviceEvent)
        .where(DeviceEvent.device_id == device.id)
        .order_by(DeviceEvent.created_at.desc())
        .limit(10)
    ).all()
    return render_template(
        db,
        "device.html",
        {
            "request": request,
            "user": user,
            "company": company,
            "device": device,
            "backups": backups,
            "can_edit_notification_settings": can_edit_notification_settings,
            "email_settings_configured": email_settings_configured(
                integration_settings
            ),
            "events": events,
            "active_page": "companies",
            "status": request.query_params.get("status"),
        },
    )


@router.get("/api/v1/devices/{device_id}")
def get_device(
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id):
        raise HTTPException(status_code=404)
    return {
        "id": str(device.id),
        "hostname": device.hostname,
        "opnsense_version": device.opnsense_version,
        "plugin_version": device.plugin_version,
        "license": device_license_label(device),
        "license_expires_at": device.license_expires_at.isoformat()
        if device.license_expires_at
        else None,
        "tunnel_ip": str(device.wg_tunnel_ip),
        "status": device.status,
        "firmware_status": device.firmware_status,
        "firmware_update_available": device.firmware_update_available,
        "firmware_update_type": device.firmware_update_type,
        "firmware_current_version": device.firmware_current_version,
        "firmware_available_version": device.firmware_available_version,
        "firmware_update_count": device.firmware_update_count,
        "firmware_reboot_required": device.firmware_reboot_required,
        "firmware_status_message": device.firmware_status_message,
        "firmware_checked_at": device.firmware_checked_at.isoformat()
        if device.firmware_checked_at
        else None,
        "backup_enabled": device.backup_enabled,
        "backup_retention_count": device.backup_retention_count,
        "backup_interval_value": device.backup_interval_value,
        "backup_interval_unit": device.backup_interval_unit,
        "backup_interval_hours": device.backup_interval_hours,
        "backup_last_requested_at": device.backup_last_requested_at.isoformat()
        if device.backup_last_requested_at
        else None,
        "backup_last_uploaded_at": device.backup_last_uploaded_at.isoformat()
        if device.backup_last_uploaded_at
        else None,
        "email_notifications_enabled": device.email_notifications_enabled,
        "email_notification_recipient": device.email_notification_recipient,
        "email_notify_on_warning": device.email_notify_on_warning,
        "email_notify_on_critical": device.email_notify_on_critical,
        "email_last_notified_status": device.email_last_notified_status,
        "email_last_notified_at": device.email_last_notified_at.isoformat()
        if device.email_last_notified_at
        else None,
        "revoked_at": device.revoked_at.isoformat() if device.revoked_at else None,
    }


@router.post("/devices/{device_id}/backup-settings")
def update_device_backup_settings(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    backup_enabled: str | None = Form(None),
    backup_retention_count: str = Form("3"),
    backup_interval_value: str = Form("24"),
    backup_interval_unit: str = Form("hours"),
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id, "admin"):
        raise HTTPException(status_code=404)
    device.backup_enabled = backup_enabled == "on"
    device.backup_retention_count = parse_bounded_int(
        backup_retention_count,
        field_name="backup retention count",
        minimum=1,
        maximum=DEVICE_BACKUP_RETENTION_MAX,
    )
    device.backup_interval_value = parse_bounded_int(
        backup_interval_value,
        field_name="backup interval value",
        minimum=1,
        maximum=DEVICE_BACKUP_INTERVAL_VALUE_MAX,
    )
    device.backup_interval_unit = parse_backup_interval_unit(backup_interval_unit)
    device.backup_interval_hours = max(
        1, int(backup_interval_delta(device).total_seconds() // 3600)
    )
    if device.backup_enabled:
        mark_device_backup_requested(device)
    else:
        device.backup_last_requested_at = None
    write_audit(
        db,
        request,
        "device.backup_settings.update",
        user=user,
        company_id=device.company_id,
        device_id=device.id,
    )
    db.commit()
    return RedirectResponse(
        f"/devices/{device.id}?status=backup-settings-saved", status_code=303
    )


@router.post("/devices/{device_id}/email-notification-settings")
def update_device_email_notification_settings(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    email_notifications_enabled: str | None = Form(None),
    email_notification_recipient: str = Form(""),
    email_notify_on_warning: str | None = Form(None),
    email_notify_on_critical: str | None = Form(None),
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id, "admin"):
        raise HTTPException(status_code=404)
    integration_settings = get_or_create_integration_settings(db)
    enabled = email_notifications_enabled == "on"
    recipient = clean_optional(email_notification_recipient)
    if enabled and not email_settings_configured(integration_settings):
        raise HTTPException(status_code=400, detail="email settings are not configured")
    if enabled and not is_valid_email_address(recipient):
        raise HTTPException(
            status_code=400, detail="a valid recipient email address is required"
        )
    device.email_notifications_enabled = enabled
    device.email_notification_recipient = recipient if enabled else None
    device.email_notify_on_warning = email_notify_on_warning == "on"
    device.email_notify_on_critical = email_notify_on_critical == "on"
    if not enabled:
        device.email_last_notified_status = None
        device.email_last_notified_at = None
    write_audit(
        db,
        request,
        "device.email_notification_settings.update",
        user=user,
        company_id=device.company_id,
        device_id=device.id,
    )
    db.commit()
    return RedirectResponse(
        f"/devices/{device.id}?status=email-notification-settings-saved",
        status_code=303,
    )


@router.post("/devices/{device_id}/backup-now")
def request_device_backup_now(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id, "admin"):
        raise HTTPException(status_code=404)
    device.backup_last_requested_at = utc_now()
    write_audit(
        db,
        request,
        "device.backup.request_now",
        user=user,
        company_id=device.company_id,
        device_id=device.id,
    )
    db.commit()
    return RedirectResponse(
        f"/devices/{device.id}?status=backup-requested", status_code=303
    )


@router.get("/devices/{device_id}/backups/{backup_id}/download")
def download_device_backup(
    device_id: uuid.UUID,
    backup_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id):
        raise HTTPException(status_code=404)
    backup = db.get(DeviceBackup, backup_id)
    if not backup or backup.device_id != device.id:
        raise HTTPException(status_code=404)
    headers = {"Content-Disposition": f'attachment; filename="{backup.filename}"'}
    return Response(
        content=backup.content.encode("utf-8"),
        media_type="application/xml",
        headers=headers,
    )


@router.post("/devices/{device_id}/backups/{backup_id}/delete")
def delete_device_backup(
    request: Request,
    device_id: uuid.UUID,
    backup_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id, "admin"):
        raise HTTPException(status_code=404)
    backup = db.get(DeviceBackup, backup_id)
    if not backup or backup.device_id != device.id:
        raise HTTPException(status_code=404)
    db.delete(backup)
    write_audit(
        db,
        request,
        "device.backup.delete",
        user=user,
        company_id=device.company_id,
        device_id=device.id,
    )
    db.commit()
    return RedirectResponse(
        f"/devices/{device.id}?status=backup-deleted", status_code=303
    )


@router.post("/api/v1/devices/{device_id}/revoke")
def revoke_device(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    from ..wireguard import remove_peer

    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id, "admin"):
        raise HTTPException(status_code=404)
    if not device.revoked_at:
        remove_peer(device.wg_public_key)
        device.revoked_at = utc_now()
        device.status = "revoked"
        device.device_token_hash = hash_secret(random_token(48))
        db.add(
            DeviceEvent(
                device_id=device.id, event_type="revoked", message="Device revoked"
            )
        )
        write_audit(
            db,
            request,
            "device.revoke",
            user=user,
            company_id=device.company_id,
            device_id=device.id,
        )
        db.commit()
    return RedirectResponse(f"/companies/{device.company_id}", status_code=303)


@router.post("/api/v1/devices/{device_id}/delete")
def delete_revoked_device(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    redirect_to: str = Form("/companies"),
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id, "admin"):
        raise HTTPException(status_code=404)
    if not device.revoked_at:
        raise HTTPException(
            status_code=400, detail="only revoked firewalls can be removed"
        )
    company_id = device.company_id
    device_id_for_audit = device.id
    db.execute(delete(DeviceEvent).where(DeviceEvent.device_id == device.id))
    write_audit(
        db,
        request,
        "device.delete_revoked",
        user=user,
        company_id=company_id,
        device_id=device_id_for_audit,
    )
    db.delete(device)
    db.commit()
    if not redirect_to.startswith("/") or redirect_to.startswith("//"):
        redirect_to = "/companies"
    return RedirectResponse(redirect_to, status_code=303)
