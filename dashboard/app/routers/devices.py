from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
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
from ..dashboard import (
    dashboard_backup_status,
    dashboard_firmware_status,
    dashboard_license_status,
    normalized_status,
)
from ..database import get_db
from ..deps import current_user, device_from_token, has_company_access
from ..integration import email_settings_configured
from ..models import AuditLog, Company, Device, DeviceBackup, DeviceEvent, User
from ..security import hash_secret, random_token, utc_now
from ..security.rate_limit import apply_rate_limit
from ..services.common import (
    clean_optional,
    content_disposition_attachment,
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
from ..services.network_diagnostics import build_device_network_diagnostics
from ..web import app_timezone_info, render_template, settings

router = APIRouter()

DEVICE_TIMELINE_LIMIT = 25
DEVICE_ACTIVITY_ACTION_LABELS = {
    "device.backup.request_now": "Backup requested",
    "device.backup.delete": "Stored backup deleted",
    "device.backup_settings.update": "Backup settings updated",
    "device.email_notification_settings.update": "Email notifications updated",
    "device.health_acknowledge": "Health issue acknowledged",
    "device.health_acknowledge.clear": "Health acknowledgement cleared",
    "device.revoke": "Firewall revoked",
    "device.runbook.update": "Runbook updated",
}
DEVICE_EVENT_LABELS = {
    "backup_uploaded": "Backup uploaded",
    "firmware_check": "Firmware check",
    "health_check": "Health check",
    "heartbeat": "Heartbeat",
    "notification_sent": "Notification sent",
    "notification_failed": "Notification failed",
    "email_notification_sent": "Email sent",
    "email_notification_failed": "Email failed",
    "revoked": "Firewall revoked",
}


def _redirect_with_status(device_id: uuid.UUID, status: str) -> RedirectResponse:
    return RedirectResponse(f"/devices/{device_id}?status={status}", status_code=303)


def _parse_optional_form_datetime(value: str, field_name: str) -> datetime | None:
    normalized = clean_optional(value)
    if not normalized:
        return None
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid {field_name}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=app_timezone_info())
    return parsed.astimezone(timezone.utc)


def _device_health_check_state(device: Device, now: datetime) -> dict[str, object]:
    if device.last_seen_at is None:
        return {
            "label": "No heartbeat yet",
            "state": "warning",
            "detail": "This firewall has not reported a heartbeat since enrollment.",
            "timestamp": None,
        }
    age = now - device.last_seen_at.astimezone(timezone.utc)
    if age <= timedelta(minutes=15):
        state = "success"
        label = "Healthy"
    elif age <= timedelta(hours=1):
        state = "warning"
        label = "Delayed"
    else:
        state = "critical"
        label = "Stale"
    return {
        "label": label,
        "state": state,
        "detail": f"Last heartbeat {age.seconds // 60 if age < timedelta(days=1) else age.days * 24 * 60} minutes ago.",
        "timestamp": device.last_seen_at,
    }


def _firmware_health_detail(device: Device) -> str:
    status = (device.firmware_status or "unknown").lower()
    if status == "update":
        update_count = max(0, int(device.firmware_update_count or 0))
        if update_count > 0:
            update_word = "update" if update_count == 1 else "updates"
            return f"There are {update_count} {update_word} available."
        if device.firmware_available_version:
            return f"Updates are available to {device.firmware_available_version}."
        return "Updates are available."
    if status == "upgrade":
        if device.firmware_available_version:
            return f"Upgrade available to {device.firmware_available_version}."
        return "A firmware upgrade is available."
    if status == "none":
        version = device.firmware_current_version or device.opnsense_version
        if version:
            return f"System is up to date on {version}."
        return "System is up to date."
    if status == "error":
        return device.firmware_status_message or "Firmware check failed."
    return (
        f"Last checked at {device.firmware_checked_at.isoformat()}."
        if device.firmware_checked_at
        else "No firmware check has been reported yet."
    )


def _device_health_details(device: Device, now: datetime) -> list[dict[str, object]]:
    heartbeat = _device_health_check_state(device, now)
    backup = dashboard_backup_status(device, now)
    firmware = dashboard_firmware_status(device)
    license_state = dashboard_license_status(device, now)
    current_status = normalized_status(device)
    tunnel_state = (
        "success"
        if current_status == "online"
        else "warning"
        if current_status == "warning"
        else "critical"
        if current_status == "critical"
        else "neutral"
    )
    license_detail = str(license_state["label"])
    days_left_value = license_state["days_left"]
    if isinstance(days_left_value, int):
        days_left = days_left_value
        if license_state["expired"]:
            license_detail = f"Expired {abs(days_left)} days ago."
        else:
            license_detail = f"Expires in {days_left} days."
    maintenance_active = bool(
        device.maintenance_until
        and device.maintenance_until.astimezone(timezone.utc)
        > now.astimezone(timezone.utc)
    )
    acknowledgement_active = bool(device.health_acknowledged_at)
    return [
        {
            "title": "Heartbeat",
            "label": heartbeat["label"],
            "state": heartbeat["state"],
            "detail": heartbeat["detail"],
            "timestamp": heartbeat["timestamp"],
        },
        {
            "title": "Tunnel status",
            "label": current_status.replace("critical", "offline").capitalize()
            if current_status == "critical"
            else current_status.capitalize(),
            "state": tunnel_state,
            "detail": "Derived from the latest firewall status reported to Hub.",
            "timestamp": device.last_seen_at,
        },
        {
            "title": "Backup freshness",
            "label": str(backup["label"]),
            "state": "success"
            if backup["label"] == "OK"
            else "warning"
            if backup["label"] in {"Pending", "Disabled"}
            else "critical",
            "detail": "Last upload: "
            + (
                device.backup_last_uploaded_at.isoformat()
                if device.backup_last_uploaded_at
                else "none recorded"
            ),
            "timestamp": device.backup_last_uploaded_at,
        },
        {
            "title": "Firmware check",
            "label": str(firmware["label"]),
            "state": "success"
            if firmware["label"] == "Up to date"
            else "warning"
            if firmware["label"] in {"Updates available", "Upgrade available"}
            else "critical"
            if firmware["label"] == "Check failed"
            else "neutral",
            "detail": _firmware_health_detail(device),
            "timestamp": device.firmware_checked_at,
        },
        {
            "title": "License",
            "label": str(license_state["label"]),
            "state": "critical"
            if license_state["expired"]
            else "warning"
            if license_state["expiring_soon"]
            else "success",
            "detail": license_detail,
            "timestamp": device.license_expires_at,
        },
        {
            "title": "Last notification",
            "label": "Sent" if device.email_last_notified_at else "Not sent",
            "state": "success" if device.email_last_notified_at else "neutral",
            "detail": (
                f"Last notification status: {device.email_last_notified_status or 'unknown'}."
                if device.email_last_notified_at
                else "No email notification has been sent for this firewall yet."
            ),
            "timestamp": device.email_last_notified_at,
        },
        {
            "title": "Maintenance window",
            "label": "Active" if maintenance_active else "Not active",
            "state": "warning" if maintenance_active else "neutral",
            "detail": (
                "Health alerts are temporarily muted for this firewall."
                if maintenance_active
                else "No maintenance window is currently scheduled."
            ),
            "timestamp": device.maintenance_until,
        },
        {
            "title": "Acknowledgement",
            "label": "Acknowledged" if acknowledgement_active else "Open",
            "state": "info" if acknowledgement_active else "warning",
            "detail": (
                device.health_acknowledged_note
                or "The current health issue has been acknowledged."
                if acknowledgement_active
                else "No acknowledgement note has been recorded."
            ),
            "timestamp": device.health_acknowledged_at,
        },
    ]


def _build_device_timeline(
    device: Device,
    events: list[DeviceEvent],
    audit_entries: list[AuditLog],
    users_by_id: dict[uuid.UUID, User],
) -> list[dict[str, object]]:
    timeline = []
    for event in events:
        timeline.append(
            {
                "source": "event",
                "title": DEVICE_EVENT_LABELS.get(
                    event.event_type, event.event_type.replace("_", " ").title()
                ),
                "detail": event.message or "Firewall activity recorded.",
                "timestamp": event.created_at,
                "actor": "Firewall",
                "state": "warning"
                if event.event_type in {"health_check", "email_notification_failed"}
                else "critical"
                if event.event_type in {"notification_failed"}
                else "success"
                if event.event_type in {"backup_uploaded", "email_notification_sent"}
                else "neutral",
            }
        )
    for entry in audit_entries:
        actor_user = (
            users_by_id.get(entry.user_id) if entry.user_id is not None else None
        )
        actor = actor_user.email if actor_user is not None else "Hub user"
        timeline.append(
            {
                "source": "audit",
                "title": DEVICE_ACTIVITY_ACTION_LABELS.get(
                    entry.action,
                    entry.action.replace(".", " ").replace("_", " ").title(),
                ),
                "detail": "Administrative action recorded in the audit log.",
                "timestamp": entry.created_at,
                "actor": actor,
                "state": "info",
            }
        )
    timeline.sort(key=lambda item: item["timestamp"], reverse=True)
    return timeline[:DEVICE_TIMELINE_LIMIT]


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
    reported_status = str(payload.get("status", "online"))[:30].strip().lower()
    previous_status = device.status
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
    if firmware_applied or reported_status not in {"", "online"}:
        event_message = reported_status or previous_status
        if firmware_applied:
            event_message = (
                f"{event_message}; firmware={device.firmware_status}; updates={device.firmware_update_count}"
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
    now = utc_now()
    backups = db.scalars(
        select(DeviceBackup)
        .where(DeviceBackup.device_id == device.id)
        .order_by(DeviceBackup.created_at.desc())
    ).all()
    events = db.scalars(
        select(DeviceEvent)
        .where(DeviceEvent.device_id == device.id)
        .order_by(DeviceEvent.created_at.desc())
        .limit(DEVICE_TIMELINE_LIMIT)
    ).all()
    audit_entries = db.scalars(
        select(AuditLog)
        .where(
            AuditLog.device_id == device.id,
            AuditLog.action != "device.view",
        )
        .order_by(AuditLog.created_at.desc())
        .limit(DEVICE_TIMELINE_LIMIT)
    ).all()
    user_ids = {entry.user_id for entry in audit_entries if entry.user_id is not None}
    users_by_id = {
        row.id: row
        for row in (
            db.scalars(select(User).where(User.id.in_(user_ids))).all()
            if user_ids
            else []
        )
    }
    toast_messages = {
        "backup-requested": "Backup request queued.",
        "backup-deleted": "Stored backup deleted.",
        "backup-settings-saved": "Backup settings saved.",
        "email-notification-settings-saved": "Email notification settings saved.",
        "health-acknowledged": "Health acknowledgement saved.",
        "health-acknowledgement-cleared": "Health acknowledgement cleared.",
        "runbook-saved": "Runbook details saved.",
    }
    status = request.query_params.get("status")
    health_acknowledged_by = (
        users_by_id.get(device.health_acknowledged_by)
        if device.health_acknowledged_by is not None
        else None
    )
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
            "can_manage_device": has_company_access(
                db, user, device.company_id, "admin"
            ),
            "email_settings_configured": email_settings_configured(
                integration_settings
            ),
            "events": events,
            "timeline": _build_device_timeline(
                device, list(events), list(audit_entries), users_by_id
            ),
            "health_details": _device_health_details(device, now),
            "health_acknowledged_by": health_acknowledged_by,
            "network_diagnostics": build_device_network_diagnostics(db, device),
            "maintenance_active": bool(
                device.maintenance_until
                and device.maintenance_until.astimezone(timezone.utc)
                > now.astimezone(timezone.utc)
            ),
            "active_page": "companies",
            "status": status,
            "toast": (
                {"message": toast_messages[status], "level": "success"}
                if status in toast_messages
                else None
            ),
        },
    )


@router.post("/devices/{device_id}/runbook")
def update_device_runbook(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    runbook_owner: str = Form(""),
    runbook_contact: str = Form(""),
    runbook_site: str = Form(""),
    support_contract_expires_at: str = Form(""),
    maintenance_until: str = Form(""),
    escalation_hint: str = Form(""),
    runbook_notes: str = Form(""),
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id, "admin"):
        raise HTTPException(status_code=404)
    device.runbook_owner = clean_optional(runbook_owner)
    device.runbook_contact = clean_optional(runbook_contact)
    device.runbook_site = clean_optional(runbook_site)
    device.support_contract_expires_at = _parse_optional_form_datetime(
        support_contract_expires_at,
        "support contract expiration",
    )
    device.maintenance_until = _parse_optional_form_datetime(
        maintenance_until,
        "maintenance window",
    )
    device.escalation_hint = clean_optional(escalation_hint)
    device.runbook_notes = clean_optional(runbook_notes)
    write_audit(
        db,
        request,
        "device.runbook.update",
        user=user,
        company_id=device.company_id,
        device_id=device.id,
    )
    db.commit()
    return _redirect_with_status(device.id, "runbook-saved")


@router.post("/devices/{device_id}/acknowledge-health")
def acknowledge_device_health(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
    acknowledgement_note: str = Form(""),
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id, "admin"):
        raise HTTPException(status_code=404)
    device.health_acknowledged_at = utc_now()
    device.health_acknowledged_note = clean_optional(acknowledgement_note)
    device.health_acknowledged_by = user.id
    write_audit(
        db,
        request,
        "device.health_acknowledge",
        user=user,
        company_id=device.company_id,
        device_id=device.id,
    )
    db.commit()
    return _redirect_with_status(device.id, "health-acknowledged")


@router.post("/devices/{device_id}/clear-acknowledgement")
def clear_device_health_acknowledgement(
    request: Request,
    device_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
):
    device = db.get(Device, device_id)
    if not device or not has_company_access(db, user, device.company_id, "admin"):
        raise HTTPException(status_code=404)
    device.health_acknowledged_at = None
    device.health_acknowledged_note = None
    device.health_acknowledged_by = None
    write_audit(
        db,
        request,
        "device.health_acknowledge.clear",
        user=user,
        company_id=device.company_id,
        device_id=device.id,
    )
    db.commit()
    return _redirect_with_status(device.id, "health-acknowledgement-cleared")


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
    email_notify_on_offline: str | None = Form(None),
    email_notify_on_backup_overdue: str | None = Form(None),
    email_notify_on_license_expiring: str | None = Form(None),
    email_notify_on_firmware_available: str | None = Form(None),
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
    device.email_notify_on_critical = email_notify_on_offline == "on"
    device.email_notify_on_backup_overdue = email_notify_on_backup_overdue == "on"
    device.email_notify_on_license_expiring = email_notify_on_license_expiring == "on"
    device.email_notify_on_firmware_available = (
        email_notify_on_firmware_available == "on"
    )
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
    headers = {
        "Content-Disposition": content_disposition_attachment(
            backup.filename,
            fallback="firewall-backup.xml",
        )
    }
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
