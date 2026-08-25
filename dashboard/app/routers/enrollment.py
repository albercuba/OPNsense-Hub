from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..database import get_db
from ..models import AuditLog, Device, DeviceEvent, EnrollmentCode
from ..security import utc_now, verify_secret
from ..security.rate_limit import apply_rate_limit
from ..services.device_tokens import issue_device_token
from ..services.firmware_scheduler import apply_device_license_payload
from ..web import settings
from ..wireguard import (
    WireGuardError,
    add_peer,
    client_allowed_ips,
    get_server_public_key,
    next_tunnel_ip,
    validate_public_key,
)

router = APIRouter()


def _log_enrollment_failure(
    db: Session,
    request: Request,
    action: str,
    *,
    company_id=None,
) -> None:
    write_audit(db, request, action, company_id=company_id)
    db.commit()


def _claim_enrollment_code(db: Session, code: EnrollmentCode, now) -> bool:
    result = db.execute(
        update(EnrollmentCode)
        .where(
            EnrollmentCode.id == code.id,
            EnrollmentCode.used_at.is_(None),
            EnrollmentCode.expires_at > now,
        )
        .values(used_at=now)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount == 1


def _compensate_failed_peer_add(
    db: Session,
    *,
    device_id,
    enrollment_code_id,
) -> None:
    db.rollback()
    db.execute(delete(AuditLog).where(AuditLog.device_id == device_id))
    db.execute(delete(DeviceEvent).where(DeviceEvent.device_id == device_id))
    db.execute(delete(Device).where(Device.id == device_id))
    db.execute(
        update(EnrollmentCode)
        .where(EnrollmentCode.id == enrollment_code_id)
        .values(used_at=None)
        .execution_options(synchronize_session=False)
    )
    db.commit()


@router.post("/api/v1/enroll")
def enroll(
    payload: dict[str, object],
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    otp = str(payload.get("otp", "")).strip().upper()
    wg_public_key = str(payload.get("wg_public_key", "")).strip()
    hostname = str(payload.get("hostname", "")).strip()[:255]
    apply_rate_limit(
        request,
        "enroll",
        otp[:8] or "unknown",
        settings.rate_limit_enrollment_attempts,
        settings.rate_limit_enrollment_window_seconds,
    )
    if not otp or not hostname or not wg_public_key:
        _log_enrollment_failure(db, request, "enrollment.invalid_payload")
        raise HTTPException(
            status_code=400, detail="otp, hostname and wg_public_key are required"
        )
    now = utc_now()
    codes = db.scalars(
        select(EnrollmentCode)
        .where(EnrollmentCode.used_at.is_(None), EnrollmentCode.expires_at > now)
        .with_for_update()
    ).all()
    matched = next((code for code in codes if verify_secret(otp, code.code_hash)), None)
    if not matched:
        _log_enrollment_failure(db, request, "enrollment.invalid_otp")
        raise HTTPException(
            status_code=401, detail="invalid or expired enrollment code"
        )
    company_id = matched.company_id
    enrollment_code_id = matched.id
    try:
        validate_public_key(wg_public_key)
    except WireGuardError as exc:
        _log_enrollment_failure(
            db,
            request,
            "enrollment.invalid_public_key",
            company_id=company_id,
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    server_public_key = get_server_public_key()
    allowed_ips = client_allowed_ips()
    if not _claim_enrollment_code(db, matched, now):
        db.rollback()
        _log_enrollment_failure(
            db, request, "enrollment.otp_already_used", company_id=company_id
        )
        raise HTTPException(
            status_code=409, detail="enrollment code has already been used"
        )

    tunnel_ip = next_tunnel_ip(db)
    device = Device(
        company_id=company_id,
        hostname=hostname,
        opnsense_version=payload.get("opnsense_version"),
        plugin_version=payload.get("plugin_version"),
        wg_public_key=wg_public_key,
        wg_tunnel_ip=tunnel_ip,
        device_token_hash="pending",
        status="online",
        last_seen_at=now,
    )
    token = issue_device_token(device, now)
    apply_device_license_payload(device, payload)
    db.add(device)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        _log_enrollment_failure(
            db,
            request,
            "enrollment.device_conflict",
            company_id=company_id,
        )
        raise HTTPException(
            status_code=409,
            detail="device WireGuard public key or tunnel address is already enrolled",
        ) from exc
    db.add(
        DeviceEvent(
            device_id=device.id, event_type="enrolled", message="Device enrolled"
        )
    )
    write_audit(
        db, request, "device.enroll", company_id=company_id, device_id=device.id
    )
    device_id = device.id
    db.commit()

    try:
        add_peer(wg_public_key, tunnel_ip)
    except WireGuardError as exc:
        _compensate_failed_peer_add(
            db, device_id=device_id, enrollment_code_id=enrollment_code_id
        )
        _log_enrollment_failure(
            db,
            request,
            "enrollment.peer_add_failed",
            company_id=company_id,
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "device_id": str(device_id),
        "device_token": token,
        "device_token_issued_at": device.device_token_issued_at.isoformat(),
        "device_token_expires_at": device.device_token_expires_at.isoformat(),
        "wireguard": {
            "interface_address": f"{tunnel_ip}/32",
            "server_public_key": server_public_key,
            "endpoint": settings.hub_wg_endpoint,
            "allowed_ips": allowed_ips,
            "persistent_keepalive": 25,
        },
    }
