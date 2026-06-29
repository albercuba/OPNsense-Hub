from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..database import get_db
from ..deps import device_from_token
from ..models import Device, DeviceEvent, EnrollmentCode
from ..security import hash_secret, random_token, utc_now, verify_secret
from ..security.rate_limit import apply_rate_limit
from ..services.firmware_scheduler import apply_device_license_payload
from ..web import settings
from ..wireguard import (
    WireGuardError,
    add_peer,
    client_allowed_ips,
    get_server_public_key,
    next_tunnel_ip,
)

router = APIRouter()


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
        raise HTTPException(
            status_code=400, detail="otp, hostname and wg_public_key are required"
        )
    now = utc_now()
    codes = db.scalars(
        select(EnrollmentCode).where(
            EnrollmentCode.used_at.is_(None), EnrollmentCode.expires_at > now
        )
    ).all()
    matched = next((code for code in codes if verify_secret(otp, code.code_hash)), None)
    if not matched:
        raise HTTPException(
            status_code=401, detail="invalid or expired enrollment code"
        )
    tunnel_ip = next_tunnel_ip(db)
    token = random_token(48)
    device = Device(
        company_id=matched.company_id,
        hostname=hostname,
        opnsense_version=payload.get("opnsense_version"),
        plugin_version=payload.get("plugin_version"),
        wg_public_key=wg_public_key,
        wg_tunnel_ip=tunnel_ip,
        device_token_hash=hash_secret(token),
        status="online",
        last_seen_at=now,
    )
    apply_device_license_payload(device, payload)
    try:
        add_peer(wg_public_key, tunnel_ip)
    except WireGuardError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    matched.used_at = now
    db.add(device)
    db.flush()
    db.add(
        DeviceEvent(
            device_id=device.id, event_type="enrolled", message="Device enrolled"
        )
    )
    write_audit(
        db, request, "device.enroll", company_id=device.company_id, device_id=device.id
    )
    db.commit()
    return {
        "device_id": str(device.id),
        "device_token": token,
        "wireguard": {
            "interface_address": f"{tunnel_ip}/32",
            "server_public_key": get_server_public_key(),
            "endpoint": settings.hub_wg_endpoint,
            "allowed_ips": client_allowed_ips(),
            "persistent_keepalive": 25,
        },
    }
