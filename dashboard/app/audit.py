import logging
from datetime import timedelta

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import AuditLog, User
from .security import utc_now
from .security.request_context import client_ip

settings = get_settings()
logger = logging.getLogger(__name__)


def log_security_warning(action: str, *, detail: str | None = None) -> None:
    message = action if not detail else f"{action}: {detail}"
    logger.warning("Security event: %s", message)


def should_write_audit(
    db: Session,
    action: str,
    *,
    user: User | None = None,
    device_id=None,
) -> bool:
    if action != "device.view":
        return True
    if (
        user is None
        or device_id is None
        or settings.audit_device_view_throttle_minutes <= 0
    ):
        return True
    cutoff = utc_now() - timedelta(minutes=settings.audit_device_view_throttle_minutes)
    recent_entry = db.scalars(
        select(AuditLog)
        .where(
            AuditLog.action == action,
            AuditLog.user_id == user.id,
            AuditLog.device_id == device_id,
            AuditLog.created_at >= cutoff,
        )
        .order_by(AuditLog.created_at.desc())
        .limit(1)
    ).first()
    return recent_entry is None


def write_audit(
    db: Session,
    request: Request | None,
    action: str,
    user: User | None = None,
    company_id=None,
    device_id=None,
) -> bool:
    if not should_write_audit(db, action, user=user, device_id=device_id):
        return False
    ip_address = None
    user_agent = None
    if request is not None:
        ip_address = client_ip(request)
        user_agent = request.headers.get("user-agent")
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            company_id=company_id,
            device_id=device_id,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=utc_now(),
        )
    )
    return True
