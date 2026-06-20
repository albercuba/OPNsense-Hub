from fastapi import Request
from sqlalchemy.orm import Session

from .models import AuditLog, User


def write_audit(
    db: Session,
    request: Request | None,
    action: str,
    user: User | None = None,
    company_id=None,
    device_id=None,
) -> None:
    ip_address = None
    user_agent = None
    if request is not None:
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            company_id=company_id,
            device_id=device_id,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    )
