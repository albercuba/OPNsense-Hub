from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..config import Settings
from ..hardening import runtime_validation_errors
from ..models import IntegrationSettings, SessionToken, User
from ..security.request_context import client_ip


def parse_allowlist_entries(raw_value: str | None) -> tuple[list[str], list[str]]:
    entries = [
        item.strip()
        for item in str(raw_value or "")
        .replace("\r", "\n")
        .replace(",", "\n")
        .split("\n")
        if item.strip()
    ]
    valid: list[str] = []
    invalid: list[str] = []
    for entry in entries:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            invalid.append(entry)
        else:
            valid.append(entry)
    return valid, invalid


def admin_login_networks(raw_value: str | None) -> tuple[ipaddress._BaseNetwork, ...]:
    valid, _invalid = parse_allowlist_entries(raw_value)
    return tuple(ipaddress.ip_network(entry, strict=False) for entry in valid)


def admin_login_ip_allowed(
    integration_settings: IntegrationSettings | None,
    request,
    user: User,
) -> bool:
    if user.role != "administrator":
        return True
    networks = admin_login_networks(
        integration_settings.admin_login_allowlist if integration_settings else None
    )
    if not networks:
        return True
    try:
        address = ipaddress.ip_address(client_ip(request))
    except ValueError:
        return False
    return any(address in network for network in networks)


def secret_health_checks(settings: Settings) -> list[dict[str, str]]:
    checks = [
        {"level": "warning", "message": message}
        for message in runtime_validation_errors(settings)
    ]
    if not settings.secret_encryption_key:
        checks.append(
            {
                "level": "warning",
                "message": "SECRET_ENCRYPTION_KEY is not set, so stored provider secrets fall back to SECRET_KEY-derived encryption.",
            }
        )
    public_host = (urlparse(settings.public_url).hostname or "").strip().lower()
    if not public_host:
        checks.append(
            {
                "level": "warning",
                "message": "PUBLIC_URL does not include a usable hostname.",
            }
        )
    if not checks:
        checks.append(
            {
                "level": "success",
                "message": "No insecure defaults or weak runtime secret settings were detected.",
            }
        )
    return checks


def active_sessions_for_user(db: Session, user_id) -> list[SessionToken]:
    return list(
        db.scalars(
            select(SessionToken)
            .where(
                SessionToken.user_id == user_id,
                SessionToken.revoked_at.is_(None),
            )
            .order_by(SessionToken.created_at.desc())
        ).all()
    )


def active_sessions_for_admin(db: Session) -> list[SessionToken]:
    return list(
        db.scalars(
            select(SessionToken)
            .options(selectinload(SessionToken.user))
            .where(SessionToken.revoked_at.is_(None))
            .order_by(SessionToken.created_at.desc())
        ).all()
    )
