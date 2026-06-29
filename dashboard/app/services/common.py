from __future__ import annotations

import re

from sqlalchemy.orm import Session

from ..models import IntegrationSettings
from ..security import utc_now


def clean_optional(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def is_valid_email_address(value: str | None) -> bool:
    if not value:
        return False
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value))


def get_or_create_integration_settings(db: Session) -> IntegrationSettings:
    integration_settings = db.get(IntegrationSettings, 1)
    if not integration_settings:
        integration_settings = IntegrationSettings(id=1, updated_at=utc_now())
        db.add(integration_settings)
        db.commit()
        db.refresh(integration_settings)
    return integration_settings
