from __future__ import annotations

import re
from urllib.parse import quote

from fastapi import HTTPException, UploadFile
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


async def read_upload_limited(
    upload: UploadFile, limit_bytes: int, *, field_name: str = "upload"
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await upload.read(min(1024 * 1024, max(limit_bytes - total + 1, 1)))
        if not chunk:
            break
        total += len(chunk)
        if total > limit_bytes:
            raise HTTPException(
                status_code=400,
                detail=f"{field_name} exceeds the maximum allowed size of {limit_bytes} bytes",
            )
        chunks.append(chunk)
    return b"".join(chunks)


def content_disposition_attachment(
    filename: str, fallback: str = "download.bin"
) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", filename or "").strip(".-") or fallback
    encoded = quote(safe)
    return f"attachment; filename=\"{safe}\"; filename*=UTF-8''{encoded}"


def get_or_create_integration_settings(db: Session) -> IntegrationSettings:
    integration_settings = db.get(IntegrationSettings, 1)
    if not integration_settings:
        integration_settings = IntegrationSettings(id=1, updated_at=utc_now())
        db.add(integration_settings)
        db.commit()
        db.refresh(integration_settings)
    return integration_settings
