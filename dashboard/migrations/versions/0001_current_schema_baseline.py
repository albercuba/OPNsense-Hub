"""Current schema baseline

Revision ID: 0001_current_schema_baseline
Revises: None
Create Date: 2026-06-29 00:00:00
"""

from __future__ import annotations

from alembic import op
from app.database import Base
from app.models import (  # noqa: F401
    AuditLog,
    Company,
    CompanyUser,
    Device,
    DeviceBackup,
    DeviceEvent,
    EnrollmentCode,
    IntegrationSettings,
    SessionToken,
    User,
)
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0001_current_schema_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
