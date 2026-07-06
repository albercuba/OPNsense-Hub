"""Add per-device email rule override fields

Revision ID: 0008_device_email_rule_overrides
Revises: 0007_phase3_security_admin
Create Date: 2026-07-06 00:00:04
"""

from __future__ import annotations

from importlib import import_module

op = import_module("alembic.op")

revision = "0008_device_email_rule_overrides"
down_revision = "0007_phase3_security_admin"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS email_notify_on_backup_overdue boolean NOT NULL DEFAULT true"
    )
    op.execute(
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS email_notify_on_license_expiring boolean NOT NULL DEFAULT true"
    )
    op.execute(
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS email_notify_on_firmware_available boolean NOT NULL DEFAULT true"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE devices DROP COLUMN IF EXISTS email_notify_on_firmware_available"
    )
    op.execute(
        "ALTER TABLE devices DROP COLUMN IF EXISTS email_notify_on_license_expiring"
    )
    op.execute(
        "ALTER TABLE devices DROP COLUMN IF EXISTS email_notify_on_backup_overdue"
    )
