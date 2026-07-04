"""Add phase 2 dashboard and notification fields

Revision ID: 0006_phase2_dashboard_notifications
Revises: 0005_device_phase1_fields
Create Date: 2026-07-04 00:00:02
"""

from __future__ import annotations

from importlib import import_module

op = import_module("alembic.op")

revision = "0006_phase2_dashboard_notifications"
down_revision = "0005_device_phase1_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS notify_on_offline boolean NOT NULL DEFAULT true"
    )
    op.execute(
        "ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS notify_on_backup_overdue boolean NOT NULL DEFAULT true"
    )
    op.execute(
        "ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS notify_on_license_expiring boolean NOT NULL DEFAULT true"
    )
    op.execute(
        "ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS notify_on_firmware_available boolean NOT NULL DEFAULT true"
    )
    op.execute(
        "ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS notify_on_repeated_auth_failures boolean NOT NULL DEFAULT true"
    )
    op.execute(
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS backup_overdue_notified_at TIMESTAMP WITH TIME ZONE NULL"
    )
    op.execute(
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS license_expiring_notified_at TIMESTAMP WITH TIME ZONE NULL"
    )
    op.execute(
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS firmware_available_notified_at TIMESTAMP WITH TIME ZONE NULL"
    )
    op.execute(
        "CREATE TABLE IF NOT EXISTS user_dashboard_filters ("
        "id uuid PRIMARY KEY, "
        "user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, "
        "name varchar(120) NOT NULL, "
        "company_id uuid NULL REFERENCES companies(id) ON DELETE SET NULL, "
        "status varchar(30) NULL, "
        "created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()"
        ")"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_user_dashboard_filters_user_created_at ON user_dashboard_filters(user_id, created_at DESC)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_user_dashboard_filters_user_created_at")
    op.execute("DROP TABLE IF EXISTS user_dashboard_filters")
    op.execute(
        "ALTER TABLE devices DROP COLUMN IF EXISTS firmware_available_notified_at"
    )
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS license_expiring_notified_at")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS backup_overdue_notified_at")
    op.execute(
        "ALTER TABLE integration_settings DROP COLUMN IF EXISTS notify_on_repeated_auth_failures"
    )
    op.execute(
        "ALTER TABLE integration_settings DROP COLUMN IF EXISTS notify_on_firmware_available"
    )
    op.execute(
        "ALTER TABLE integration_settings DROP COLUMN IF EXISTS notify_on_license_expiring"
    )
    op.execute(
        "ALTER TABLE integration_settings DROP COLUMN IF EXISTS notify_on_backup_overdue"
    )
    op.execute(
        "ALTER TABLE integration_settings DROP COLUMN IF EXISTS notify_on_offline"
    )
