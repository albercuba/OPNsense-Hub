"""Add log retention indexes

Revision ID: 0002_log_retention_indexes
Revises: 0001_current_schema_baseline
Create Date: 2026-06-30 00:00:00
"""

from __future__ import annotations

from importlib import import_module

op = import_module("alembic.op")

# revision identifiers, used by Alembic.
revision = "0002_log_retention_indexes"
down_revision = "0001_current_schema_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_device_events_created_at ON device_events (created_at)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_device_events_device_created_at ON device_events (device_id, created_at DESC)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_action_created_at ON audit_logs (action, created_at DESC)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_device_created_at ON audit_logs (device_id, created_at DESC)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_audit_logs_device_created_at")
    op.execute("DROP INDEX IF EXISTS idx_audit_logs_action_created_at")
    op.execute("DROP INDEX IF EXISTS idx_audit_logs_created_at")
    op.execute("DROP INDEX IF EXISTS idx_device_events_device_created_at")
    op.execute("DROP INDEX IF EXISTS idx_device_events_created_at")
