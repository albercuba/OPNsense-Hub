"""Add phase 3 security admin fields

Revision ID: 0007_phase3_security_admin
Revises: 0006_phase2_dashboard_ops
Create Date: 2026-07-05 00:00:03
"""

from __future__ import annotations

from importlib import import_module

op = import_module("alembic.op")

revision = "0007_phase3_security_admin"
down_revision = "0006_phase2_dashboard_ops"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS admin_login_allowlist TEXT NULL"
    )
    op.execute(
        "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip_address varchar(64) NULL"
    )
    op.execute(
        "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent varchar(500) NULL"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE sessions DROP COLUMN IF EXISTS user_agent")
    op.execute("ALTER TABLE sessions DROP COLUMN IF EXISTS ip_address")
    op.execute(
        "ALTER TABLE integration_settings DROP COLUMN IF EXISTS admin_login_allowlist"
    )
