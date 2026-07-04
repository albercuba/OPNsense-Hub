"""Add device runbook and health acknowledgement fields

Revision ID: 0005_device_phase1_fields
Revises: 0004_user_totp_mfa
Create Date: 2026-07-04 00:00:01
"""

from __future__ import annotations

from importlib import import_module

op = import_module("alembic.op")

# revision identifiers, used by Alembic.
revision = "0005_device_phase1_fields"
down_revision = "0004_user_totp_mfa"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE devices ADD COLUMN IF NOT EXISTS runbook_notes text NULL")
    op.execute(
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS runbook_owner varchar(200) NULL"
    )
    op.execute(
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS runbook_contact varchar(320) NULL"
    )
    op.execute(
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS runbook_site varchar(200) NULL"
    )
    op.execute(
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS support_contract_expires_at TIMESTAMP WITH TIME ZONE NULL"
    )
    op.execute("ALTER TABLE devices ADD COLUMN IF NOT EXISTS escalation_hint text NULL")
    op.execute(
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS maintenance_until TIMESTAMP WITH TIME ZONE NULL"
    )
    op.execute(
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS health_acknowledged_at TIMESTAMP WITH TIME ZONE NULL"
    )
    op.execute(
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS health_acknowledged_note text NULL"
    )
    op.execute(
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS health_acknowledged_by uuid NULL REFERENCES users(id) ON DELETE SET NULL"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS health_acknowledged_by")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS health_acknowledged_note")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS health_acknowledged_at")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS maintenance_until")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS escalation_hint")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS support_contract_expires_at")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS runbook_site")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS runbook_contact")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS runbook_owner")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS runbook_notes")
