"""Add auth provider for external users

Revision ID: 0003_user_auth_provider
Revises: 0002_log_retention_indexes
Create Date: 2026-06-30 00:00:00
"""

from __future__ import annotations

from importlib import import_module

op = import_module("alembic.op")

# revision identifiers, used by Alembic.
revision = "0003_user_auth_provider"
down_revision = "0002_log_retention_indexes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider text NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS auth_provider")
