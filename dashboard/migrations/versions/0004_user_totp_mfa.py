"""Add TOTP MFA secret for local users

Revision ID: 0004_user_totp_mfa
Revises: 0003_user_auth_provider
Create Date: 2026-06-30 00:00:01
"""

from __future__ import annotations

from importlib import import_module

op = import_module("alembic.op")

# revision identifiers, used by Alembic.
revision = "0004_user_totp_mfa"
down_revision = "0003_user_auth_provider"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret text NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS mfa_secret")
