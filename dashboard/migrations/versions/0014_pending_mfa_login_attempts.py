"""Add pending MFA login attempt tracking."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0014_pending_mfa_login_attempts"
down_revision = "0013_unique_device_wg_public_key"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "pending_mfa_logins",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("nonce_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("failed_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_pending_mfa_logins_user_active",
        "pending_mfa_logins",
        ["user_id", "expires_at", "consumed_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_pending_mfa_logins_user_active", table_name="pending_mfa_logins"
    )
    op.drop_table("pending_mfa_logins")
