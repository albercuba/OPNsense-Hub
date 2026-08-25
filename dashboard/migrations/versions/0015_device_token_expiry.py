"""Add device token issue and expiry timestamps."""

from __future__ import annotations

from importlib import import_module

import sqlalchemy as sa

op = import_module("alembic.op")
context = import_module("alembic.context")

revision = "0015_device_token_expiry"
down_revision = "0014_pending_mfa_login_attempts"
branch_labels = None
depends_on = None


def _columns() -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns("devices")}


def upgrade() -> None:
    columns = set() if context.is_offline_mode() else _columns()
    with op.batch_alter_table("devices") as batch_op:
        if context.is_offline_mode() or "device_token_issued_at" not in columns:
            batch_op.add_column(
                sa.Column("device_token_issued_at", sa.DateTime(timezone=True), nullable=True)
            )
        if context.is_offline_mode() or "device_token_expires_at" not in columns:
            batch_op.add_column(
                sa.Column("device_token_expires_at", sa.DateTime(timezone=True), nullable=True)
            )

    op.execute(
        "UPDATE devices SET "
        "device_token_issued_at = COALESCE(device_token_issued_at, created_at, CURRENT_TIMESTAMP), "
        "device_token_expires_at = COALESCE(device_token_expires_at, created_at + INTERVAL '90 days', CURRENT_TIMESTAMP + INTERVAL '90 days')"
    )

    with op.batch_alter_table("devices") as batch_op:
        batch_op.alter_column("device_token_issued_at", nullable=False)
        batch_op.alter_column("device_token_expires_at", nullable=False)


def downgrade() -> None:
    columns = set() if context.is_offline_mode() else _columns()
    with op.batch_alter_table("devices") as batch_op:
        if context.is_offline_mode() or "device_token_expires_at" in columns:
            batch_op.drop_column("device_token_expires_at")
        if context.is_offline_mode() or "device_token_issued_at" in columns:
            batch_op.drop_column("device_token_issued_at")
