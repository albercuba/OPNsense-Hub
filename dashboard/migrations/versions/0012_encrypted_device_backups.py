"""Require firewall-encrypted device configuration backups

Revision ID: 0012_encrypted_device_backups
Revises: 0011_connector_access_sessions
Create Date: 2026-08-17 00:00:00
"""

from __future__ import annotations

from importlib import import_module

import sqlalchemy as sa

op = import_module("alembic.op")
context = import_module("alembic.context")

revision = "0012_encrypted_device_backups"
down_revision = "0011_connector_access_sessions"
branch_labels = None
depends_on = None

_FORMAT = "opnsense-config-encrypted-v1"
_CONSTRAINT = "ck_device_backups_encrypted_format"


def _column_names() -> set[str]:
    return {
        column["name"]
        for column in sa.inspect(op.get_bind()).get_columns("device_backups")
    }


def _constraint_names() -> set[str]:
    return {
        constraint["name"]
        for constraint in sa.inspect(op.get_bind()).get_check_constraints(
            "device_backups"
        )
        if constraint.get("name")
    }


def upgrade() -> None:
    # Existing rows contain raw config.xml and cannot be encrypted safely because
    # the Hub must never possess the firewall's backup master key.
    op.execute("DELETE FROM device_backups")
    op.execute(
        "UPDATE devices SET backup_last_uploaded_at = NULL, "
        "backup_last_requested_at = CASE WHEN backup_enabled THEN now() ELSE NULL END"
    )

    if context.is_offline_mode():
        op.alter_column(
            "device_backups", "content", new_column_name="encrypted_payload"
        )
        op.add_column(
            "device_backups",
            sa.Column(
                "backup_format",
                sa.String(length=64),
                nullable=False,
                server_default=_FORMAT,
            ),
        )
        op.alter_column("device_backups", "backup_format", server_default=None)
        op.create_check_constraint(
            _CONSTRAINT,
            "device_backups",
            f"backup_format = '{_FORMAT}'",
        )
        return

    columns = _column_names()
    if "content" in columns and "encrypted_payload" not in columns:
        op.alter_column(
            "device_backups", "content", new_column_name="encrypted_payload"
        )
        columns.remove("content")
        columns.add("encrypted_payload")
    elif "content" in columns and "encrypted_payload" in columns:
        op.drop_column("device_backups", "content")
        columns.remove("content")
    if "encrypted_payload" not in columns:
        op.add_column(
            "device_backups",
            sa.Column("encrypted_payload", sa.Text(), nullable=False),
        )
    if "backup_format" not in columns:
        op.add_column(
            "device_backups",
            sa.Column(
                "backup_format",
                sa.String(length=64),
                nullable=False,
                server_default=_FORMAT,
            ),
        )
        op.alter_column("device_backups", "backup_format", server_default=None)
    if _CONSTRAINT not in _constraint_names():
        op.create_check_constraint(
            _CONSTRAINT,
            "device_backups",
            f"backup_format = '{_FORMAT}'",
        )


def downgrade() -> None:
    # Ciphertext cannot be represented safely by the legacy plaintext schema.
    op.execute("DELETE FROM device_backups")
    op.execute(
        "UPDATE devices SET backup_last_uploaded_at = NULL, "
        "backup_last_requested_at = NULL"
    )
    if context.is_offline_mode():
        op.drop_constraint(_CONSTRAINT, "device_backups", type_="check")
        op.drop_column("device_backups", "backup_format")
        op.alter_column(
            "device_backups", "encrypted_payload", new_column_name="content"
        )
        return

    if _CONSTRAINT in _constraint_names():
        op.drop_constraint(_CONSTRAINT, "device_backups", type_="check")

    columns = _column_names()
    if "backup_format" in columns:
        op.drop_column("device_backups", "backup_format")
    columns = _column_names()
    if "encrypted_payload" in columns and "content" not in columns:
        op.alter_column(
            "device_backups", "encrypted_payload", new_column_name="content"
        )
    elif "encrypted_payload" in columns and "content" in columns:
        op.drop_column("device_backups", "encrypted_payload")
