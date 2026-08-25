"""Require unique device WireGuard public keys

Revision ID: 0013_unique_device_wg_public_key
Revises: 0012_encrypted_device_backups
Create Date: 2026-08-25 00:00:00
"""

from __future__ import annotations

from importlib import import_module

import sqlalchemy as sa

op = import_module("alembic.op")
context = import_module("alembic.context")

revision = "0013_unique_device_wg_public_key"
down_revision = "0012_encrypted_device_backups"
branch_labels = None
depends_on = None

_CONSTRAINT = "uq_devices_wg_public_key"


def _unique_constraint_names() -> set[str]:
    return {
        constraint["name"]
        for constraint in sa.inspect(op.get_bind()).get_unique_constraints("devices")
        if constraint.get("name")
    }


def upgrade() -> None:
    if not context.is_offline_mode():
        duplicate = op.get_bind().execute(
            sa.text(
                "SELECT wg_public_key FROM devices "
                "GROUP BY wg_public_key HAVING COUNT(*) > 1 LIMIT 1"
            )
        ).first()
        if duplicate is not None:
            raise RuntimeError(
                "cannot add unique device WireGuard public-key constraint while duplicate devices exist"
            )
    if context.is_offline_mode() or _CONSTRAINT not in _unique_constraint_names():
        with op.batch_alter_table("devices") as batch_op:
            batch_op.create_unique_constraint(_CONSTRAINT, ["wg_public_key"])


def downgrade() -> None:
    if context.is_offline_mode() or _CONSTRAINT in _unique_constraint_names():
        with op.batch_alter_table("devices") as batch_op:
            batch_op.drop_constraint(_CONSTRAINT, type_="unique")
