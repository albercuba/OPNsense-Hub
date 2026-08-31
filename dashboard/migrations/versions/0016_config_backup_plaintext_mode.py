"""Allow explicit plaintext device configuration backup mode."""

from __future__ import annotations

from importlib import import_module

import sqlalchemy as sa

op = import_module("alembic.op")
context = import_module("alembic.context")

revision = "0016_config_backup_plaintext_mode"
down_revision = "0015_device_token_expiry"
branch_labels = None
depends_on = None

_ENCRYPTED_FORMAT = "opnsense-config-encrypted-v1"
_PLAINTEXT_FORMAT = "opnsense-config-plaintext-v1"
_CONSTRAINT = "ck_device_backups_encrypted_format"


def _constraint_names() -> set[str]:
    return {
        constraint["name"]
        for constraint in sa.inspect(op.get_bind()).get_check_constraints(
            "device_backups"
        )
        if constraint.get("name")
    }


def _drop_format_constraint() -> None:
    if context.is_offline_mode() or _CONSTRAINT in _constraint_names():
        op.drop_constraint(_CONSTRAINT, "device_backups", type_="check")


def upgrade() -> None:
    _drop_format_constraint()
    op.create_check_constraint(
        _CONSTRAINT,
        "device_backups",
        "backup_format IN "
        f"('{_ENCRYPTED_FORMAT}', '{_PLAINTEXT_FORMAT}')",
    )


def downgrade() -> None:
    # Rows uploaded in explicit plaintext mode cannot satisfy the previous
    # encrypted-only schema. Remove only those rows before restoring it.
    op.execute(
        "DELETE FROM device_backups "
        f"WHERE backup_format = '{_PLAINTEXT_FORMAT}'"
    )
    _drop_format_constraint()
    op.create_check_constraint(
        _CONSTRAINT,
        "device_backups",
        f"backup_format = '{_ENCRYPTED_FORMAT}'",
    )
